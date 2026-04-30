from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
from typing import Any

from agents.evaluator import run_evaluator
from agents.executor import run_executor
from agents.planner import run_planner
from agents.validator import run_validator
from core.llm_client import DeepSeekClient
from core.memory_store import LayeredMemory
from core.settings import get_settings


def _print_agent_header(name: str) -> None:
    print(f"[agent:{name}] ----------------")


def _list_json_files(folder: Path) -> list[str]:
    if not folder.exists() or not folder.is_dir():
        return []
    return sorted([p.name for p in folder.glob("*.json") if p.is_file()])


def _load_confirmed(path: Path) -> dict[str, Any]:
    target = path.expanduser().resolve()
    if target.is_dir():
        candidates = _list_json_files(target)
        raise FileNotFoundError(
            "你传入的是目录而不是文件。\n"
            f"当前路径: {target}\n"
            f"该目录下可用 JSON 文件: {candidates if candidates else '无'}\n"
            "请使用 --confirmed 指定具体 json 文件路径。"
        )

    if not target.exists():
        fallback = _ROOT / "data" / "confirmed_vuln.json"
        if fallback.exists():
            print(f"[coordinator] 主路径不存在，回退到: {fallback}")
            target = fallback
        else:
            data_dir = _ROOT / "data"
            available = _list_json_files(data_dir)
            raise FileNotFoundError(
                "缺少输入文件。\n"
                f"当前尝试路径: {path}\n"
                f"回退路径: {fallback} 也不存在\n"
                f"data 目录可用 JSON 文件: {available if available else '无'}"
            )

    return json.loads(target.read_text(encoding="utf-8"))

def _count_execution_failures(exec_out: dict[str, Any]) -> dict[str, list[str]]:
    failures: dict[str, list[str]] = {"skipped": [], "error": [], "blocked": []}
    for r in exec_out.get("step_results") or []:
        rr = r.get("result") or {}
        if not rr.get("ok"):
            reason = rr.get("execution_mode", "unknown")
            step_id = str(r.get("step_id", "?"))
            purpose = r.get("purpose", "")
            detail = f"step[{step_id}]: {purpose} (mode={reason})"
            if reason == "skipped_syntax_error":
                failures["skipped"].append(detail)
            elif reason == "security_blocked":
                failures["blocked"].append(detail)
            else:
                failures["error"].append(detail)
    return failures


def _build_retry_prompt(failures: dict[str, list[str]], confirmed: dict[str, Any]) -> str:
    prompt = "【定向修复迭代】上一轮虽然整体成功，但以下步骤失败，需要修复后重试：\n"
    for category, items in failures.items():
        if items:
            prompt += f"\n[{category}]类失败：\n" + "\n".join(f"  - {item}" for item in items)
    prompt += (
        "\n\n请只针对上述失败步骤生成修复版计划。已经成功的漏洞无需再测。"
        "重点修复 Pickle 反序列化的语法问题、命令注入的 payload 参数选择、SSRF 的内网地址替换。"
        "每个失败步骤生成 1-2 个修复变体。"
    )
    return prompt

def run_pipeline(confirmed_path: Path | None = None) -> int:
    settings = get_settings()
    memory = LayeredMemory(settings.memory_dir)
    ws = settings.workspace_dir
    ws.mkdir(parents=True, exist_ok=True)

    confirmed_file = confirmed_path or settings.confirmed_vuln_path
    confirmed = _load_confirmed(confirmed_file)
    print(f"[coordinator] 输入漏洞文件: {confirmed_file}")
    print(f"[coordinator] mock_llm={settings.mock_llm}, model={settings.deepseek_model}")

    llm: DeepSeekClient | None = None
    if settings.deepseek_api_key and not settings.mock_llm:
        llm = DeepSeekClient(settings)

    plan_path = ws / "plan.json"
    validated_path = ws / "validated_plan.json"
    exec_path = ws / "execution_result.json"
    feedback_path = ws / "feedback.json"

    feedback: dict[str, Any] | None = None
    last_plan: dict[str, Any] | None = None
    success_log: list[dict[str, Any]] = []
    _retry_iteration_done = False

    for iteration in range(1, settings.max_iterations + 1):
        print(f"[coordinator] 迭代 {iteration}/{settings.max_iterations}")

        _print_agent_header("planner")
        last_plan = run_planner(
            settings=settings,
            memory=memory,
            confirmed=confirmed,
            feedback=feedback,
            out_path=plan_path,
            llm=llm,
        )
        print(
            f"[planner] plan_id={last_plan.get('plan_id')} steps={len(last_plan.get('steps') or [])} "
            f"输出={plan_path.name}"
        )
        for st in (last_plan.get("steps") or []):
            if isinstance(st, dict) and st.get("type") == "python":
                print(f"[planner] step_id={st.get('id')} python_cmd={repr(st.get('command', ''))[:220]}")

        _print_agent_header("validator")
        v = run_validator(plan_path, validated_path)
        val = v.get("validation", {})
        warnings = v.get("warnings") or []
        print(
            f"[validator] passed={val.get('passed')} "
            f"errors={len(val.get('errors') or [])} warnings={len(warnings)} 输出={validated_path.name}"
        )
        if warnings:
            print("[validator] 自动修复/提示:", warnings)
        if not v["validation"]["passed"]:
            feedback = {
                "from": "validator",
                "iteration": iteration,
                "errors": v["validation"]["errors"],
                "warnings": warnings,
                "hint": "根据校验错误修订 plan.json 结构与安全策略",
            }
            print("[coordinator] 验证未通过，反馈规划智能体:", v["validation"]["errors"])
            continue

        _print_agent_header("executor")
        try:
            exec_out = run_executor(
                validated_path=validated_path,
                result_path=exec_path,
                workdir=settings.project_root,
                timeout_sec=settings.docker_timeout,
                docker_image=settings.docker_image,
                dockerfile_dir=_ROOT,
            )
        except Exception as e:
            print(f"[executor] 🚨 FATAL: {e}")
            exec_out = {
                "version": 1,
                "executed": False,
                "execution_mode": "security_blocked",
                "step_results": [],
                "error": str(e),
            }
        step_results = exec_out.get("step_results") or []
        ok_cnt = sum(1 for r in step_results if (r.get("result") or {}).get("ok"))
        fail_cnt = len(step_results) - ok_cnt
        print(
            f"[executor] executed={exec_out.get('executed')} steps={len(step_results)} "
            f"ok={ok_cnt} fail={fail_cnt} 输出={exec_path.name}"
        )
        if fail_cnt > 0:
            for r in step_results:
                rr = r.get("result") or {}
                if not rr.get("ok"):
                    print(
                        f"[executor] step_id={r.get('step_id')} exit={rr.get('exit_code')} "
                        f"stderr={(rr.get('stderr') or '')[:160]}"
                    )

        _print_agent_header("evaluator")
        fb = run_evaluator(
            settings=settings,
            memory=memory,
            confirmed=confirmed,
            plan=last_plan,
            exec_out=exec_out,
            feedback_path=feedback_path,
            llm=llm,
        )
        feedback = fb
        print(
            f"[evaluator] repro_success={fb.get('repro_success')} confidence={fb.get('confidence')} "
            f"should_continue={fb.get('should_continue')} 输出={feedback_path.name}"
        )

        if fb.get("repro_success"):
            conf = fb.get("confidence", 0)
            print(f"[coordinator] ✅ 本轮复现成功！confidence={conf}")
            success_log.append({
                "iteration": iteration,
                "plan_id": last_plan.get("plan_id"),
                "confidence": fb.get("confidence"),
                "summary": fb.get("summary", ""),
            })
            fb["repro_success"] = True
            fb["success_log"] = success_log
            if conf >= 0.65:
                failures = _count_execution_failures(exec_out)
                has_failures = any(v for v in failures.values())
                if has_failures and not _retry_iteration_done and iteration < settings.max_iterations:
                    _retry_iteration_done = True
                    print(f"[coordinator] 🟡 置信度达标但存在失败步骤: skipped={len(failures['skipped'])} error={len(failures['error'])} blocked={len(failures['blocked'])}")
                    print("[coordinator] 🔄 启动定向修复迭代，专攻失败步骤...")
                    retry_prompt = _build_retry_prompt(failures, confirmed)
                    fb["feedback_for_planner"] = retry_prompt
                    fb["should_continue"] = True
                    feedback = fb
                    continue
                print(f"[coordinator] 🎉 置信度 {conf:.0%} 达标，停止迭代。")
                break
            vulns = confirmed.get("vulnerabilities") or []
            remaining = [f"CWE-{v.get('cwe_id','').replace('CWE-','')} {v.get('vuln_name','')}" for v in vulns]
            fb["feedback_for_planner"] = (
                (fb.get("feedback_for_planner") or "")
                + f" 【继续探索】目标系统仍有漏洞待验证。confirmed_vuln 中共 {len(remaining)} 个漏洞：\n"
                + "\n".join(f"  - {r}" for r in remaining)
                + "\n请根据 confirmed_vuln 中各条目生成新计划。已成功的漏洞可跳过，集中攻击尚未验证的漏洞。确保每个漏洞类型至少一个步骤。"
            )
            feedback = fb
            continue

        if fb.get("should_continue") is False:
            print("[coordinator] 评估建议终止迭代。")
            return 2

    if success_log:
        print(f"[coordinator] 🎉 总计复现成功 {len(success_log)} 次！")
        for s in success_log:
            print(f"[coordinator]   迭代{s['iteration']} plan={s['plan_id']} confidence={s['confidence']}")
        return 0
    print("[coordinator] 达到最大迭代次数，未判定成功。")
    return 3


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Co-RedTeam 协调器（多智能体 + 分层长期记忆）")
    parser.add_argument(
        "--confirmed",
        type=Path,
        default=None,
        help="confirmed_vuln.json 路径，默认 data/confirmed_vuln.json",
    )
    args = parser.parse_args()
    code = run_pipeline(confirmed_path=args.confirmed)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
