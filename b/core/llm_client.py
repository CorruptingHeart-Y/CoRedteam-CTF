from __future__ import annotations

import json
import re
import time
from typing import Any

import openai
import httpx
from openai import OpenAI

from core.settings import Settings


class SchemaValidationError(Exception):
    """LLM 返回了 str 而非 dict — 必须重试，严禁将 Markdown 字符串当作 dict 传递。"""


def _extract_json_object(text: str) -> dict[str, Any]:
    """从模型回复中解析 JSON 对象（允许前后有说明文字）。"""
    text = text.strip()
    
    # 清理可能包含的 Markdown 代码块标记，防止 json.loads 报错
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'\s*```', '', text)
    
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
        
    # 扩大匹配范围，兼容对象 {...} 和数组 [...]
    m = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    if not m:
        raise ValueError("模型输出中未找到 JSON 对象")
        
    return json.loads(m.group(0))


class DeepSeekClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: OpenAI | None = None
        if settings.deepseek_api_key and not settings.mock_llm:
            self._client = OpenAI(
                api_key=settings.deepseek_api_key,
                base_url=settings.deepseek_base_url,
                max_retries=0,
            )

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("未配置 API 密钥或已启用 MOCK 模式，不应调用 complete_json")
            
        if "json" not in system.lower():
            system += "\n\n请严格输出合法的 JSON 格式数据。"
            
        max_retries = 3  # 最大重试次数
        last_exception: Exception | None = None

        _json_mode_active = self._settings.json_mode

        for attempt in range(max_retries):
            try:
                _timeout = httpx.Timeout(300.0, connect=15.0)
                kwargs: dict[str, Any] = dict(
                    model=self._settings.deepseek_model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.2 + (attempt * 0.1),
                    max_tokens=16384,
                )
                if _json_mode_active:
                    kwargs["response_format"] = {"type": "json_object"}
                resp = self._client.chat.completions.create(timeout=_timeout, **kwargs)

                # ── DIAGNOSTIC: prompt sizes ──
                sys_bytes = len(system.encode("utf-8"))
                usr_bytes = len(user.encode("utf-8"))
                print(f"[llm] DIAG — system_prompt: {len(system)} chars / {sys_bytes} bytes")
                print(f"[llm] DIAG — user_prompt:   {len(user)} chars / {usr_bytes} bytes")
                print(f"[llm] DIAG — total_prompt:  {len(system) + len(user)} chars / {sys_bytes + usr_bytes} bytes")

                # ── DIAGNOSTIC: usage / token estimate ──
                usage = getattr(resp, "usage", None)
                if usage is not None:
                    print(f"[llm] DIAG — usage: prompt_tokens={usage.prompt_tokens}, "
                          f"completion_tokens={usage.completion_tokens}, "
                          f"total_tokens={usage.total_tokens}")
                else:
                    print("[llm] DIAG — usage: NOT PRESENT in response")

                # ── DIAGNOSTIC: choices array ──
                print(f"[llm] DIAG — len(resp.choices)={len(resp.choices)}")

                # ── DIAGNOSTIC: message fields ──
                msg = resp.choices[0].message
                finish = resp.choices[0].finish_reason
                content = msg.content or ""
                reasoning = getattr(msg, "reasoning_content", None) or ""
                tool_calls = getattr(msg, "tool_calls", None)

                print(f"[llm] DIAG — finish_reason: {finish}")
                print(f"[llm] DIAG — content len:   {len(content)}")
                print(f"[llm] DIAG — reasoning_content len: {len(reasoning) if reasoning else 0}")
                print(f"[llm] DIAG — tool_calls: {tool_calls}")

                # ── DIAGNOSTIC: content preview ──
                if content:
                    print(f"[llm] DIAG — content[:500]: {repr(content[:500])}")
                else:
                    print("[llm] DIAG — content is EMPTY")
                    if reasoning:
                        print(f"[llm] DIAG — reasoning_content[:500]: {repr(reasoning[:500])}")

                # ── DIAGNOSTIC: raw message dump ──
                print(f"[llm] DIAG — raw message dict: {msg.model_dump() if hasattr(msg, 'model_dump') else msg}")

                # ── FIX: DeepSeek V4/R1 puts all output in reasoning_content ──
                if not content and reasoning:
                    print("[llm] DIAG — FALLBACK: content is empty, using reasoning_content for JSON extraction")
                    content = reasoning

                # ── DIAGNOSTIC: verdict ──
                if not content and reasoning:
                    print("[llm] DIAG — VERDICT: reasoning-only response, content is empty — 需要提取 reasoning_content 或切换模型")
                elif not content and finish == "length":
                    print("[llm] DIAG — VERDICT: truncated by max_tokens, content empty — 增大 max_tokens 或缩短 prompt")
                elif not content:
                    print("[llm] DIAG — VERDICT: content empty, finish_reason != 'length', 检查 response_format 兼容性")
                elif finish == "length":
                    print("[llm] DIAG — VERDICT: content present but truncated by length")
                else:
                    print("[llm] DIAG — VERDICT: normal response")
                print("=" * 80)

                result = _extract_json_object(content)
                if isinstance(result, str):
                    raise SchemaValidationError(
                        f"LLM 返回了纯字符串而非 dict: {result[:200]}..."
                    )
                return result

            except (json.JSONDecodeError, ValueError, SchemaValidationError) as e:
                last_exception = e
                print(f"\n[llm] 触发自动重试 (JSON 解析失败): {e} (尝试 {attempt + 1}/{max_retries})")

            except openai.BadRequestError as e:
                # BLSC/中转站可能拒绝 response_format → 降级重试
                err_msg = str(e)
                if _json_mode_active and ("400" in err_msg or "参数" in err_msg or "response_format" in err_msg.lower()):
                    _json_mode_active = False
                    print(f"\n[llm] response_format 被代理拒绝，降级为纯文本 JSON 模式 (尝试 {attempt + 1}/{max_retries})")
                    continue
                last_exception = e
                print(f"\n[llm] BadRequest 不可恢复: {e}")

            except (openai.APITimeoutError, openai.APIConnectionError,
                    openai.RateLimitError, openai.InternalServerError) as e:
                last_exception = e
                wait = 2 ** attempt  # 指数退避: 1s, 2s, 4s
                print(f"\n[llm] API 网络层错误，{wait}s 后重试 (尝试 {attempt + 1}/{max_retries}): {e}")
                time.sleep(wait)

        # 如果 3 次全部失败，再抛出异常
        print(f"\n[llm] 连续 {max_retries} 次失败，LLM 调用彻底不可用。")
        raise last_exception

    def complete_text(self, system: str, user: str) -> str:
        """调用 LLM 返回纯文本（非 JSON 模式）。使用与 complete_json 相同的重试策略。"""
        if self._client is None:
            raise RuntimeError("未配置 API 密钥或已启用 MOCK 模式")

        for attempt in range(3):
            try:
                resp = self._client.chat.completions.create(
                    model=self._settings.deepseek_model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.3,
                    max_tokens=16384,
                    timeout=httpx.Timeout(300.0, connect=15.0),
                )
                text = (resp.choices[0].message.content or "").strip()
                text = re.sub(r'^```(?:python)?\s*\n?', '', text)
                text = re.sub(r'\n?```\s*$', '', text)
                return text
            except Exception as e:
                wait = 2 ** attempt
                print(f"[llm] complete_text 失败，{wait}s 后重试 ({attempt + 1}/3): {type(e).__name__}: {e}")
                time.sleep(wait)
        return ""