from __future__ import annotations

import json
import re
import time
from typing import Any

import openai
from openai import OpenAI

from core.settings import Settings


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
            )

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("未配置 API 密钥或已启用 MOCK 模式，不应调用 complete_json")
            
        if "json" not in system.lower():
            system += "\n\n请严格输出合法的 JSON 格式数据。"
            
        max_retries = 3  # 最大重试次数
        last_exception: Exception | None = None

        for attempt in range(max_retries):
            try:
                kwargs: dict[str, Any] = dict(
                    model=self._settings.deepseek_model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.2 + (attempt * 0.1),
                    max_tokens=8192,
                    timeout=120.0,
                )
                if self._settings.json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                resp = self._client.chat.completions.create(**kwargs)
                content = resp.choices[0].message.content or ""
                return _extract_json_object(content)

            except (json.JSONDecodeError, ValueError) as e:
                last_exception = e
                print(f"\n[llm] 触发自动重试 (JSON 解析失败): {e} (尝试 {attempt + 1}/{max_retries})")

            except (openai.APITimeoutError, openai.APIConnectionError,
                    openai.RateLimitError, openai.InternalServerError) as e:
                last_exception = e
                wait = 2 ** attempt  # 指数退避: 1s, 2s, 4s
                print(f"\n[llm] API 网络层错误，{wait}s 后重试 (尝试 {attempt + 1}/{max_retries}): {e}")
                time.sleep(wait)

        # 如果 3 次全部失败，再抛出异常
        print(f"\n[llm] 连续 {max_retries} 次失败，LLM 调用彻底不可用。")
        raise last_exception