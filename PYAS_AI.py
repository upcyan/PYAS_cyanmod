# -*- coding: utf-8 -*-
"""AI 接入层:OpenAI 兼容协议统一云端与本地模型(Ollama / LM Studio 等)。

P1 仅提供连接性验证;P2 的拦截建议与 P3 的日志归纳都复用这里的配置
(ai_provider_mode / ai_base_url / ai_api_key / ai_model)。
"""
from PYAS_Diagnostics import log_exception
import requests

# 连接测试的超时与探测消息;max_tokens 压到 1,避免测试消耗真实计费
_AI_TEST_TIMEOUT = 10


class AIMixin:
    def _ai_endpoint_config(self):
        with self.lock_config:
            base_url = str(self.pyas_config.get("ai_base_url", "")).strip().rstrip("/")
            model = str(self.pyas_config.get("ai_model", "")).strip()
            api_key = str(self.pyas_config.get("ai_api_key", "")).strip()

        return base_url, model, api_key

    def test_ai_connection(self):
        base_url, model, api_key = self._ai_endpoint_config()

        if not base_url or not model:
            return {"ok": False, "error": "missing_config"}

        try:
            response = requests.post(
                f"{base_url}/chat/completions",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                    "stream": False,
                },
                headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
                timeout=_AI_TEST_TIMEOUT,
            )
        except Exception as error:
            log_exception("PYAS_AI.AIMixin.test_ai_connection")
            return {"ok": False, "error": str(error)[:200]}

        if response.status_code == 200:
            return {"ok": True}

        return {
            "ok": False,
            "error": f"HTTP {response.status_code}",
            "detail": response.text[:200],
        }
