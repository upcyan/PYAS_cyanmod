# -*- coding: utf-8 -*-
"""AI 接入层:OpenAI 兼容协议统一云端与本地模型(Ollama / LM Studio 等)。

P1 提供连接性验证;P2 的拦截建议与 P3 的日志归纳都复用这里的配置
(ai_provider_mode / ai_base_url / ai_api_key / ai_model)。
"""
from PYAS_Diagnostics import log_exception
import json
import requests

# 连接测试的超时与探测消息;max_tokens 压到 1,避免测试消耗真实计费
_AI_TEST_TIMEOUT = 10

# 拦截建议的裁决询问:证据有限时保守判拦截,放行只能由用户手动确认
_AI_VERDICT_TIMEOUT = 20

_AI_VERDICT_SYSTEM = (
    "You are a security analyst assisting PYAS, a Windows antivirus, with a user decision "
    "about one flagged event. Judge from an ordinary user's perspective: verdict \"block\" when "
    "the evidence suggests real malware, persistence, privilege escalation, data theft or "
    "tampering with security software; verdict \"allow\" when the event clearly looks like "
    "legitimate software behaviour (installers, updaters, build tools, package managers, "
    "scripts inside project directories). When evidence is insufficient, choose \"block\". "
    "Reply with strict JSON only and no markdown: "
    '{"verdict":"block"|"allow","reason":"at most 100 characters"}'
)

_VERDICT_LANGUAGES = {
    "simplified_switch": "Simplified Chinese",
    "traditional_switch": "Traditional Chinese",
    "japanese_switch": "Japanese",
    "korean_switch": "Korean",
    "french_switch": "French",
    "spanish_switch": "Spanish",
    "hindi_switch": "Hindi",
    "arabic_switch": "Arabic",
    "russian_switch": "Russian",
    "slovenian_switch": "Slovenian",
}


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


def parse_ai_verdict(content):
    """从模型回复中提取严格 JSON 裁决;任何不规范输入都返回 None。"""
    if not isinstance(content, str):
        return None

    start, end = content.find("{"), content.rfind("}")

    if start < 0 or end <= start:
        return None

    try:
        data = json.loads(content[start:end + 1])
    except Exception:
        return None

    if not isinstance(data, dict) or data.get("verdict") not in ("block", "allow"):
        return None

    reason = str(data.get("reason", "")).strip()[:200]
    return {"verdict": data["verdict"], "reason": reason}


def request_ai_verdict(base_url, model, api_key, category, title, detail, lang="english_switch"):
    """询问模型对一次拦截事件给出 block/allow 建议;失败返回 None(绝不默认放行)。"""
    language = _VERDICT_LANGUAGES.get(lang, "English")
    user_content = f"Category: {category}\nTitle: {title}\n{detail}\nWrite reason in {language}."

    try:
        response = requests.post(
            f"{base_url}/chat/completions",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": _AI_VERDICT_SYSTEM},
                    {"role": "user", "content": user_content},
                ],
                "temperature": 0,
                "max_tokens": 200,
                "stream": False,
            },
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=_AI_VERDICT_TIMEOUT,
        )
    except Exception:
        log_exception("PYAS_AI.request_ai_verdict")
        return None

    if response.status_code != 200:
        return None

    try:
        content = response.json()["choices"][0]["message"]["content"]
    except Exception:
        return None

    return parse_ai_verdict(content)
