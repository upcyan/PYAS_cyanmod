# -*- coding: utf-8 -*-
"""AI 接入层:OpenAI 兼容协议统一云端与本地模型(Ollama / LM Studio 等)。

P1 提供连接性验证;P2 的拦截建议与 P3 的日志归纳都复用这里的配置
(ai_provider_mode / ai_base_url / ai_api_key / ai_model)。
"""
from PYAS_Diagnostics import log_exception
import json
import re
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


    def scan_local_ai_models(self):
        base_url, _, api_key = self._ai_endpoint_config()

        if not base_url:
            return {"ok": False, "error": "missing_config"}

        models = detect_local_models(base_url, api_key)
        return {"ok": bool(models), "models": models}


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


def parse_rule_drafts(content):
    """从模型回复提取抑制规则草案;严格校验哈希与枚举,任何不合规条目丢弃。"""
    if not isinstance(content, str):
        return None

    start, end = content.find("{"), content.rfind("}")

    if start < 0 or end <= start:
        return None

    try:
        data = json.loads(content[start:end + 1])
    except Exception:
        return None

    drafts = data.get("drafts") if isinstance(data, dict) else None

    if not isinstance(drafts, list):
        return None

    valid = []

    for item in drafts[:10]:
        if not isinstance(item, dict):
            continue

        digest = str(item.get("sha256", "")).strip().lower()

        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            continue

        reason = item.get("reason") if item.get("reason") in (
            "dev_tool", "installer", "enterprise", "game_patch") else "other"
        valid.append({"sha256": digest, "reason": reason,
            "note": str(item.get("note", "")).strip()[:200]})

    return valid


def request_rule_drafts(base_url, model, api_key, candidates, lang="english_switch"):
    """把近期放行记录交给模型归纳候选抑制规则;失败返回 None(绝不自动生效)。"""
    language = _VERDICT_LANGUAGES.get(lang, "English")
    system = (
        "You curate false-positive suppression rules for PYAS, a Windows antivirus. "
        "Given recent file-allow decisions (SHA-256 with counts), pick only entries that "
        "clearly look like legitimate recurring software (build tools, package managers, "
        "installers, updaters, dev servers). Never propose rules for anything that could be "
        "malware, packed, or unfamiliar. Reply with strict JSON only and no markdown: "
        '{"drafts":[{"sha256":"64 hex chars","reason":"dev_tool|installer|enterprise|game_patch",'
        '"note":"at most 120 characters"}]} '
        "Return an empty drafts list when nothing qualifies. Write notes in " + language + "."
    )
    user = json.dumps(candidates, ensure_ascii=False)

    try:
        response = requests.post(
            f"{base_url}/chat/completions",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0,
                "max_tokens": 800,
                "stream": False,
            },
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=_AI_VERDICT_TIMEOUT * 2,
        )
    except Exception:
        log_exception("PYAS_AI.request_rule_drafts")
        return None

    if response.status_code != 200:
        return None

    try:
        content = response.json()["choices"][0]["message"]["content"]
    except Exception:
        return None

    return parse_rule_drafts(content)


def detect_local_models(base_url, api_key=""):
    """探测 OpenAI 兼容 /models(覆盖 Ollama / LM Studio);失败返回空列表。"""
    try:
        response = requests.get(f"{base_url}/models", timeout=4,
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {})
    except Exception:
        return []

    if response.status_code != 200:
        return []

    try:
        data = response.json()
    except Exception:
        return []

    models = data.get("data") if isinstance(data, dict) else data

    if not isinstance(models, list):
        return []

    ids = {str(item.get("id", "")).strip() for item in models if isinstance(item, dict)}
    return sorted(item for item in ids if item)
