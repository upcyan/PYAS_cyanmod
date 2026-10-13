# -*- coding: utf-8 -*-
"""AI 接入层:OpenAI 兼容协议统一云端与本地模型(Ollama / LM Studio 等)。

P1 提供连接性验证;P2 的拦截建议与 P3 的日志归纳都复用这里的配置
(ai_provider_mode / ai_base_url / ai_api_key / ai_model)。
"""
from PYAS_Diagnostics import log_exception
import base64
import json
import re
import ctypes
import ctypes.wintypes
import requests

# 连接测试的超时与探测消息;max_tokens 压到 1,避免测试消耗真实计费
_AI_TEST_TIMEOUT = 10

# 拦截建议的裁决询问:证据有限时保守判拦截,放行只能由用户手动确认
_AI_VERDICT_TIMEOUT = 20

# 延迟启动:弹窗出现后先留出自主决策窗口,期间不发起任何请求(零 token 消耗)
AI_DELAY_MIN = 1
AI_DELAY_MAX = 30
AI_DELAY_DEFAULT = 3


def clamp_ai_delay_seconds(value):
    """把配置里的延迟秒数夹到合法区间;非法值回落到默认 3 秒。"""
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return AI_DELAY_DEFAULT

    return max(AI_DELAY_MIN, min(seconds, AI_DELAY_MAX))

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


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _to_blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))


def _from_blob(blob: _DATA_BLOB) -> bytes:
    if not blob.pbData or not blob.cbData:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def _dpapi_transform(data: bytes, protect: bool) -> bytes:
    """DPAPI:密文只绑定当前 Windows 用户与本机,配置文件泄露也拿不到明文。"""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    inp = _to_blob(data)
    out = _DATA_BLOB()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    ok = (crypt32.CryptProtectData(ctypes.byref(inp), None, None, None, None, flags, ctypes.byref(out))
          if protect else
          crypt32.CryptUnprotectData(ctypes.byref(inp), None, None, None, None, flags, ctypes.byref(out)))
    if not ok:
        raise OSError(f"DPAPI {'encrypt' if protect else 'decrypt'} failed: {ctypes.get_last_error()}")
    try:
        return _from_blob(out)
    finally:
        kernel32.LocalFree(out.pbData)


def protect_ai_key(plain: str) -> str:
    if not plain:
        return ""
    return base64.b64encode(_dpapi_transform(plain.encode("utf-8"), True)).decode("ascii")


def unprotect_ai_key(encoded: str) -> str:
    if not encoded:
        return ""
    return _dpapi_transform(base64.b64decode(encoded), False).decode("utf-8")


def mask_ai_key(key: str) -> str:
    key = (key or "").strip()
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:3]}{'*' * (len(key) - 7)}{key[-4:]}"


# ---- AI 建议结果缓存 ----
# 同一告警内容(SHA-256 锚定 key,无身份时用分析输入哈希)在 TTL 内复用,
# 避免每次弹窗重复连接模型消耗 token。内存级,进程重启即清空。
import threading as _threading
import time as _time
import hashlib as _hashlib

_VERDICT_CACHE = {}
_VERDICT_CACHE_LOCK = _threading.Lock()
_VERDICT_CACHE_TTL = 86400     # 24 小时:建议基于路径+SHA-256+检测的静态证据,反复触发无需重复询问模型
_VERDICT_CACHE_MAX = 128


def _cache_put(key, value):
    now = _time.time()
    with _VERDICT_CACHE_LOCK:
        if len(_VERDICT_CACHE) >= _VERDICT_CACHE_MAX:
            expired = [k for k, (v, t) in _VERDICT_CACHE.items() if now - t > _VERDICT_CACHE_TTL]
            for k in expired:
                _VERDICT_CACHE.pop(k, None)
            while len(_VERDICT_CACHE) >= _VERDICT_CACHE_MAX:
                _VERDICT_CACHE.pop(next(iter(_VERDICT_CACHE)), None)
        _VERDICT_CACHE[key] = (value, now)


def _cache_get(key):
    if not key:
        return None
    with _VERDICT_CACHE_LOCK:
        entry = _VERDICT_CACHE.get(key)

    if not entry:
        return None

    value, saved_at = entry

    if _time.time() - saved_at > _VERDICT_CACHE_TTL:
        with _VERDICT_CACHE_LOCK:
            _VERDICT_CACHE.pop(key, None)
        return None

    return value


_LAST_CACHE_HIT = {}


def is_verdict_cache_hit(cache_key):
    """worker 请求后查询本次是否命中缓存(审计标记;每键独立)。"""
    with _VERDICT_CACHE_LOCK:
        return bool(_LAST_CACHE_HIT.get(cache_key))


def request_ai_verdict_cached(cache_key, base_url, model, api_key,
                              category, title, detail, lang="english_switch",
                              usage_sink=None, cancel_event=None, session_holder=None):
    """带缓存的建议请求;命中直接返回,不发网络请求(也不计 token)。"""
    cached = _cache_get(cache_key)

    if cached:
        with _VERDICT_CACHE_LOCK:
            _LAST_CACHE_HIT[cache_key] = True
        return cached

    with _VERDICT_CACHE_LOCK:
        _LAST_CACHE_HIT[cache_key] = False

        if len(_LAST_CACHE_HIT) > _VERDICT_CACHE_MAX:
            _LAST_CACHE_HIT.clear()

    suggestion = request_ai_verdict(base_url, model, api_key, category, title, detail, lang,
                                    usage_sink=usage_sink, cancel_event=cancel_event,
                                    session_holder=session_holder)

    # 已取消的建议一律作废:既不返回给调用方,也不入缓存
    # (否则用户下次遇到同一事件会拿到被作废的结论)
    if cancel_event is not None and cancel_event.is_set():
        return None

    if suggestion:
        _cache_put(cache_key, suggestion)

    return suggestion


def make_verdict_cache_key(rule, category, title, detail):
    if rule and rule.get("key"):
        return f"rule:{rule['key']}"
    if rule and rule.get("sha256"):
        return f"sha:{rule['sha256']}"

    fingerprint = "\n".join((category or "", title or "", detail or ""))
    return "fp:" + _hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


class AIMixin:
    def _ai_endpoint_config(self):
        with self.lock_config:
            base_url = str(self.pyas_config.get("ai_base_url", "")).strip().rstrip("/")
            model = str(self.pyas_config.get("ai_model", "")).strip()
            encoded = str(self.pyas_config.get("ai_api_key_enc", "")).strip()
            legacy = str(self.pyas_config.get("ai_api_key", "")).strip()

        api_key = ""

        if encoded:
            try:
                api_key = unprotect_ai_key(encoded)
            except Exception:
                log_exception("PYAS_AI.AIMixin._ai_endpoint_config.decrypt")
                api_key = ""
        elif legacy:
            # 旧明文配置:读取即用,下次保存自动升级为密文
            api_key = legacy

        return base_url, model, api_key

    def save_ai_config(self, base_url=None, model=None, provider_mode=None, api_key=None):
        """显式保存接口:API Key 一律以 DPAPI 密文落盘。"""
        with self.lock_config:
            encoded = str(self.pyas_config.get("ai_api_key_enc", "")).strip()
            legacy = str(self.pyas_config.get("ai_api_key", "")).strip()

            if encoded:
                try:
                    current_mask = mask_ai_key(unprotect_ai_key(encoded))
                except Exception:
                    log_exception("PYAS_AI.AIMixin.save_ai_config.mask")
                    current_mask = ""
            else:
                current_mask = mask_ai_key(legacy)

        with self.lock_config:
            if base_url is not None:
                self.pyas_config["ai_base_url"] = str(base_url).strip().rstrip("/")

            if model is not None:
                self.pyas_config["ai_model"] = str(model).strip()

            if provider_mode is not None and str(provider_mode) in ("local", "cloud"):
                self.pyas_config["ai_provider_mode"] = str(provider_mode)

            if api_key is not None:
                incoming = str(api_key).strip()

                # 空或与回传掩码一致 = 未修改,保留原密文
                if incoming and incoming != current_mask:
                    try:
                        self.pyas_config["ai_api_key_enc"] = protect_ai_key(incoming)
                    except Exception:
                        log_exception("PYAS_AI.AIMixin.save_ai_config.encrypt")
                        self.write_log("WARN", "AI Config",
                                       detail="DPAPI encrypt failed; key not saved", success=False)
                        return {"ok": False, "error": "encrypt_failed"}

                    self.pyas_config["ai_api_key"] = ""  # 清除历史明文

            ok = self.save_config()

        if not ok:
            return {"ok": False, "error": "persist_failed"}

        self.write_log("INFO", "AI Config", detail="Model access settings saved")
        return {"ok": True}

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
            # 连接测试同样向提供商计费(max_tokens=1 只是压到最低),用量照实计入
            try:
                tokens = _extract_total_tokens(response.json())

                if tokens > 0:
                    self.record_ai_token_usage(model, tokens)
            except Exception:
                log_exception("PYAS_AI.AIMixin.test_ai_connection.usage")

            return {"ok": True}

        return {
            "ok": False,
            "error": f"HTTP {response.status_code}",
            "detail": response.text[:200],
        }

    # ---- token 累计消耗(按模型分账,切换模型各计各的) ----
    _AI_MODEL_KEY_MAX = 64

    def _ai_usage_store(self):
        """配置里的用量表;缺省或损坏时重置为空 dict(计数功能降级不致命)。"""
        usage = self.pyas_config.get("ai_token_usage")

        if not isinstance(usage, dict):
            usage = {}
            self.pyas_config["ai_token_usage"] = usage

        return usage

    def record_ai_token_usage(self, model, tokens, requests=1):
        """一次真实 API 调用的用量入账;tokens<=0 或落盘失败时静默跳过(绝不打断建议流程)。"""
        try:
            tokens = int(tokens or 0)
            requests = int(requests or 0)
        except Exception:
            return False

        if tokens <= 0 or requests <= 0:
            return False

        key = str(model or "").strip()[:self._AI_MODEL_KEY_MAX] or "(unknown)"

        with self.lock_config:
            entry = self._ai_usage_store().setdefault(key, {"tokens": 0, "requests": 0})

            if not isinstance(entry, dict):
                entry = {"tokens": 0, "requests": 0}
                self.pyas_config["ai_token_usage"][key] = entry

            entry["tokens"] = int(entry.get("tokens") or 0) + tokens
            entry["requests"] = int(entry.get("requests") or 0) + requests
            ok = self.save_config()

        if not ok:
            if hasattr(self, "write_log"):
                self.write_log("WARN", "AI Token Usage", detail=f"persist failed model={key}", success=False)

        return ok

    def get_ai_token_usage(self):
        """当前模型 + 分模型用量 + 总计;UI 切换模型后按模型名取各自累计。"""
        with self.lock_config:
            model = str(self.pyas_config.get("ai_model", "")).strip()
            raw = self.pyas_config.get("ai_token_usage")
            usage = {}

            if isinstance(raw, dict):
                for key, entry in raw.items():
                    if not isinstance(entry, dict):
                        continue

                    tokens = int(entry.get("tokens") or 0)
                    count = int(entry.get("requests") or 0)

                    if tokens > 0 or count > 0:
                        usage[str(key)] = {"tokens": tokens, "requests": count}

        return {
            "model": model,
            "usage": usage,
            "total": {
                "tokens": sum(item["tokens"] for item in usage.values()),
                "requests": sum(item["requests"] for item in usage.values()),
            },
        }

    def reset_ai_token_usage(self, model=None):
        """重置计数:指定模型只清该模型;model=None 清全部。返回重置后的最新用量。"""
        key = str(model or "").strip()[:self._AI_MODEL_KEY_MAX]

        with self.lock_config:
            if key:
                self._ai_usage_store().pop(key, None)
            else:
                self.pyas_config["ai_token_usage"] = {}

            ok = self.save_config()

        if not ok:
            return {"ok": False, "error": "persist_failed"}

        self.write_log("INFO", "AI Token Usage",
                       detail=f"counter reset scope={'all' if not key else key}")
        result = self.get_ai_token_usage()
        result["ok"] = True
        return result


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


def _extract_total_tokens(payload):
    """OpenAI 兼容响应的 usage;缺字段时按 prompt+completion 合计,再缺返回 0。"""
    if not isinstance(payload, dict):
        return 0

    usage = payload.get("usage")

    if not isinstance(usage, dict):
        return 0

    total = usage.get("total_tokens")

    if isinstance(total, (int, float)):
        return int(total)

    prompt = usage.get("prompt_tokens") or 0
    completion = usage.get("completion_tokens") or 0

    if isinstance(prompt, (int, float)) and isinstance(completion, (int, float)):
        return int(prompt) + int(completion)

    return 0


def request_ai_verdict(base_url, model, api_key, category, title, detail, lang="english_switch",
                       usage_sink=None, cancel_event=None, session_holder=None):
    """询问模型对一次拦截事件给出 block/allow 建议;失败返回 None(绝不默认放行)。

    cancel_event 用于「用户已自主决策」场景:
      - 发起前已取消 → 直接返回,不发请求;
      - 请求在途 → 通过 session_holder 暴露的 Session 关闭连接,尽早中断;
      - 响应已回但已取消 → 不解析、不计用量,调用方也不会入缓存。
    """
    if cancel_event is not None and cancel_event.is_set():
        return None

    language = _VERDICT_LANGUAGES.get(lang, "English")
    user_content = f"Category: {category}\nTitle: {title}\n{detail}\nWrite reason in {language}."

    session = requests.Session()

    if session_holder is not None:
        # 交给调用方持有句柄,取消时可从另一线程关闭在途连接
        session_holder.append(session)

    try:
        if cancel_event is not None and cancel_event.is_set():
            return None

        response = session.post(
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
        # 取消导致的连接中断属预期路径,不记异常
        if cancel_event is None or not cancel_event.is_set():
            log_exception("PYAS_AI.request_ai_verdict")

        return None
    finally:
        try:
            session.close()
        except Exception:
            pass

    if cancel_event is not None and cancel_event.is_set():
        return None

    if response.status_code != 200:
        return None

    try:
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
    except Exception:
        return None

    if usage_sink:
        # 计数失败绝不能影响建议本身;本地模型无 usage 字段时为 0,直接跳过
        try:
            tokens = _extract_total_tokens(payload)

            if tokens > 0:
                usage_sink(tokens)
        except Exception:
            log_exception("PYAS_AI.request_ai_verdict.usage_sink")

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
