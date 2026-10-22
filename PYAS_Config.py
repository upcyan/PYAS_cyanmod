from PYAS_Diagnostics import log_exception
from PYAS_AI import mask_ai_key
from PYAS_ETW import ETW_LOG_TEXTS
from PYAS_Version import UPSTREAM_TRACKED
import os
import copy
import json
import threading
from PYAS_Storage import atomic_write_json


class ConfigMixin:
    def _loc(self, text_dict):
        with self.lock_config:
            lang = (
                self.pyas_config.get("language", "traditional_switch")
                if hasattr(self, "pyas_config")
                else "traditional_switch"
            )

        return text_dict.get(lang, text_dict.get("traditional_switch", ""))

    # 主语言 ID(LANGID 低 10 位)到界面语言选项的映射
    SYSTEM_UI_LANGUAGES = {
        0x0001: "arabic_switch",
        0x000A: "spanish_switch",
        0x000C: "french_switch",
        0x0011: "japanese_switch",
        0x0012: "korean_switch",
        0x0019: "russian_switch",
        0x0024: "slovenian_switch",
        0x0039: "hindi_switch",
    }

    def detect_system_language(self):
        """首次生成配置时没有用户偏好,按用户 UI 语言选择界面语言;
        中文细分简繁,非 Windows 或检测失败时回退英文。"""
        try:
            import ctypes

            windll = getattr(ctypes, "windll", None)

            if windll is None:
                return "english_switch"

            langid = int(windll.kernel32.GetUserDefaultUILanguage()) & 0xFFFF
        except Exception:
            return "english_switch"

        if (langid & 0x03FF) == 0x0004:
            return "simplified_switch" if langid in (0x0804, 0x1004) else "traditional_switch"

        return self.SYSTEM_UI_LANGUAGES.get(langid & 0x03FF, "english_switch")

    def load_config(self):
        if getattr(self, '_policy_required', False):
            self._load_scoped_config()
            return
        with self.lock_config:

            if not os.path.exists(self.file_config):
                self.pyas_config = copy.deepcopy(self.pyas_default)
                self.pyas_config["language"] = self.detect_system_language()
                self.write_log("INFO", "Config Update", detail="Create default config")
                self.save_config()

            else:
                try:
                    with open(self.file_config, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.pyas_config = copy.deepcopy(self.pyas_default)
                        self.pyas_config.update(data)

                    self.pyas_config["version"] = self.pyas_default["version"]
                    whitelist_metadata_updated = False

                    for item in self.pyas_config.get("white_list", []):
                        if not isinstance(item, dict) or not item.get("file") or "is_dir" in item:
                            continue

                        item_path = self.norm_path(item["file"], must_exist=False)

                        if item_path and os.path.exists(item_path):
                            item["is_dir"] = os.path.isdir(item_path)
                            whitelist_metadata_updated = True

                    # 启动时回填 is_dir 属于派生信息,不是管理员的授权变更。
                    # 受策略约束时不能偷偷落盘(那是没有租约的策略写入,会被拒绝),
                    # 每次启动重新算一遍即可,代价是几次 stat。
                    if whitelist_metadata_updated and not getattr(self, '_policy_required', False):
                        self.save_config()
                except Exception as e:
                    log_exception("PYAS_Config.ConfigMixin.load_config:40")
                    self.pyas_config = copy.deepcopy(self.pyas_default)
                    self.pyas_config["language"] = self.detect_system_language()
                    self.write_log("WARN", "load_config", detail=str(e), success=False)

    def save_config(self):
        if getattr(self, '_policy_required', False):
            store = getattr(self, '_policy_store', None)
            if store is None:
                return False
            with self.lock_config:
                snapshot = copy.deepcopy(self.pyas_config)
            return store.save(snapshot)
        with self.lock_config:
            try:
                atomic_write_json(self.file_config, self.pyas_config)
                return True
            except Exception as error:
                log_exception("PYAS_Config.ConfigMixin.save_config:49")
                self.write_log("WARN", "save_config", detail=str(error), success=False)
                return False

    def update_config(self, key, value):
        with self.lock_update:
            with self.lock_config:
                old_value = self.pyas_config.get(key)

                if old_value == value:
                    return value

                defer_driver_disable = key == "driver_switch" and not value

                if not defer_driver_disable:
                    self.pyas_config[key] = value
                # Fork AI authority changes invalidate all old model generations,
                # even when the user quickly disables and re-enables the setting.
                if key in ('ai_assist_switch', 'ai_auto_execute'):
                    from PYAS_AI import clear_verdict_cache
                    self._ai_config_epoch = getattr(self, '_ai_config_epoch', 0) + 1
                    clear_verdict_cache()

            def apply_switch(state):
                if key == "cloud_switch":
                    with self.lock_config:
                        if state:
                            self.cloud_cancel_event = threading.Event()
                        else:
                            self.cloud_cancel_event.set()
                elif (
                    key in ("process_switch", "document_switch", "system_switch", "network_switch")
                    and state
                ):
                    target = {
                        "process_switch": self.protect_proc_thread,
                        "document_switch": self.protect_file_thread,
                        "system_switch": self.protect_system_thread,
                        "network_switch": self.protect_net_thread,
                    }[key]
                    self.start_feature_thread(target, key)
                elif key == "driver_switch":
                    if state:
                        if self.install_system_driver() and self.start_driver_listener(
                            wait_ready=True
                        ):
                            return True

                        self.stop_system_driver()
                        return False

                    return bool(self.stop_system_driver())
                elif key == "etw_attribution_switch":
                    # 未提权时消费者起不来,进程内切换永远失败 —— 弹 UAC 以
                    # 管理员重启(开关意愿已随正常路径持久化,重启后由引擎
                    # 初始化接管);用户拒绝 UAC 则回拨开关
                    if state:
                        ok, reason = self._etw_availability()

                        if not ok:
                            if reason == "elevated-required" and self.restart_application_elevated(
                                *self._etw_restart_notice("feature_etw")
                            ):
                                return True

                            from PYAS_ETW import UNAVAILABLE_REASON_KEYS

                            self.write_log(
                                "WARN",
                                "ETW Attribution",
                                detail=self._loc(ETW_LOG_TEXTS[UNAVAILABLE_REASON_KEYS[reason]])
                                if reason in UNAVAILABLE_REASON_KEYS else f"Unavailable: {reason}",
                                success=False,
                            )
                            return False

                        return bool(self.start_etw_consumer())

                    return self._stop_etw_with_behavior_notice()
                elif key == "behavior_defense_switch":
                    # 数据源是 ETW:未提权时同款提权重启;起不来回拨开关
                    if state:
                        ok, reason = self._etw_availability()

                        if not ok:
                            if reason == "elevated-required" and self.restart_application_elevated(
                                *self._etw_restart_notice("feature_behavior")
                            ):
                                return True

                            from PYAS_Behavior import ACTION_DEFENSE, BEHAVIOR_LOG_TEXTS

                            self.write_log(
                                "WARN",
                                ACTION_DEFENSE,
                                detail=self._loc(BEHAVIOR_LOG_TEXTS["requires_etw"]),
                                success=False,
                            )
                            return False

                        if not self.start_etw_consumer():
                            from PYAS_Behavior import ACTION_DEFENSE, BEHAVIOR_LOG_TEXTS

                            self.write_log(
                                "WARN",
                                ACTION_DEFENSE,
                                detail=self._loc(BEHAVIOR_LOG_TEXTS["requires_etw"]),
                                success=False,
                            )
                            return False

                        return True

                    return True
                elif key == "context_switch":
                    return self.register_context_menu(state, retry=bool(state)) is not False
                elif key == "classic_menu_switch":
                    return self.manage_classic_context_menu(state)
                elif key == "autostart_switch":
                    # 仅设置页开关允许弹 UAC 申请提权自启动;开机复核走默认不弹窗
                    return bool(self.manage_autostart(state, allow_elevate=True))
                elif key == "document_switch" and not state:
                    self._cancel_pending_file_scans()
                    # 先 CancelIoEx 再关句柄:同步读挂起期间直接 CloseHandle 会
                    # 让监视线程永久卡死(句柄失效后事件静默丢失)
                    self.stop_dir_watcher()
                elif key == "suspend_switch" and not state:
                    with self.lock_proc:
                        for handle in list(getattr(self, "suspended_procs", ())):
                            if self.ntdll.NtResumeProcess(handle) != 0:
                                raise OSError("Could not resume suspended process")

                            self.suspended_procs.discard(handle)

                return True

            action_succeeded = False

            try:
                if key in ("extension_switch", "sensitive_switch"):
                    with self.lock_file_ops:
                        self.hash_cache.clear()

                action_succeeded = apply_switch(value)

                if not action_succeeded:
                    raise RuntimeError(f"Could not apply {key}")

                with self.lock_config:
                    self.pyas_config[key] = value

                    if self.save_config() is False:
                        raise OSError("Could not persist configuration")

                self.write_log("INFO", "Config Update", detail=f"[{key}] {old_value} -> {value}")

                if key == "language" and self.tray_icon:
                    try:
                        self.tray_icon.update_menu()
                    except Exception:
                        log_exception("PYAS_Config.ConfigMixin.update_config:116")
                        pass

                return value
            except Exception as error:
                log_exception("PYAS_Config.ConfigMixin.update_config:119")
                self.write_log("WARN", "Config Update", detail=f"[{key}] {error}", success=False)

                with self.lock_config:
                    self.pyas_config[key] = old_value

                if action_succeeded:
                    try:
                        if apply_switch(old_value) is False:
                            raise RuntimeError(f"Could not roll back {key}")
                    except Exception as rollback_error:
                        log_exception("PYAS_Config.ConfigMixin.update_config:127")
                        self.write_log(
                            "WARN",
                            "Config Rollback",
                            detail=f"[{key}] {rollback_error}",
                            success=False,
                        )

                        if key == "driver_switch":
                            with self.lock_config:
                                self.pyas_config[key] = bool(self.check_system_driver())

                if self._window:
                    try:
                        self._window.evaluate_js(
                            f"if(window.revertSwitch) window.revertSwitch({json.dumps(key)});"
                        )
                    except Exception:
                        log_exception("PYAS_Config.ConfigMixin.update_config:135")
                        pass

                return self.pyas_config.get(key, old_value)

    def get_config(self):
        with self.lock_config:
            cfg = self.pyas_config.copy()
            cfg["autostart_mode"] = self.autostart_mode
            cfg["upstream_tracked"] = UPSTREAM_TRACKED
            # 界面据此在版本号后挂「开发者模式」标识;不读生成文件时按普通模式
            import PYAS_Channel
            cfg["dev_channel"] = bool(PYAS_Channel.IS_DEV)

            # API Key 不出库:回传掩码,密文字段一并剔除
            from PYAS_AI import unprotect_ai_key
            encoded = str(cfg.get("ai_api_key_enc", "")).strip()
            cfg.pop("ai_api_key_enc", None)

            if encoded:
                try:
                    cfg["ai_api_key"] = mask_ai_key(unprotect_ai_key(encoded))
                except Exception:
                    cfg["ai_api_key"] = ""
            else:
                cfg["ai_api_key"] = mask_ai_key(str(cfg.get("ai_api_key", "")))

            rules = []

            if os.path.exists(self.path_rules):
                for f in os.listdir(self.path_rules):
                    if f.lower().endswith(".json"):
                        fp = os.path.join(self.path_rules, f)
                        rules.append({"file": fp, "time": os.path.getmtime(fp)})

            cfg["custom_rule"] = rules
            return cfg

    def reset_config(self):
        with self.lock_update:
            with self.lock_config:
                previous = self.pyas_config
                self.pyas_config = copy.deepcopy(self.pyas_default)
                self.pyas_config["language"] = self.detect_system_language()

                if self.save_config() is False:
                    self.pyas_config = previous
                    return False

                self.write_log("INFO", "Config Update", detail="Reset to default")

        return True
