from PYAS_Diagnostics import log_exception
import os
import threading
import yara
from PYAS_Detection import detection_result


class RuleScanner:
    def __init__(self):
        self.rules = None
        self.network = []
        # 检测结果翻译层:命中规则的 meta description,按扫描线程隔离
        self._meta_local = threading.local()

    def last_description(self):
        """同线程最近一次 yara_scan 的规则描述;无则空串。"""
        return str(getattr(self._meta_local, "description", "") or "")

    def load_path(self, path, callback=None):
        yara_files = {}

        for root, _, files in os.walk(path):
            for file in files:

                full_path = os.path.join(root, file)

                if callback:
                    callback(full_path)

                ext = os.path.splitext(file)[1].lower()

                if ext in (".yara", ".yar"):
                    namespace = os.path.relpath(full_path, path).replace(os.sep, "_")
                    yara_files[namespace] = full_path

                elif ext in (".yc", ".yrc"):
                    self.load_compiled_rule(full_path)

                elif ext in (".ip", ".txt"):
                    self.load_network_list(full_path)

        if yara_files:
            self.compile_all_rules(yara_files)

    def load_compiled_rule(self, file):
        try:
            self.rules = yara.load(file)
        except Exception:
            log_exception("PYAS_Rules.RuleScanner.load_compiled_rule:38")
            pass

    def load_network_list(self, file):
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                self.network.extend(line.strip() for line in f if line.strip())
        except Exception:
            log_exception("PYAS_Rules.RuleScanner.load_network_list:45")
            pass

    def compile_all_rules(self, file_map):
        try:
            self.rules = yara.compile(filepaths=file_map)
        except Exception:
            log_exception("PYAS_Rules.RuleScanner.compile_all_rules:51")
            pass

    def yara_scan(self, file_path):
        self._meta_local.description = ""
        try:
            if not self.rules:
                return False, False

            matches = self.rules.match(filepath=file_path)

            if matches:
                rule_name = str(matches[0])
                self._meta_local.description = str(matches[0].meta.get("description", "") or "")

                try:
                    label = rule_name.split("_")[0]
                    platform = rule_name.split("_")[1]
                    family = rule_name.split("_")[2]

                    finding = f"{label}:{platform}/{family}.{len(matches)}!yr"
                    return detection_result(finding, "yr",
                        description=self._meta_local.description, rules=tuple(map(str, matches))), 100
                except Exception:
                    log_exception("PYAS_Rules.RuleScanner.yara_scan:70")
                    return detection_result(rule_name, "yr",
                        description=self._meta_local.description, rules=tuple(map(str, matches))), 100

            return False, False
        except Exception:
            log_exception("PYAS_Rules.RuleScanner.yara_scan:74")
            return False, False

    def yara_mem_scan(self, pid):
        self._meta_local.description = ""
        try:
            if not self.rules:
                return False, False

            matches = self.rules.match(pid=pid)

            if matches:
                rule_name = str(matches[0])
                self._meta_local.description = str(matches[0].meta.get("description", "") or "")

                try:
                    label = rule_name.split("_")[0]
                    platform = rule_name.split("_")[1]
                    family = rule_name.split("_")[2]

                    finding = f"{label}:{platform}/{family}.{len(matches)}!ym"
                    return detection_result(finding, "ym",
                        description=self._meta_local.description, rules=tuple(map(str, matches))), 100
                except Exception:
                    log_exception("PYAS_Rules.RuleScanner.yara_mem_scan:91")
                    return detection_result(rule_name, "ym",
                        description=self._meta_local.description, rules=tuple(map(str, matches))), 100

            return False, False
        except Exception:
            log_exception("PYAS_Rules.RuleScanner.yara_mem_scan:95")
            return False, False
