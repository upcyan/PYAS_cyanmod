"""Portable detector-contract tests: no real malware, model, driver or native calls."""
import ast
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from itertools import islice
from types import SimpleNamespace
from unittest.mock import Mock

from PYAS_Detection import DetectionResult, detection_result, detection_view

ROOT = Path(__file__).resolve().parents[1]


def load_methods(filename, owner, names, **extra):
    tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == owner)
    methods = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(methods) == len(names)
    scope = dict(os=os, threading=threading, time=time, islice=islice,
                 DetectionResult=DetectionResult, detection_result=detection_result,
                 log_exception=Mock(), exception_sequence=lambda: 0, **extra)
    exec(compile(ast.Module(body=methods, type_ignores=[]), filename, "exec"), scope)
    return type(owner, (), {name: scope[name] for name in names})


Scanner = load_methods("PYAS_Scanner.py", "ScannerMixin",
                       {"scan_engine", "safe_scan_engine", "_scan_retry_state", "_retry_verified_scan"})
Rules = load_methods("PYAS_Rules.py", "RuleScanner",
                     {"__init__", "last_description", "yara_scan", "yara_mem_scan"})
Realtime = load_methods("PYAS_Realtime.py", "RealtimeMixin", {"handle_new_process"},
                        PYAS_PROCESS_SCAN_ACCESS=1)


class Match:
    def __init__(self, name, description):
        self.name = name
        self.meta = {"description": description}

    def __str__(self):
        return self.name


class DetectionEvidenceTests(unittest.TestCase):
    def test_legacy_label_and_json_are_compatible(self):
        label = "Malware:WinPE/General.91!ml"
        result = detection_result(label, "ml", 91)
        self.assertIsInstance(result, str)
        self.assertEqual(result, label)
        self.assertEqual(json.loads(json.dumps({"finding": result})), {"finding": label})
        self.assertEqual(detection_view(copy.deepcopy(result)), detection_view(result))

    def test_score_comes_from_engine_not_rounded_label(self):
        result = detection_result("Malware:WinPE/General.91!ml", "ml", 89.5)
        data = detection_view(result)
        self.assertEqual(data["score"], 89.5)
        self.assertEqual(data["score_kind"], "model_probability")
        self.assertTrue(data["generic"])
        self.assertEqual(data["family"], "General")
        self.assertEqual(data["category"], "Malware")

    def test_suspicious_classification_is_preserved(self):
        data = detection_view(detection_result("Suspicious:WinPE/General.54!ml", "ml", 54))
        self.assertEqual(data["score"], 54)
        self.assertEqual(data["category"], "Suspicious")

    def test_invalid_scores_never_become_probabilities(self):
        for value in (None, False, True, "90", -1, 101, float("nan"), float("inf")):
            with self.subTest(value=value):
                data = detection_view(detection_result("Malware:WinPE/General.90!ml", "ml", value))
                self.assertIsNone(data["score"])
                self.assertEqual(data["score_kind"], "not_provided")

    def test_zero_score_is_not_confused_with_missing(self):
        self.assertEqual(detection_view(detection_result("custom", "ml", 0))["score"], 0)

    def test_yara_fixed_100_is_not_a_probability(self):
        for engine in ("yr", "ym"):
            with self.subTest(engine=engine):
                data = detection_view(detection_result("Trojan:JS/Test.2!" + engine,
                    engine, 100, "observed strings", ("Trojan_JS_Test", "Trojan_JS_Other")))
                self.assertIsNone(data["score"])
                self.assertEqual(data["score_kind"], "rule_match")
                self.assertEqual(data["rule_count"], 2)
                self.assertEqual(len(data["rules"]), 2)
                self.assertEqual(data["description"], "observed strings")

    def test_legacy_labels_use_only_known_encoding(self):
        self.assertEqual(detection_view("Malware:WinPE/General.88!ml")["score"], 88)
        yara = detection_view("Trojan:JS/Test.3!yr")
        self.assertIsNone(yara["score"])
        self.assertEqual(yara["rule_count"], 3)
        self.assertIsNone(detection_view("Malware:WinPE/General.999!ml")["score"])
        self.assertEqual(detection_view("a random 100% claim")["engine"], "unknown")

    def test_missing_and_policy_evidence_are_not_malware(self):
        for value in (None, False, "", {}):
            self.assertEqual(detection_view(value)["status"], "unknown")
        data = detection_view({"remote_ip": "192.0.2.1"}, "Network Block")
        self.assertEqual(data["engine"], "network")
        self.assertEqual(data["status"], "policy")
        self.assertIsNone(data["score"])

    def test_unknown_rule_name_not_guessed(self):
        data = detection_view(detection_result("custom_rule", "yr", 100, rules=("custom_rule",)))
        self.assertEqual(data["category"], "")
        self.assertEqual(data["family"], "")
        self.assertEqual(data["raw_label"], "custom_rule")

    def test_views_are_detached_from_cached_facts(self):
        result = detection_result("Trojan:JS/Test.1!yr", "yr", rules=("one",))
        view = detection_view(result)
        view["rules"].append("injected")
        view["score"] = 100
        self.assertEqual(detection_view(result)["rules"], ["one"])
        self.assertIsNone(detection_view(result)["score"])


class RuleEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.scanner = Rules()
        self.scanner.rules = Mock()

    def test_file_match_carries_all_rule_names_and_description(self):
        self.scanner.rules.match.return_value = [Match("Trojan_JS_Test", "download and execute"), Match("Trojan_JS_Other", "other")]
        label, score = self.scanner.yara_scan("fixture.js")
        self.assertEqual(score, 100)  # legacy API kept, UI never treats this as probability
        self.assertEqual(str(label), "Trojan:JS/Test.2!yr")
        self.assertEqual(label.evidence.description, "download and execute")
        self.assertEqual(len(label.evidence.rules), 2)

    def test_description_is_cleared_after_no_hit_or_error(self):
        self.scanner.rules.match.return_value = [Match("Trojan_JS_Test", "old description")]
        result, _ = self.scanner.yara_scan("hit")
        self.scanner.rules.match.return_value = []
        self.assertEqual(self.scanner.yara_scan("clean"), (False, False))
        self.assertEqual(self.scanner.last_description(), "")
        self.assertEqual(result.evidence.description, "old description")
        self.scanner.rules.match.side_effect = OSError("unreadable")
        self.assertEqual(self.scanner.yara_scan("error"), (False, False))
        self.assertEqual(self.scanner.last_description(), "")

    def test_memory_match_and_unstructured_name(self):
        self.scanner.rules.match.return_value = [Match("custom", "observed memory marker")]
        result, _ = self.scanner.yara_mem_scan(42)
        self.assertEqual(str(result), "custom")
        self.assertEqual(result.evidence.engine, "ym")
        self.assertIsNone(result.evidence.score)


class ScannerEvidenceTests(unittest.TestCase):
    def setUp(self):
        s = self.scanner = Scanner()
        s.lock_config = threading.RLock()
        s.lock_file_ops = threading.RLock()
        s.pyas_config = {"extension_switch": True, "sensitive_switch": False}
        s.properties = SimpleNamespace(pe_scan=Mock(return_value=(False, False)))
        s.heuristic = SimpleNamespace(yara_scan=Mock(return_value=(False, False)))
        s.norm_path = lambda path: path
        s._acquire_file_scan_gate = Mock(return_value=(123, None))
        s.calc_file_hash = Mock(return_value="content-a")
        s.kernel32 = SimpleNamespace(CloseHandle=Mock())
        s.hash_cache = {}
        s.scan_events = {}

    def test_ml_precedes_yara_and_passes_actual_score(self):
        self.scanner.properties.pe_scan.return_value = ("Malware:WinPE/General.93!ml", 92.5)
        result = self.scanner.scan_engine("fixture")
        self.assertEqual(result.evidence.score, 92.5)
        self.scanner.heuristic.yara_scan.assert_not_called()

    def test_extension_disabled_keeps_yara_disabled(self):
        self.scanner.pyas_config["extension_switch"] = False
        self.assertFalse(self.scanner.scan_engine("fixture"))
        self.scanner.heuristic.yara_scan.assert_not_called()

    def test_yara_cached_metadata_does_not_use_thread_last_description(self):
        result = detection_result("Trojan:JS/Test.1!yr", "yr", description="first scan", rules=("Trojan_JS_Test",))
        self.scanner.heuristic.yara_scan.return_value = (result, 100)
        first = self.scanner.safe_scan_engine("file-a")
        self.scanner.heuristic.yara_scan.return_value = (detection_result("Trojan:JS/Other.1!yr", "yr", description="other file"), 100)
        out = []
        thread = threading.Thread(target=lambda: out.append(self.scanner.safe_scan_engine("file-b-same-content")))
        thread.start(); thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertIs(out[0], first)
        self.assertEqual(out[0].evidence.description, "first scan")
        self.scanner.heuristic.yara_scan.assert_called_once()
        self.assertEqual(self.scanner.kernel32.CloseHandle.call_count, 2)
        self.assertEqual(self.scanner.scan_events, {})

    def test_policy_and_content_changes_invalidate_cache(self):
        self.scanner.properties.pe_scan.return_value = ("Suspicious:WinPE/General.60!ml", 60)
        self.scanner.safe_scan_engine("a")
        self.scanner.pyas_config["sensitive_switch"] = True
        self.scanner.safe_scan_engine("a")
        self.scanner.calc_file_hash.return_value = "content-b"
        self.scanner.safe_scan_engine("a")
        self.assertEqual(self.scanner.properties.pe_scan.call_count, 3)
        self.assertEqual(self.scanner.kernel32.CloseHandle.call_count, 3)

    def test_gate_and_pending_state_release_on_unexpected_scan_error(self):
        self.scanner.scan_engine = Mock(side_effect=RuntimeError("scan failed"))
        with self.assertRaises(RuntimeError):
            self.scanner.safe_scan_engine("a")
        self.assertEqual(self.scanner.hash_cache, {})
        self.assertEqual(self.scanner.scan_events, {})
        self.scanner.kernel32.CloseHandle.assert_called_once_with(123)

    def test_deferred_scan_uses_bound_result_not_thread_metadata(self):
        with tempfile.NamedTemporaryFile() as file:
            result = detection_result("Malware:WinPE/General.90!ml", "ml", 90)
            self.scanner.closing = False
            self.scanner.safe_scan_engine = Mock(return_value=result)
            self.scanner.request_block_decision = Mock(return_value=True)
            self.scanner.manage_named_list = Mock()
            self.scanner.lock_file = Mock()
            self.scanner.write_log = Mock()
            self.scanner._retry_verified_scan(file.name)
            self.scanner.request_block_decision.assert_called_once_with("Deferred Scan Block", source=file.name, detection=result)

    def test_process_dll_preserves_detection_and_closes_handle(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as file:
            app = Realtime()
            app.lock_config = threading.RLock()
            app.pyas_config = {"suffix_switch": False, "load_switch": True}
            app.get_process_cmdline = lambda _: ""
            app.get_process_file = lambda _: file.name
            app.extract_paths_from_cmdline = lambda _: []
            app.norm_path = app.device_path_to_drive = lambda p: p
            app.is_in_whitelist = lambda _: False
            app.safe_scan_engine = lambda _: False
            app.cloud_check = Mock()
            result = detection_result("Malware:WinPE/General.91!ml", "ml", 91)
            app.scan_process_memory = Mock(return_value=("loaded.dll", result))
            app.request_block_decision = Mock(return_value=False)
            app.write_log = Mock()
            app.kernel32 = SimpleNamespace(CloseHandle=Mock())
            app.handle_new_process(77, h=123, suspended=False)
            app.scan_process_memory.assert_called_once_with(77, 123, include_result=True)
            app.request_block_decision.assert_called_once_with("Process DLL Block", source="loaded.dll", pid=77, detection=result)
            app.kernel32.CloseHandle.assert_called_once_with(123)


if __name__ == "__main__":
    unittest.main()
