"""Deterministic bridge/queue blocking regressions; no native windows or processes."""
import threading
import unittest
from unittest.mock import Mock

from PYAS_Dialog import DialogMixin, _DecisionRequest, _ThreatPromptQueue, _WebThreatDialogSession


class Owner(DialogMixin):
    def __init__(self):
        self.lock_config = threading.RLock()
        self.pyas_config = {"theme": "white_switch", "language": "simplified_switch"}


def request(name, timeout=None):
    return _DecisionRequest("simplified_switch", name, "fixture", timeout, rule={
        "key": name, "source": "C:/fixture/" + name + ".js", "sha256": "0" * 64,
        "target": "", "action": "File Block", "detection": '"fixture"'})


class DecisionResponsivenessTests(unittest.TestCase):
    def session(self, queue, owner=None):
        session = _WebThreatDialogSession("zh", "fixture", "fixture", None, str, queue, owner or Owner())
        session.api.ready()
        return session

    def assert_queue_available(self, queue):
        acquired = queue.condition.acquire(timeout=.3)
        try:
            self.assertTrue(acquired, "external work is holding the decision queue lock")
        finally:
            if acquired:
                queue.condition.release()

    def test_snapshot_never_runs_external_signature_probe(self):
        owner = Owner()
        entered, release = threading.Event(), threading.Event()
        def signer(rule):
            entered.set()
            release.wait(3)
            return None
        owner._rule_signer = Mock(side_effect=signer)
        q = _ThreatPromptQueue()
        q.active = request("first")
        session = self.session(q, owner)
        result = []
        reader = threading.Thread(target=lambda: result.append(session.api.snapshot()))
        try:
            reader.start(); reader.join(.3)
            self.assertFalse(reader.is_alive(), "snapshot must not wait for a PowerShell signature query")
            owner._rule_signer.assert_not_called()
            self.assertEqual(result[0]["id"], q.active.id)
        finally:
            release.set(); reader.join(2); q.close()

    def test_countdown_snapshot_does_not_wait_for_config_writer(self):
        owner = Owner()
        q = _ThreatPromptQueue()
        q.active = request("timer", timeout=5)
        q.active.ai = {"state": "unavailable"}
        session = self.session(q, owner)
        entered, release = threading.Event(), threading.Event()
        def writer():
            with owner.lock_config:
                entered.set(); release.wait(3)
        holder = threading.Thread(target=writer)
        result = []
        reader = threading.Thread(target=lambda: result.append(session.api.snapshot()))
        try:
            holder.start(); self.assertTrue(entered.wait(1))
            reader.start(); reader.join(.3)
            self.assertFalse(reader.is_alive(), "countdown path still waits for global configuration lock")
            self.assertEqual(result[0]["remaining"], 5)
        finally:
            release.set(); holder.join(2); reader.join(2); q.close()

    def test_late_policy_allow_cannot_block_manual_decision_or_allow_new_event(self):
        entered, release = threading.Event(), threading.Event()
        first, second, third = request("one"), request("two"), request("three")
        def lookup(rule, uses):
            if rule is second.rule:
                entered.set(); release.wait(3); return "allow"
            return None
        q = _ThreatPromptQueue(policy_lookup=lookup)
        q.active = first
        q.pending.extend([second, third])
        session = self.session(q)
        first_call = threading.Thread(target=lambda: session.api.decide(first.id, "block"))
        second_call = None
        try:
            first_call.start(); self.assertTrue(entered.wait(1))
            self.assertTrue(first.done.is_set())
            self.assert_queue_available(q)
            second_call = threading.Thread(target=lambda: session.api.decide(second.id, "block"))
            second_call.start(); second_call.join(.3)
            self.assertFalse(second_call.is_alive(), "manual decision waits for another event's policy lookup")
            self.assertEqual(second.choice, "block")
            self.assertIs(q.active, third)
            release.set(); first_call.join(2)
            self.assertFalse(third.done.is_set(), "late cached allow was applied to a different event")
            self.assertEqual(second.choice, "block")
        finally:
            release.set(); first_call.join(2)
            if second_call: second_call.join(2)
            q.close()

    def test_slow_ai_abort_releases_queue_for_next_request(self):
        entered, release = threading.Event(), threading.Event()
        q = _ThreatPromptQueue()
        first, second = request("first"), request("second")
        def abort():
            entered.set(); release.wait(3)
        first.ai_abort = abort
        q.active = first; q.pending.append(second)
        session = self.session(q)
        decider = threading.Thread(target=lambda: session.api.decide(first.id, "block"))
        try:
            decider.start(); self.assertTrue(entered.wait(1))
            self.assertTrue(first.done.is_set())
            self.assertTrue(first.ai_cancel.is_set())
            self.assert_queue_available(q)
            self.assertIs(q.take_next(), second)
        finally:
            release.set(); decider.join(2); q.close()

    def test_take_next_never_replaces_an_unresolved_active_request(self):
        lookup = Mock(return_value=None)
        q = _ThreatPromptQueue(policy_lookup=lookup)
        first, second = request("active"), request("pending")
        q.active = first; q.pending.append(second)
        try:
            self.assertIs(q.take_next(), first)
            self.assertEqual(list(q.pending), [second])
            lookup.assert_not_called()
            self.assertFalse(first.done.is_set())
        finally:
            q.close()

    def test_ai_start_callback_does_not_hold_queue_lock(self):
        entered, release = threading.Event(), threading.Event()
        def start(item):
            entered.set(); release.wait(3)
        q = _ThreatPromptQueue(ai_starter=start)
        q.worker = object()  # existing session/worker; don't start a native test window
        q.active = request("first")
        second = request("second")
        producer = threading.Thread(target=lambda: q.submit(second))
        try:
            producer.start(); self.assertTrue(entered.wait(1))
            self.assert_queue_available(q)
        finally:
            release.set(); q.close(); producer.join(2)
            self.assertFalse(producer.is_alive())


if __name__ == "__main__":
    unittest.main()
