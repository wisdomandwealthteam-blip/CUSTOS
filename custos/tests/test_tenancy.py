import os
import shutil
import tempfile
import threading
import unittest

from detgov import GovernanceViolation
from custos import CustosError, CustosGate, SecretVault, TenantIsolationError, TenantRegistry
from custos.core.tenancy import key_id
from tests.fixtures import PK_A, PK_B, PK_NEW, POLICY, SK_A, SK_B, SK_NEW, write_policy


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class Registration(unittest.TestCase):
    def test_signature_is_mandatory_and_keys_are_per_tenant(self):
        reg = TenantRegistry()
        reg.register_tenant("a", write_policy(), PK_A)
        self.assertEqual(reg.keys("a").current_hex, PK_A)
        with self.assertRaises(CustosError) as cm:
            reg.register_tenant("b", write_policy(key=SK_A), PK_B)               # signed with A's key, verified against B's
        self.assertEqual(cm.exception.code, "CS-T-003")
        with self.assertRaises(CustosError):
            reg.register_tenant("c", write_policy(sign=False), PK_A)
        self.assertEqual(reg.tenant_ids(), ["a"])                                  # failed registrations leave nothing behind
        reg.register_tenant("b", write_policy(key=SK_B), PK_B)
        self.assertEqual(reg.keys("b").current_hex, PK_B)
        self.assertNotEqual(reg.keys("a").current_id, reg.keys("b").current_id)
        with self.assertRaises(CustosError) as cm:
            reg.register_tenant("a", write_policy(), PK_A)
        self.assertEqual(cm.exception.code, "CS-T-004")

    def test_validation(self):
        reg = TenantRegistry()
        for tid in ("", "bad id", None, 5, "x" * 65):
            with self.assertRaises(CustosError):
                reg.register_tenant(tid, write_policy(), PK_A)
        for pk in ("", "zz", PK_A[:-1], None, 5):
            with self.assertRaises(CustosError):
                reg.register_tenant("a", write_policy(), pk)
        for tid in ("nobody", "", None):
            with self.assertRaises(CustosError) as cm:
                reg.state(tid)
            self.assertEqual(cm.exception.code, "CS-T-002")

    def test_tampered_policy_cannot_register(self):
        p = write_policy()
        text = open(p).read().replace('"allowlist": [', '"allowlist": ["os.fork", ')
        open(p, "w").write(text)
        with self.assertRaises(CustosError):
            TenantRegistry().register_tenant("a", p, PK_A)

    def test_cross_tenant_handler_namespaces(self):
        reg = TenantRegistry()
        reg.register_tenant("a", write_policy(), PK_A)
        reg.register_tenant("b", write_policy(key=SK_B), PK_B)
        reg.register_handler("a", "http.post", lambda p: {"a": 1})
        self.assertEqual(reg.firewall("a").execute("http.post", {}), {"a": 1})
        with self.assertRaises(GovernanceViolation) as cm:
            reg.firewall("b").execute("http.post", {})
        self.assertEqual(cm.exception.code, "DG-G-005")
        with self.assertRaises(ValueError):
            reg.register_handler("a", "http.post", lambda p: {})
        with self.assertRaises(TypeError):
            reg.register_handler("a", "db.query", "nope")


def policy_with(allow, **extra):
    return {**POLICY, "allowlist": allow, **extra}


class Rotation(unittest.TestCase):
    def setUp(self):
        self.clk = Clock()
        self.reg = TenantRegistry(clock=self.clk)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.pol = write_policy(self.dir, policy_with(["http.post", "db.query"]), key=SK_A)
        self.reg.register_tenant("a", self.pol, PK_A)
        self.reg.register_handler("a", "http.post", lambda p: {"v": 1})
        self.reg.register_handler("a", "db.query", lambda p: {"v": 2})

    def resign(self, key, allow=("http.post", "db.query")):
        return write_policy(self.dir, policy_with(list(allow)), key=key)

    def test_rotation_with_resigned_policy_swaps_atomically(self):
        old_state = self.reg.state("a")
        new_pol = self.resign(SK_NEW)
        res = self.reg.rotate_key("a", PK_NEW, policy_path=new_pol)
        new_state = self.reg.state("a")
        self.assertIsNot(old_state, new_state)
        self.assertEqual((res.old_key_id, res.new_key_id), (key_id(PK_A), key_id(PK_NEW)))
        self.assertEqual(new_state.keys.current_hex, PK_NEW)
        self.assertEqual(new_state.keys.version, 2)
        self.assertEqual(res.dropped_handlers, ())
        self.assertEqual(self.reg.firewall("a").execute("db.query", {}), {"v": 2})       # handlers carried over, service continuous
        self.assertEqual(old_state.firewall.execute("http.post", {}), {"v": 1})          # in-flight callers on the old state still work

    def test_failed_rotation_changes_nothing(self):
        before = self.reg.state("a")
        bad = [lambda: self.reg.rotate_key("a", PK_NEW, policy_path=self.pol),                        # policy signed by the OLD key
               lambda: self.reg.rotate_key("a", PK_NEW, policy_path="/nonexistent/policy.json"),
               lambda: self.reg.rotate_key("a", "nothex"),
               lambda: self.reg.rotate_key("a", PK_A),                                              # same key
               lambda: self.reg.rotate_key("a", PK_NEW, grace_seconds=-1),
               lambda: self.reg.rotate_key("a", PK_NEW, grace_seconds=True),
               lambda: self.reg.rotate_key("a", PK_NEW, grace_seconds=float("nan")),
               lambda: self.reg.rotate_key("a", PK_NEW, grace_seconds=31 * 86400)]
        for fn in bad:
            with self.assertRaises(CustosError) as cm:
                fn()
            self.assertEqual(cm.exception.code, "CS-T-003")
            self.assertIs(self.reg.state("a"), before)
        self.assertEqual(self.reg.firewall("a").execute("http.post", {}), {"v": 1})

    def test_rotation_without_policy_keeps_router_and_governs_next_reload(self):
        before = self.reg.state("a")
        self.reg.rotate_key("a", PK_NEW)
        after = self.reg.state("a")
        self.assertIs(after.router, before.router)
        self.assertIs(after.firewall, before.firewall)
        self.assertEqual(after.keys.current_hex, PK_NEW)
        self.resign(SK_A)                                                                        # old-key policy: rejected (no grace)
        with self.assertRaises(CustosError):
            self.reg.reload_policy("a")
        self.resign(SK_NEW)
        self.reg.reload_policy("a")                                                               # new-key policy: accepted

    def test_grace_window_accepts_previous_key_until_it_expires(self):
        self.reg.rotate_key("a", PK_NEW, grace_seconds=100)
        self.assertEqual(self.reg.keys("a").acceptable(self.clk.t), (PK_NEW, PK_A))
        self.resign(SK_A)
        self.clk.t = 99.9
        self.reg.reload_policy("a")                                                               # still inside grace
        self.clk.t = 100.0
        self.assertEqual(self.reg.keys("a").acceptable(self.clk.t), (PK_NEW,))
        with self.assertRaises(CustosError):
            self.reg.reload_policy("a")

    def test_grace_edges_and_expired_previous_keys_are_pruned(self):
        res0 = self.reg.rotate_key("a", PK_NEW, grace_seconds=0)
        self.assertEqual(self.reg.keys("a").previous, ())                                          # no grace -> nothing retained
        self.reg.rotate_key("a", PK_B, grace_seconds=30 * 86400)                                   # maximum accepted
        with self.assertRaises(CustosError):
            self.reg.rotate_key("a", PK_A, grace_seconds=30 * 86400 + 1)
        self.assertEqual(len(self.reg.keys("a").previous), 1)
        until = self.reg.keys("a").previous[0][1]
        self.clk.t = until                                                                         # exactly expired
        self.reg.rotate_key("a", PK_A, grace_seconds=10)
        self.assertEqual([pk for pk, _ in self.reg.keys("a").previous], [PK_B])                    # expired entry pruned, only the newest remains

    def test_revoke_previous_keys_is_immediate(self):
        self.reg.rotate_key("a", PK_NEW, grace_seconds=1000)
        v = self.reg.keys("a").version
        self.reg.revoke_previous_keys("a")
        self.assertEqual(self.reg.keys("a").version, v + 1)
        self.assertEqual(self.reg.keys("a").acceptable(self.clk.t), (PK_NEW,))
        self.resign(SK_A)
        with self.assertRaises(CustosError):
            self.reg.reload_policy("a")

    def test_tightened_policy_drops_handlers_fail_closed(self):
        new_pol = self.resign(SK_NEW, allow=("http.post",))
        res = self.reg.rotate_key("a", PK_NEW, policy_path=new_pol)
        self.assertEqual(res.dropped_handlers, ("db.query",))
        self.assertEqual(self.reg.firewall("a").execute("http.post", {}), {"v": 1})
        with self.assertRaises(GovernanceViolation) as cm:
            self.reg.firewall("a").execute("db.query", {})
        self.assertEqual(cm.exception.code, "DG-G-003")

    def test_loosened_policy_does_not_resurrect_unregistered_tools(self):
        new_pol = self.resign(SK_NEW, allow=("http.post", "db.query", "files.read"))
        self.reg.rotate_key("a", PK_NEW, policy_path=new_pol)
        with self.assertRaises(GovernanceViolation) as cm:
            self.reg.firewall("a").execute("files.read", {})
        self.assertEqual(cm.exception.code, "DG-G-005")

    def test_policy_reload_swaps_and_bumps_version(self):
        v0 = self.reg.state("a").version
        self.resign(SK_A, allow=("http.post",))
        res = self.reg.reload_policy("a")
        self.assertEqual((self.reg.state("a").version, res.dropped_handlers), (v0 + 1, ("db.query",)))
        with self.assertRaises(CustosError):
            self.reg.reload_policy("a", "/nonexistent")
        self.assertEqual(self.reg.state("a").version, v0 + 1)

    def test_hooks_run_after_swap_and_errors_are_isolated(self):
        calls = []
        self.reg.on_rotate(lambda r: calls.append(("ok", r.version, self.reg.keys("a").current_hex)))
        self.reg.on_rotate(lambda r: 1 / 0)
        self.reg.on_rotate(lambda r: calls.append(("after-bad", r.version)))
        self.reg.rotate_key("a", PK_NEW, policy_path=self.resign(SK_NEW))
        self.assertEqual(calls, [("ok", 2, PK_NEW), ("after-bad", 2)])                           # hook saw the NEW state; bad hook skipped, rest ran
        self.assertEqual(self.reg.hook_errors, [("a", "ZeroDivisionError")])
        self.assertEqual(self.reg.keys("a").current_hex, PK_NEW)
        calls.clear()
        with self.assertRaises(CustosError):
            self.reg.rotate_key("a", PK_NEW)                                                      # same key as current: fails, hooks not fired
        self.assertEqual(calls, [])

    def test_no_downtime_under_concurrent_traffic_and_rotation(self):
        keys = [(SK_A, PK_A), (SK_NEW, PK_NEW)]
        errors, stop, count = [], threading.Event(), [0]

        def traffic():
            while not stop.is_set():
                try:
                    r = self.reg.firewall("a").execute("http.post", {})
                    assert r == {"v": 1}
                    count[0] += 1
                except Exception as e:
                    errors.append(repr(e))
        ts = [threading.Thread(target=traffic) for _ in range(4)]
        [t.start() for t in ts]
        try:
            cur = 0
            for _ in range(12):
                nxt = 1 - cur
                self.reg.rotate_key("a", keys[nxt][1], policy_path=self.resign(keys[nxt][0]))
                cur = nxt
        finally:
            stop.set()
            [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertGreater(count[0], 50)
        self.assertEqual(self.reg.state("a").version, 13)

    def test_rotating_one_tenant_never_touches_another(self):
        self.reg.register_tenant("b", write_policy(key=SK_B), PK_B)
        sb = self.reg.state("b")
        self.reg.rotate_key("a", PK_NEW, policy_path=self.resign(SK_NEW))
        self.assertIs(self.reg.state("b"), sb)
        self.assertEqual(self.reg.keys("b").current_hex, PK_B)
        with self.assertRaises(CustosError):
            self.reg.reload_policy("b", self.resign(SK_NEW))              # a policy signed for A's new key does not verify under B's keys
        self.assertIs(self.reg.state("b"), sb)


if __name__ == "__main__":
    unittest.main()
