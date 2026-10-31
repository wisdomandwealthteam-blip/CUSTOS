import gc
import json
import re
import threading
import unittest

from detgov import Firewall, GovernanceViolation
from detgov.core import Firewall as CoreFirewall
from custos import CustosError, CustosGate, SecretVault, TenantIsolationError, TenantRegistry
from custos.core.vault import HANDLE_RE, MIN_SECRET_BYTES, SecretLease
from tests.fixtures import PK_A, PK_B, SK_B, write_policy

RAW = "sk_test_" + "custosfixture" * 3


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def env(**gate_kw):
    reg, vault = TenantRegistry(), SecretVault()
    gate = CustosGate(reg, vault, **gate_kw)
    reg.register_tenant("tenant-a", write_policy(), PK_A)
    reg.register_tenant("tenant-b", write_policy(key=SK_B), PK_B)
    return reg, vault, gate


class ZeroLeakage(unittest.TestCase):
    def test_handle_format_is_cst_sec_uuid4(self):
        v = SecretVault()
        hs = {v.store("t", f"secret-value-{i:04d}") for i in range(200)}
        self.assertEqual(len(hs), 200)
        for h in hs:
            self.assertRegex(h, r"^cst_sec_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            self.assertIsNotNone(HANDLE_RE.fullmatch(h))

    def test_handles_never_look_like_card_numbers_to_detgov(self):
        from detgov.core.router import _PAN_RE, luhn_ok
        v = SecretVault()
        for i in range(3000):
            h = v.store("t", "x" * 8)
            for m in _PAN_RE.finditer(h):
                self.fail(f"{h} matches PAN regex: {m.group()}")
            v.revoke("t", h)

    def test_plaintext_not_stored_in_clear_and_repr_hides_everything(self):
        v = SecretVault()
        h = v.store("t", RAW, label="prod stripe")
        blob = repr(v) + repr(v.info("t", h)) + str(v.audit_log()) + repr(v._entries[h].ct)
        self.assertNotIn(RAW, blob)
        e = v._entries[h]
        self.assertNotIn(RAW.encode(), e.ct)
        self.assertEqual(len(e.ct), len(RAW))
        with v.lease("t", h) as lease:
            self.assertNotIn(RAW, repr(lease) + str(lease))
            self.assertEqual(bytes(lease.view()), RAW.encode())
            self.assertEqual(lease.text(), RAW)

    def test_lease_buffer_is_zeroed_and_unusable_after_close(self):
        v = SecretVault()
        h = v.store("t", RAW)
        lease = v.lease("t", h)
        buf = lease._buf
        view = lease.view()
        self.assertEqual(bytes(view), RAW.encode())
        lease.close()
        self.assertEqual(bytes(buf), b"\x00" * len(RAW))
        self.assertEqual(bytes(view), b"\x00" * len(RAW))
        self.assertTrue(lease.closed)
        with self.assertRaises(CustosError):
            lease.view()
        with self.assertRaises(CustosError):
            lease.text()
        lease.close()                                   # idempotent
        with v.lease("t", h) as l2:
            b2 = l2._buf
        self.assertEqual(bytes(b2), b"\x00" * len(RAW))

    def test_view_is_read_only(self):
        v = SecretVault()
        with v.lease("t", v.store("t", RAW)) as l:
            with self.assertRaises(TypeError):
                l.view()[0] = 0

    def test_bytearray_input_is_wiped_after_sealing(self):
        v = SecretVault()
        ba = bytearray(RAW.encode())
        h = v.store("t", ba)
        self.assertEqual(bytes(ba), b"\x00" * len(RAW))
        with v.lease("t", h) as l:
            self.assertEqual(l.text(), RAW)

    def test_bytes_and_unicode_secrets_roundtrip(self):
        v = SecretVault()
        for s in (RAW, RAW.encode(), "pässwörd-日本語-🔑-secret", bytes(range(8, 40)), "x" * 65536):
            h = v.store("t", s)
            with v.lease("t", h) as l:
                self.assertEqual(bytes(l.view()), s.encode() if isinstance(s, str) else s)

    def test_sealed_entry_swap_detected(self):
        v = SecretVault()
        h1, h2 = v.store("t", "first-secret-value"), v.store("t", "second-secret-val")
        e1, e2 = v._entries[h1], v._entries[h2]
        e1.ct, e1.nonce, e1.tag, e1.n = e2.ct, e2.nonce, e2.tag, e2.n            # splice entry 2's sealed bytes under handle 1
        with self.assertRaises(CustosError) as cm:
            v.lease("t", h1)
        self.assertEqual(cm.exception.code, "CS-V-006")
        e = v._entries[h2]
        e.ct = bytes([e.ct[0] ^ 1]) + e.ct[1:]
        with self.assertRaises(CustosError):
            v.lease("t", h2)

    def test_store_validation(self):
        v = SecretVault()
        bad = [("", RAW), ("bad tenant", RAW), (None, RAW), ("t", 5), ("t", None), ("t", "short"), ("t", "x" * 7), ("t", "x" * 65537), ("t", "\ud800" * 9), ("t", [RAW])]
        for tenant, s in bad:
            with self.assertRaises(CustosError, msg=repr((tenant, str(s)[:10]))):
                v.store(tenant, s)
        v.store("t", "x" * 8)
        v.store("t", "x" * 65536)
        for kw in ({"ttl_seconds": 0}, {"ttl_seconds": -1}, {"ttl_seconds": True}, {"ttl_seconds": "5"}, {"ttl_seconds": float("nan")}, {"ttl_seconds": float("inf")},
                   {"max_uses": 0}, {"max_uses": -1}, {"max_uses": 1.5}, {"max_uses": True}, {"tools": "http.post"}, {"tools": []}, {"tools": ["bad tool"]}, {"tools": [5]},
                   {"label": 5}, {"label": "x" * 201}):
            with self.assertRaises(CustosError, msg=str(kw)):
                v.store("t", RAW, **kw)
        v.store("t", RAW, label="x" * 200, max_uses=1, ttl_seconds=0.5, tools=["a.b"])

    def test_capacity_limits(self):
        v = SecretVault(max_per_tenant=3)
        hs = [v.store("t", f"secret-value-{i}") for i in range(3)]
        with self.assertRaises(CustosError) as cm:
            v.store("t", "secret-value-9")
        self.assertEqual(cm.exception.code, "CS-V-007")
        v.store("other", "secret-value-9")
        v.revoke("t", hs[0])
        v.store("t", "secret-value-10")

    def test_close_erases_and_disables(self):
        v = SecretVault()
        h = v.store("t", RAW)
        v.close()
        self.assertEqual(len(v), 0)
        for fn in (lambda: v.lease("t", h), lambda: v.store("t", RAW), lambda: v.peek("t", h), lambda: v.revoke("t", h), lambda: v.scan_material("t")):
            with self.assertRaises(CustosError) as cm:
                fn()
            self.assertEqual(cm.exception.code, "CS-V-008")

    def test_revoke_and_purge(self):
        clk = Clock()
        v = SecretVault(clock=clk)
        h1, h2, h3 = v.store("t", "secret-number-1"), v.store("t", "secret-number-2", ttl_seconds=10), v.store("t", "secret-number-3", max_uses=1)
        self.assertTrue(v.revoke("t", h1))
        self.assertFalse(v.revoke("t", h1))
        with self.assertRaises(CustosError) as cm:
            v.lease("t", h1)
        self.assertEqual(cm.exception.code, "CS-V-001")
        clk.t += 11
        v.lease("t", h3).close()
        self.assertEqual(v.purge(), 2)
        self.assertEqual(v.handles("t"), [])
        v.store("t", "secret-number-4")
        v.store("u", "secret-number-5")
        self.assertEqual(v.revoke_tenant("t"), 1)
        self.assertEqual(len(v), 1)
        self.assertEqual(len(v.handles("u")), 1)                     # only tenant t's secrets were destroyed
        self.assertEqual(v.handles("t"), [])


class Boundaries(unittest.TestCase):
    def test_ttl_and_use_bounds(self):
        v = SecretVault()
        v.store("t", RAW, ttl_seconds=10 ** 9 - 1)
        with self.assertRaises(CustosError):
            v.store("t", RAW, ttl_seconds=10 ** 9)
        with self.assertRaises(CustosError):
            v.store("t", RAW, ttl_seconds=0)
        v.store("t", RAW, ttl_seconds=1e-6)
        v.store("t", RAW, max_uses=10 ** 9)
        v.store("t", RAW, max_uses=1)
        with self.assertRaises(CustosError):
            v.store("t", RAW, max_uses=10 ** 9 + 1)
        with self.assertRaises(CustosError):
            v.store("t", RAW, max_uses=0)

    def test_tools_all_must_be_valid(self):
        v = SecretVault()
        for bad in (["ok.tool", "bad tool"], ["bad tool", "ok.tool"], ["ok.tool", 5]):
            with self.assertRaises(CustosError):
                v.store("t", RAW, tools=bad)

    def test_capacity_accounting_survives_revocations(self):
        v = SecretVault(max_per_tenant=3)
        hs = [v.store("t", f"secret-value-{i}") for i in range(3)]
        v.revoke("t", hs[0])
        v.store("t", "secret-value-x")                                # back to 3
        with self.assertRaises(CustosError) as cm:
            v.store("t", "secret-value-y")
        self.assertEqual(cm.exception.code, "CS-V-007")
        v.revoke_tenant("t")
        for i in range(3):
            v.store("t", f"secret-value-n{i}")
        with self.assertRaises(CustosError):
            v.store("t", "secret-value-z")

    def test_lease_exit_does_not_swallow_exceptions_and_repr_reflects_state(self):
        v = SecretVault()
        h = v.store("t", RAW)
        with self.assertRaises(ZeroDivisionError):
            with v.lease("t", h) as l:
                self.assertEqual(repr(l), "<SecretLease open>")
                1 / 0
        self.assertTrue(l.closed)
        self.assertEqual(repr(l), "<SecretLease closed>")

    def test_minimum_length_secret_is_still_scrubbed(self):
        from custos.core.scrub import Scrubber
        v = SecretVault()
        h = v.store("t", "12345678")
        self.assertEqual(Scrubber(v).scrub("t", "pw=12345678;")[0], f"pw={h};")


class TenantBoundary(unittest.TestCase):
    def test_tenant_a_cannot_resolve_tenant_b_handle(self):
        v = SecretVault()
        hb = v.store("tenant-b", RAW)
        for call in (lambda: v.lease("tenant-a", hb), lambda: v.peek("tenant-a", hb), lambda: v.info("tenant-a", hb), lambda: v.revoke("tenant-a", hb)):
            with self.assertRaises(TenantIsolationError) as cm:
                call()
            self.assertEqual(cm.exception.code, "CS-T-001")
            self.assertNotIn(RAW, str(cm.exception))
        with v.lease("tenant-b", hb) as l:                 # owner unaffected, nothing consumed or destroyed by the failed attempts
            self.assertEqual(l.text(), RAW)

    def test_failed_cross_tenant_attempt_consumes_nothing(self):
        v = SecretVault()
        h = v.store("b", RAW, max_uses=1)
        for _ in range(5):
            with self.assertRaises(TenantIsolationError):
                v.lease("a", h)
        self.assertEqual(v.info("b", h).uses_remaining, 1)
        v.lease("b", h).close()

    def test_isolation_in_audit_and_listing(self):
        v = SecretVault()
        ha, hb = v.store("a", "secret-for-tenant-a"), v.store("b", "secret-for-tenant-b")
        self.assertEqual(v.handles("a"), [ha])
        with self.assertRaises(TenantIsolationError):
            v.lease("a", hb)
        self.assertIn("CS-T-001", [e[5] for e in v.audit_log()])

    def test_unknown_and_malformed_handles_are_not_isolation_errors(self):
        v = SecretVault()
        for h in ("cst_sec_00000000-0000-4000-8000-000000000000", "junk", "", None, 5, ["x"]):
            with self.assertRaises(CustosError) as cm:
                v.lease("a", h)
            self.assertEqual(cm.exception.code, "CS-V-001")
            self.assertNotIsInstance(cm.exception, TenantIsolationError)

    def test_gate_raises_isolation_error_for_foreign_handle(self):
        reg, vault, gate = env()
        gate.register_handler("tenant-b", "http.post", lambda p: {"ok": True})
        hb = vault.store("tenant-b", RAW)
        with self.assertRaises(TenantIsolationError):
            gate.execute("tenant-a", "http.post", {"auth": hb})
        with self.assertRaises(TenantIsolationError):
            gate.execute("tenant-a", "http.post", {"nested": {"l": [f"Bearer {hb}"]}})
        self.assertEqual(gate.audit_log()[-1]["outcome"], "error")
        self.assertEqual(gate.audit_log()[-1]["code"], "CS-T-001")


class TtlAndCounts(unittest.TestCase):
    def test_ttl_expiry(self):
        clk = Clock()
        v = SecretVault(clock=clk)
        h = v.store("t", RAW, ttl_seconds=60)
        clk.t += 59.999
        v.lease("t", h).close()
        self.assertAlmostEqual(v.info("t", h).seconds_remaining, 0.001, places=3)
        clk.t += 0.001                                   # exactly at expiry: expired
        with self.assertRaises(CustosError) as cm:
            v.lease("t", h)
        self.assertEqual(cm.exception.code, "CS-V-002")
        self.assertEqual(v.info("t", h).state, "expired")

    def test_invocation_exhaustion(self):
        v = SecretVault()
        h = v.store("t", RAW, max_uses=3)
        for i in range(3):
            v.lease("t", h).close()
            self.assertEqual(v.info("t", h).uses_remaining, 2 - i)
        with self.assertRaises(CustosError) as cm:
            v.lease("t", h)
        self.assertEqual(cm.exception.code, "CS-V-003")
        self.assertEqual(v.info("t", h).state, "exhausted")
        with self.assertRaises(CustosError):
            v.peek("t", h)

    def test_peek_does_not_consume(self):
        v = SecretVault()
        h = v.store("t", RAW, max_uses=1)
        for _ in range(10):
            self.assertEqual(v.peek("t", h).uses_remaining, 1)
        v.lease("t", h).close()
        with self.assertRaises(CustosError):
            v.lease("t", h)

    def test_concurrent_leases_never_exceed_max_uses(self):
        v = SecretVault()
        h = v.store("t", RAW, max_uses=50)
        ok, bad = [], []

        def work():
            for _ in range(40):
                try:
                    v.lease("t", h).close()
                    ok.append(1)
                except CustosError as e:
                    bad.append(e.code)
        ts = [threading.Thread(target=work) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(ok), 50)
        self.assertEqual(set(bad), {"CS-V-003"})

    def test_tool_binding(self):
        v = SecretVault()
        h = v.store("t", RAW, tools=["http.post", "db.query"], max_uses=5)
        for bad in (None, "files.read", "HTTP.POST"):
            with self.assertRaises(CustosError) as cm:
                v.lease("t", h, bad)
            self.assertEqual(cm.exception.code, "CS-V-005")
        self.assertEqual(v.info("t", h).uses_remaining, 5)                        # refused attempts consume nothing
        self.assertEqual(v.info("t", h).tools, ("db.query", "http.post"))
        v.lease("t", h, "db.query").close()
        free = v.store("t", RAW)
        v.lease("t", free, None).close()
        v.lease("t", free, "anything").close()

    def test_expired_and_exhausted_secrets_remain_scrubbable_until_purged(self):
        reg, vault, gate = env()
        clk = Clock()
        vault._clock = clk
        h = vault.store("tenant-a", RAW, ttl_seconds=1)
        clk.t += 5
        self.assertEqual(gate.sanitize("tenant-a", f"echo {RAW}"), f"echo {h}")
        vault.purge()
        self.assertNotIn(h, gate.sanitize("tenant-a", f"echo {RAW}"))


class FirewallIntegration(unittest.TestCase):
    """Conformance: Custos wraps detgov.core.Firewall; DetGov policy decisions, errors and sanitisers keep working unchanged."""

    def test_gate_uses_a_real_detgov_firewall(self):
        reg, vault, gate = env()
        self.assertIs(type(reg.firewall("tenant-a")), CoreFirewall)
        self.assertIs(CoreFirewall, Firewall)

    def test_allowed_call_dispatches_through_detgov_and_injects_only_at_the_boundary(self):
        reg, vault, gate = env()
        seen = {}

        def post(p):
            seen["auth"] = p["headers"]["Authorization"]
            return {"status": 200, "echo": p["headers"]["Authorization"], "n": 1}
        gate.register_handler("tenant-a", "http.post", post)
        h = vault.store("tenant-a", RAW, tools=["http.post"], max_uses=3)
        out = gate.execute("tenant-a", "http.post", {"url": "https://api.example/v1", "headers": {"Authorization": f"Bearer {h}"}})
        self.assertEqual(seen["auth"], f"Bearer {RAW}")                          # handler got the real credential...
        self.assertEqual(out, {"status": 200, "echo": f"Bearer {h}", "n": 1})   # ...caller got a handle back
        blob = json.dumps(gate.audit_log()) + json.dumps(reg.firewall("tenant-a").audit_log()) + json.dumps(vault.audit_log(), default=str)
        self.assertNotIn(RAW, blob)
        self.assertIn(h, blob)
        self.assertEqual(vault.info("tenant-a", h).uses_remaining, 2)

    def test_detgov_denials_are_unchanged_and_never_consume_a_use(self):
        reg, vault, gate = env()
        h = vault.store("tenant-a", RAW, max_uses=1)
        for tool, code in (("os.fork", "DG-G-002"), ("eval", "DG-R-001"), ("not.listed", "DG-G-003"), ("google_search", "DG-B-001")):
            with self.assertRaises(GovernanceViolation) as cm:
                gate.execute("tenant-a", tool, {"k": h})
            self.assertEqual(cm.exception.code, code)
        self.assertEqual(vault.info("tenant-a", h).uses_remaining, 1)
        self.assertEqual([a["outcome"] for a in gate.audit_log()], ["denied"] * 4)

    def test_params_deny_rules_still_apply_with_handles_present(self):
        reg, vault, gate = env()
        gate.register_handler("tenant-a", "http.post", lambda p: {})
        h = vault.store("tenant-a", RAW)
        for params, code in (({"auth": h, "sudo": True}, "DG-G-001"), ({"auth": h, "unix_socket": "/x"}, "DG-B-002"), ({"auth": h, "pan": "4111111111111111"}, "DG-B-003")):
            with self.assertRaises(GovernanceViolation) as cm:
                gate.execute("tenant-a", "http.post", params)
            self.assertEqual(cm.exception.code, code)

    def test_handler_not_callable_outside_the_gate(self):
        reg, vault, gate = env()
        gate.register_handler("tenant-a", "http.post", lambda p: {"ok": 1})
        h = vault.store("tenant-a", RAW)
        with self.assertRaises(CustosError) as cm:
            reg.firewall("tenant-a").execute("http.post", {"auth": h})            # bypassing the gate: no context -> refused
        self.assertEqual(cm.exception.code, "CS-G-005")
        self.assertEqual(vault.info("tenant-a", h).state, "active")

    def test_unknown_tenant_and_missing_handler(self):
        reg, vault, gate = env()
        with self.assertRaises(CustosError) as cm:
            gate.execute("nobody", "http.post", {})
        self.assertEqual(cm.exception.code, "CS-T-002")
        with self.assertRaises(GovernanceViolation) as cm:
            gate.execute("tenant-a", "http.post", {})
        self.assertEqual(cm.exception.code, "DG-G-005")

    def test_tenants_have_separate_handlers_and_policies(self):
        reg, vault, gate = env()
        gate.register_handler("tenant-a", "http.post", lambda p: {"who": "a"})
        gate.register_handler("tenant-b", "http.post", lambda p: {"who": "b"})
        self.assertEqual(gate.execute("tenant-a", "http.post", {}), {"who": "a"})
        self.assertEqual(gate.execute("tenant-b", "http.post", {}), {"who": "b"})
        with self.assertRaises(GovernanceViolation):
            gate.register_handler("tenant-a", "os.fork", lambda p: {})

    def test_firewall_sanitisers_remain_available_per_tenant(self):
        reg, vault, gate = env()
        tools = [{"name": "http.post", "input_schema": {"type": "object"}}, {"type": "web_search_20250305", "name": "web_search"}, {"name": "os.fork", "input_schema": {}}]
        self.assertEqual([t["name"] for t in reg.firewall("tenant-a").sanitize_claude_tools(tools)], ["http.post"])


if __name__ == "__main__":
    unittest.main()
