import base64
import json
import random
import unittest
from urllib.parse import quote

from detgov import GovernanceViolation
from custos import CustosError, CustosGate, HandlerError, SecretVault, TenantIsolationError, TenantRegistry
from custos.core.scrub import Scrubber
from custos.core.middleware import find_handles
from tests.fixtures import PK_A, PK_B, SK_B, write_policy

RAW = "sk_test_" + "custosfixture" * 3
DBURL = "postgres://svc_user:Tr0ub4dor&3xyz@db.internal:5432/app"


def env(**kw):
    reg, vault = TenantRegistry(), SecretVault()
    gate = CustosGate(reg, vault, **kw)
    reg.register_tenant("a", write_policy(), PK_A)
    reg.register_tenant("b", write_policy(key=SK_B), PK_B)
    return reg, vault, gate


class Scrubbing(unittest.TestCase):
    def setUp(self):
        self.vault = SecretVault()
        self.sc = Scrubber(self.vault)
        self.h = self.vault.store("a", RAW)

    def test_known_secret_in_every_encoding_becomes_the_handle(self):
        b = RAW.encode()
        forms = [RAW, base64.b64encode(b).decode(), base64.b64encode(b).decode().rstrip("="), base64.urlsafe_b64encode(b).decode(), b.hex(), b.hex().upper(), quote(RAW, safe=""), json.dumps(RAW)[1:-1]]
        for f in forms:
            out, rep = self.sc.scrub("a", {"msg": f"prefix {f} suffix", "l": [f]})
            self.assertEqual(out, {"msg": f"prefix {self.h} suffix", "l": [self.h]}, f)
            self.assertEqual(rep.known_handles, [self.h])
            self.assertTrue(rep.leaks)

    def test_secret_with_special_characters_json_and_url_forms(self):
        h2 = self.vault.store("a", 'pa"ss\\w/ord+=&?éx')
        for f in ('pa"ss\\w/ord+=&?éx', quote('pa"ss\\w/ord+=&?éx', safe=""), json.dumps('pa"ss\\w/ord+=&?éx')[1:-1]):
            self.assertEqual(self.sc.scrub("a", f)[0], h2)

    def test_keys_are_scrubbed_and_collisions_resolved(self):
        out, _ = self.sc.scrub("a", {RAW: 1, self.h: 2})
        self.assertEqual(set(out), {self.h, self.h + "~dup"})
        self.assertEqual(out[self.h] + out[self.h + "~dup"], 3)

    def test_other_tenants_secrets_are_not_touched_or_revealed(self):
        hb = self.vault.store("b", "another-tenants-secret-value")
        out, rep = self.sc.scrub("a", "text another-tenants-secret-value here")
        self.assertEqual(out, "text another-tenants-secret-value here")       # not A's secret: left alone (pattern detection only)
        self.assertNotIn(hb, out)

    def test_pattern_detection(self):
        cases = {
            "aws_access_key": "key AKIAIOSFODNN7EXAMPLE end", "github_token": "ghp_" + "a1B2" * 9, "slack_token": "xoxb-1234567890-abcdefghij",
            "stripe_key": "sk_test_" + "A1b2C3d4E5f6G7h8", "api_key": "sk-ant-api03-" + "Zz9_-" * 6, "google_api_key": "AIza" + "x" * 35,
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "bearer": "Authorization: Bearer abcdefghijklmnop1234567890", "pem_private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----",
            "url_password": DBURL, "keyed_value": "password=hunter2hunter2",
        }
        for kind, text in cases.items():
            out, rep = self.sc.scrub("a", {"x": text})
            self.assertIn(kind, rep.kinds, (kind, out))
            self.assertIn("[REDACTED", out["x"], kind)
        out, _ = self.sc.scrub("a", DBURL)
        self.assertEqual(out, "postgres://svc_user:[REDACTED:url_password]@db.internal:5432/app")
        self.assertNotIn("Tr0ub4dor", out)
        out, _ = self.sc.scrub("a", "-----BEGIN PRIVATE KEY----- truncated without end")
        self.assertEqual(out, "[REDACTED:pem_private_key] truncated without end")

    def test_keyed_values(self):
        out, rep = self.sc.scrub("a", {"password": "correct-horse-battery", "API-Key": "abcdefgh1234", "Authorization": "Basic dXNlcjpwYXNz", "token": "short", "name": "visible-value-123"})
        self.assertEqual(out["password"], "[REDACTED:keyed_value]")
        self.assertEqual(out["API-Key"], "[REDACTED:keyed_value]")
        self.assertEqual(out["Authorization"], "[REDACTED:keyed_value]")
        self.assertEqual((out["token"], out["name"]), ("short", "visible-value-123"))               # < 8 chars / non-sensitive key untouched
        out, rep = self.sc.scrub("a", {"token": self.h, "authorization": f"Bearer {self.h}"})
        self.assertEqual(out, {"token": self.h, "authorization": f"Bearer {self.h}"})                # handles are never redacted
        self.assertFalse(rep.leaks)
        out, _ = self.sc.scrub("a", {"authorization": f"Bearer {RAW}"})
        self.assertEqual(out, {"authorization": f"Bearer {self.h}"})                                  # known secret under a sensitive key -> handle, not blanket redaction

    def test_benign_text_is_untouched(self):
        benign = {"a": "hello world", "n": 42, "f": 1.5, "b": True, "z": None, "l": [1, "two", {"k": "v"}], "url": "https://example.com/path?q=1", "tokens_used": "123456789",
                  "email": "user@example.com", "sha": "a" * 64, "uuid": "123e4567-e89b-42d3-a456-426614174000"}
        out, rep = self.sc.scrub("a", benign)
        self.assertEqual(out, benign)
        self.assertFalse(rep.leaks)

    def test_input_not_mutated_and_non_json_rejected(self):
        src = {"a": [RAW, {"b": RAW}]}
        before = json.dumps(src)
        self.sc.scrub("a", src)
        self.assertEqual(json.dumps(src), before)
        for bad in ({"a": object()}, {"a": (1, 2)}, {"a": b"x"}, {1: "x"}, {"a": {1, 2}}):
            with self.assertRaises(CustosError) as cm:
                self.sc.scrub("a", bad)
            self.assertEqual(cm.exception.code, "CS-G-003")

    def test_depth_and_size_limits(self):
        deep = cur = []
        for _ in range(70):
            n = []
            cur.append(n)
            cur = n
        with self.assertRaises(CustosError):
            self.sc.scrub("a", deep)
        with self.assertRaises(CustosError):
            self.sc.scrub("a", list(range(100_001)))
        self.sc.scrub("a", list(range(99_999)))

    def test_exact_depth_and_sensitive_value_length_boundaries(self):
        def nest(levels):
            v = 1
            for _ in range(levels - 1):
                v = [v]
            return v
        self.sc.scrub("a", nest(64))
        with self.assertRaises(CustosError):
            self.sc.scrub("a", nest(65))
        def nest_d(levels):
            v = "x"
            for _ in range(levels - 1):
                v = {"k": v}
            return v
        self.sc.scrub("a", nest_d(64))
        with self.assertRaises(CustosError):
            self.sc.scrub("a", nest_d(65))
        self.assertEqual(self.sc.scrub("a", {"password": "12345678"})[0], {"password": "[REDACTED:keyed_value]"})
        self.assertEqual(self.sc.scrub("a", {"password": "1234567"})[0], {"password": "1234567"})

    def test_pathological_inputs_run_in_bounded_time(self):
        import time
        t = time.time()
        for text in ("-----BEGIN PRIVATE KEY-----" * 2000, "A" * 200000, "Bearer " + "a" * 100000, "password=" + "x" * 100000, "a://" + ":" * 100000, "xoxb-" + "-" * 100000):
            self.sc.scrub("a", text)
        self.assertLess(time.time() - t, 20)

    def test_short_secrets_are_not_stored(self):
        with self.assertRaises(CustosError):
            self.vault.store("a", "abc")

    def test_longer_variants_replace_before_shorter(self):
        h2 = self.vault.store("a", RAW + "-extended-suffix")
        self.assertEqual(self.sc.scrub("a", RAW + "-extended-suffix")[0], h2)
        self.assertEqual(self.sc.scrub("a", RAW)[0], self.h)

    def test_scan_buffers_are_wiped(self):
        mats = self.vault.scan_material("a")
        bufs = [b for _, b in mats]
        self.assertEqual(bytes(bufs[0]), RAW.encode())
        for b in bufs:
            b[:] = bytes(len(b))
        captured = []
        orig = self.vault.scan_material
        self.vault.scan_material = lambda t: (lambda m: (captured.extend(b for _, b in m), m)[1])(orig(t))
        self.sc.scrub("a", "x")
        self.assertTrue(captured and all(set(b) == {0} for b in captured))


class GateFlow(unittest.TestCase):
    def test_inbound_raw_known_secret_is_replaced_with_handle_before_detgov_and_audit(self):
        reg, vault, gate = env()
        seen = {}
        gate.register_handler("a", "http.post", lambda p: seen.update(p=json.loads(json.dumps(p))) or {"ok": 1})
        h = vault.store("a", RAW, max_uses=5)
        gate.execute("a", "http.post", {"body": f"key={RAW}"})
        self.assertEqual(seen["p"], {"body": f"key={RAW}"})                   # handler still gets the working credential
        a = gate.audit_log()[-1]
        self.assertEqual((a["outcome"], a["handles"], a["leaks"]), ("allowed", [h], {"known_secret": 1}))
        self.assertNotIn(RAW, json.dumps(gate.audit_log()) + json.dumps(reg.firewall("a").audit_log()))
        self.assertEqual(a["params"], json.dumps({"body": f"key={h}"}, sort_keys=True, separators=(",", ":")))

    def test_leak_policy_reject(self):
        reg, vault, gate = env(leak_policy="reject")
        gate.register_handler("a", "http.post", lambda p: {"ok": 1})
        h = vault.store("a", RAW)
        for params in ({"x": RAW}, {"x": DBURL}, {"password": "correct-horse-battery"}, {"x": "AKIAIOSFODNN7EXAMPLE"}):
            with self.assertRaises(CustosError) as cm:
                gate.execute("a", "http.post", params)
            self.assertEqual(cm.exception.code, "CS-G-001")
            self.assertNotIn(RAW, str(cm.exception))
            self.assertNotIn("Tr0ub4dor", str(cm.exception))
        self.assertEqual(gate.execute("a", "http.post", {"x": h}), {"ok": 1})        # handles are fine
        with self.assertRaises(ValueError):
            CustosGate(reg, vault, leak_policy="allow")

    def test_unknown_credentials_are_redacted_not_forwarded(self):
        reg, vault, gate = env()
        seen = {}
        gate.register_handler("a", "http.post", lambda p: seen.update(p=json.loads(json.dumps(p))) or {"ok": 1})
        gate.execute("a", "http.post", {"cs": DBURL, "k": "AKIAIOSFODNN7EXAMPLE"})
        self.assertNotIn("Tr0ub4dor", json.dumps(seen["p"]))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(seen["p"]))
        self.assertNotIn("Tr0ub4dor", json.dumps(gate.audit_log()))

    def test_use_counts_one_per_distinct_handle_per_call_and_only_on_dispatch(self):
        reg, vault, gate = env()
        gate.register_handler("a", "http.post", lambda p: {"ok": 1})
        h = vault.store("a", RAW, max_uses=3)
        gate.execute("a", "http.post", {"a": h, "b": [h, f"x{h}y"]})
        self.assertEqual(vault.info("a", h).uses_remaining, 2)
        with self.assertRaises(GovernanceViolation):
            gate.execute("a", "os.fork", {"a": h})
        self.assertEqual(vault.info("a", h).uses_remaining, 2)
        gate.execute("a", "http.post", {"a": h})
        gate.execute("a", "http.post", {"a": h})
        with self.assertRaises(CustosError) as cm:
            gate.execute("a", "http.post", {"a": h})
        self.assertEqual(cm.exception.code, "CS-V-003")
        self.assertEqual(gate.audit_log()[-1]["outcome"], "error")

    def test_handler_failure_still_consumes_the_use_and_leaks_nothing(self):
        reg, vault, gate = env()

        def boom(p):
            raise RuntimeError(f"upstream rejected credential {p['k']}")
        gate.register_handler("a", "http.post", boom)
        h = vault.store("a", RAW, max_uses=2)
        with self.assertRaises(HandlerError) as cm:
            gate.execute("a", "http.post", {"k": h})
        self.assertNotIn(RAW, str(cm.exception) + repr(cm.exception) + cm.exception.detail)
        self.assertIn(h, cm.exception.detail)
        self.assertIsNone(cm.exception.__context__)                                   # no chained exception carrying the plaintext
        self.assertEqual(vault.info("a", h).uses_remaining, 1)
        self.assertEqual(gate.audit_log()[-1]["code"], "CS-G-002")

    def test_result_scrubbing_covers_nested_encoded_and_unknown_secrets(self):
        reg, vault, gate = env()
        h = vault.store("a", RAW)
        gate.register_handler("a", "http.post", lambda p: {"deep": {"l": [base64.b64encode(RAW.encode()).decode(), "AKIAIOSFODNN7EXAMPLE"]}, "msg": f"auth failed for {RAW}"})
        out = gate.execute("a", "http.post", {"x": h})
        self.assertNotIn(RAW, json.dumps(out))
        self.assertEqual(out["deep"]["l"], [h, "[REDACTED:aws_access_key]"])
        self.assertEqual(out["msg"], f"auth failed for {h}")

    def test_handler_result_contract(self):
        reg, vault, gate = env()
        for ret in ("text", [1], None, {"x": object()}, {"x": b"bytes"}):
            reg2, vault2, gate2 = env()
            gate2.register_handler("a", "http.post", lambda p, r=ret: r)
            with self.assertRaises(CustosError) as cm:
                gate2.execute("a", "http.post", {})
            self.assertEqual(cm.exception.code, "CS-G-003")

    def test_handles_in_keys_are_refused(self):
        reg, vault, gate = env()
        gate.register_handler("a", "http.post", lambda p: {})
        h = vault.store("a", RAW)
        with self.assertRaises(CustosError) as cm:
            gate.execute("a", "http.post", {h: "x"})
        self.assertEqual(cm.exception.code, "CS-G-004")
        self.assertEqual(find_handles({"a": [f"{h}-{h}", {"b": h}], "c": "none"}), [h])
        self.assertEqual(find_handles("cst_sec_00000000-0000-1000-8000-000000000000"), [])     # not a uuid4 shape -> not a handle

    def test_lease_mode_gives_wipeable_buffers_and_refuses_embedded_handles(self):
        reg, vault, gate = env()
        got = {}

        def h_lease(p):
            lease = p["token"]
            got["lease"] = lease
            got["bytes"] = bytes(lease.view())
            return {"ok": True}
        gate.register_handler("a", "http.post", h_lease, inject="lease")
        h = vault.store("a", RAW)
        gate.execute("a", "http.post", {"token": h})
        self.assertEqual(got["bytes"], RAW.encode())
        self.assertTrue(got["lease"].closed)                                             # wiped when the call ended
        with self.assertRaises(CustosError) as cm:
            gate.execute("a", "http.post", {"token": f"Bearer {h}"})
        self.assertEqual(cm.exception.code, "CS-G-004")
        with self.assertRaises(ValueError):
            gate.register_handler("a", "db.query", lambda p: {}, inject="bogus")

    def test_dispatch_copy_is_wiped_after_the_call(self):
        reg, vault, gate = env()
        keep = {}
        gate.register_handler("a", "http.post", lambda p: keep.update(p=p) or {})
        h = vault.store("a", RAW)
        gate.execute("a", "http.post", {"hdr": {"Authorization": f"Bearer {h}"}, "l": [h]})
        self.assertNotIn(RAW, json.dumps(keep["p"]))

    def test_sanitize_helper_for_llm_facing_text(self):
        reg, vault, gate = env()
        h = vault.store("a", RAW)
        self.assertEqual(gate.sanitize("a", {"note": f"I used {RAW} and {DBURL}"}), {"note": f"I used {h} and postgres://svc_user:[REDACTED:url_password]@db.internal:5432/app"})
        vault.store("a", "opaque-internal-secret-zz")
        self.assertEqual(gate.sanitize("b", "I used opaque-internal-secret-zz"), "I used opaque-internal-secret-zz")   # not B's secret: only patterns apply
        self.assertEqual(gate.sanitize("b", f"I used {RAW}"), "I used [REDACTED:stripe_key]")

    def test_invalid_tool_names_are_audited_without_crashing(self):
        reg, vault, gate = env()
        for bad in (None, 5, ["x"], "a" * 129):
            with self.assertRaises(GovernanceViolation) as cm:
                gate.execute("a", bad, {})
            self.assertEqual(cm.exception.code, "DG-G-004")
            self.assertEqual(gate.audit_log()[-1]["tool"], "<invalid>")
        with self.assertRaises(GovernanceViolation):
            gate.execute("a", "a" * 128, {})
        self.assertEqual(gate.audit_log()[-1]["tool"], "a" * 128)

    def test_dispatch_requires_matching_tenant_and_tool_context(self):
        from custos.core.middleware import _CALL, _Call
        reg, vault, gate = env()
        gate.register_handler("a", "http.post", lambda p: {"ok": 1})
        gate.register_handler("a", "db.query", lambda p: {"ok": 2})
        fw = reg.firewall("a")
        for ctx in (_Call("b", "http.post"), _Call("a", "db.query"), _Call("b", "db.query")):
            tok = _CALL.set(ctx)
            try:
                with self.assertRaises(CustosError) as cm:
                    fw.execute("http.post", {})
                self.assertEqual(cm.exception.code, "CS-G-005")
            finally:
                _CALL.reset(tok)
        tok = _CALL.set(_Call("a", "http.post"))
        try:
            self.assertEqual(fw.execute("http.post", {}), {"ok": 1})
        finally:
            _CALL.reset(tok)

    def test_malformed_requests(self):
        reg, vault, gate = env()
        for params in ("x", 5, [], {1: 2}, {"a": object()}):
            with self.assertRaises(GovernanceViolation) as cm:
                gate.execute("a", "http.post", params)
            self.assertEqual(cm.exception.code, "DG-G-004")
        self.assertEqual(gate.audit_log()[-1]["outcome"], "denied")

    def test_audit_is_bounded_and_never_has_plaintext_under_fuzz(self):
        reg, vault, gate = env(audit_size=50)
        gate.register_handler("a", "http.post", lambda p: {"echo": json.dumps(p)})
        secrets_ = [vault.store("a", f"fuzz-secret-{i:03d}-abcdef") for i in range(5)]
        raws = [f"fuzz-secret-{i:03d}-abcdef" for i in range(5)]
        r = random.Random(5)
        for _ in range(300):
            val = r.choice(raws + secrets_ + ["plain", DBURL])
            fmt = r.choice(["{v}", "Bearer {v}", "k={v}&x=1", "[{v}]"])
            params = {r.choice(["a", "b", "password", "headers"]): fmt.format(v=val)}
            try:
                out = gate.execute("a", "http.post", params)
                self.assertFalse(any(x in json.dumps(out) for x in raws))
            except (CustosError, GovernanceViolation):
                pass
        blob = json.dumps(gate.audit_log())
        self.assertFalse(any(x in blob for x in raws))
        self.assertEqual(len(gate.audit_log()), 50)


if __name__ == "__main__":
    unittest.main()
