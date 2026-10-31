"""Boundary and fail-closed tests found by mutation testing."""
import copy
import json
import os
import tempfile
import unittest

from detgov import DetGovRouter, Firewall, GovernanceViolation
from detgov.core import crypto as C
from detgov.core import router as R
from tests.fixtures import POLICY, write_policy


def luhn_number(prefix: str, length: int) -> str:
    body = prefix + "0" * (length - len(prefix) - 1)
    for check in "0123456789":
        if R.luhn_ok(body + check):
            return body + check


def router(**over):
    pol = copy.deepcopy(POLICY)
    pol.update(over)
    return DetGovRouter(write_policy(policy=pol, sign=False))


class CryptoBoundaries(unittest.TestCase):
    def test_point_equality_needs_both_coordinates(self):
        p = (3, 5, 1, 15)
        self.assertTrue(C._eq(p, p))
        self.assertFalse(C._eq(p, (3, 6, 1, 18)))      # same x, different y
        self.assertFalse(C._eq(p, (4, 5, 1, 20)))      # same y, different x
        self.assertTrue(C._eq(p, (6, 10, 2, 30)))      # projective scaling

    def test_noncanonical_y_is_rejected(self):
        self.assertIsNone(C._decode_point(C._P.to_bytes(32, "little")))                 # y == p encodes y == 0 non-canonically
        self.assertIsNone(C._decode_point((C._P + 5).to_bytes(32, "little")))

    def test_read_limited_exact_limit(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "f")
        open(p, "wb").write(b"x" * 10)
        self.assertEqual(C.read_limited(p, 10), b"x" * 10)
        open(p, "wb").write(b"x" * 11)
        with self.assertRaises(ValueError):
            C.read_limited(p, 10)

    def test_canonical_rejects_any_non_string_key(self):
        with self.assertRaises(ValueError):
            C.canonical_json_bytes({"a": 1, 2: 3})
        with self.assertRaises(ValueError):
            C.canonical_json_bytes({"a": {"b": 1, 2: 3}})


class RouterBoundaries(unittest.TestCase):
    def test_os_token_alone_is_not_spawn(self):
        r = router(allowlist=["os.info", "exec.info"])
        self.assertEqual(r.evaluate_request("os.info", {})[0], True)
        self.assertEqual(r.evaluate_request("exec.info", {})[1], "DG-R-001")
        self.assertEqual(r.evaluate_request("os.exec", {})[1], "DG-G-002")

    def test_endpoint_guards_catch_each_smuggling_trick(self):
        r = router()
        pan = "4111111111111111"
        for ep in ("https://tele\nmetry.corp.example/x", "https://tele\tmetry.corp.example/x", "https://tele\rmetry.corp.example/x", "https://telemetry.corp.example/\x01",
                   "https://telemetry.corp.example\x7f", "https://user@telemetry.corp.example/", "https://:pw@telemetry.corp.example/", "https://telemetry.corp.example\\x"):
            self.assertEqual(r.evaluate_request("telemetry.send", {"x": pan, "endpoint": ep})[1], "DG-B-003", repr(ep))
        self.assertEqual(r.evaluate_request("telemetry.send", {"x": pan, "endpoint": ""})[1], "DG-B-003")
        self.assertEqual(r.evaluate_request("telemetry.send", {"x": pan, "endpoint": 5})[1], "DG-B-003")        # non-string destination counts as none

    def test_pan_length_boundaries(self):
        r = router()
        for n in (13, 14, 15, 16, 17, 18, 19):
            pan = luhn_number("4", n)
            self.assertEqual(len(pan), n)
            self.assertEqual(r.evaluate_request("telemetry.send", {"endpoint": "https://e.x", "x": pan})[1], "DG-B-003", n)
            self.assertEqual(r.evaluate_request("telemetry.send", {"endpoint": "https://e.x", "x": int(pan)})[1], "DG-B-003", n)
        for n in (12, 20):
            pan = luhn_number("4", n)
            self.assertEqual(r.evaluate_request("telemetry.send", {"endpoint": "https://e.x", "x": pan})[0], True, n)
            self.assertEqual(r.evaluate_request("telemetry.send", {"endpoint": "https://e.x", "x": int(pan)})[0], True, n)

    def test_string_size_boundary(self):
        r = router()
        self.assertEqual(r.evaluate_request("files.read", {"x": "a" * R.MAX_STRING})[0], True)
        self.assertEqual(r.evaluate_request("files.read", {"x": "a" * (R.MAX_STRING + 1)})[1], "DG-G-004")

    def test_list_depth_boundary(self):
        r = router()

        def nest(levels):
            v = 1
            for _ in range(levels):
                v = [v]
            return {"x": v}
        self.assertEqual(r.evaluate_request("files.read", nest(R.MAX_DEPTH - 2))[0], True)
        self.assertEqual(r.evaluate_request("files.read", nest(R.MAX_DEPTH))[1], "DG-G-004")

    def test_policy_limits(self):
        def loads(**kw):
            d = tempfile.mkdtemp()
            p = os.path.join(d, "p.json")
            json.dump({"policy_version": 1, **kw}, open(p, "w"))
            return DetGovRouter(p)
        loads(allowlist=[f"t{i}" for i in range(10000)])
        with self.assertRaises(GovernanceViolation):
            loads(allowlist=[f"t{i}" for i in range(10001)])
        loads(revoked_entities=["x" * 512])
        with self.assertRaises(GovernanceViolation):
            loads(revoked_entities=["x" * 513])
        loads(approved_endpoints=["h" * 512])
        with self.assertRaises(GovernanceViolation):
            loads(approved_endpoints=["h" * 513])
        for ok in (1, 86400):
            self.assertEqual(loads(max_background_seconds=ok)._policy.max_background_seconds, ok)
        for bad in (0, 86401, -1):
            with self.assertRaises(GovernanceViolation):
                loads(max_background_seconds=bad)

    def test_unexpected_internal_error_fails_closed(self):
        r = router()

        def boom(*a, **k):
            raise RuntimeError("secret internal detail")
        r._evaluate = boom
        allowed, code, why = r.evaluate_request("files.read", {})
        self.assertEqual((allowed, code), (False, "DG-G-004"))
        self.assertNotIn("secret", why)


class FirewallBoundaries(unittest.TestCase):
    def test_audit_keeps_name_up_to_128_chars(self):
        f = Firewall(write_policy(sign=False))
        name = "a" * 128
        with self.assertRaises(GovernanceViolation):
            f.execute(name, {})
        self.assertEqual(f.audit_log()[-1][0], name)
        with self.assertRaises(GovernanceViolation):
            f.execute("a" * 129, {})
        self.assertEqual(f.audit_log()[-1][0], "<invalid>")


if __name__ == "__main__":
    unittest.main()
