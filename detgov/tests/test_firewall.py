import copy
import threading
import unittest

from detgov import DetGovRouter, Firewall, GovernanceViolation
from tests.fixtures import PK_HEX, POLICY, write_policy


def fw():
    return Firewall(write_policy(), public_key_hex=PK_HEX, enforce_sig=True)


class Execute(unittest.TestCase):
    def test_dispatch_and_audit(self):
        f = fw()
        seen = []
        f.register_handler("files.read", lambda p: (seen.append(p), {"ok": True, "echo": p})[1])
        out = f.execute("files.read", {"path": "/a", "n": [1, 2]})
        self.assertEqual(out, {"ok": True, "echo": {"path": "/a", "n": [1, 2]}})
        self.assertEqual(f.audit_log(), [("files.read", True, "")])

    def test_denied_requests_never_reach_handler(self):
        f = fw()
        calls = []
        f.register_handler("directory.lookup", lambda p: calls.append(p) or {})
        for params, code in (({"a": "ACC-REVOKED-9821"}, "DG-C-002"), ({"sudo": True}, "DG-G-001"), ({"x": object()}, "DG-G-004")):
            with self.assertRaises(GovernanceViolation) as cm:
                f.execute("directory.lookup", params)
            self.assertEqual(cm.exception.code, code)
        for name, code in (("os.fork", "DG-G-002"), ("eval", "DG-R-001"), ("unlisted", "DG-G-003")):
            with self.assertRaises(GovernanceViolation) as cm:
                f.execute(name, {})
            self.assertEqual(cm.exception.code, code)
        self.assertEqual(calls, [])
        self.assertTrue(all(not a for _, a, _ in f.audit_log()))

    def test_missing_handler_and_registration_rules(self):
        f = fw()
        with self.assertRaises(GovernanceViolation) as cm:
            f.execute("files.read", {})
        self.assertEqual(cm.exception.code, "DG-G-005")
        for bad in ("os.fork", "eval", "not.allowlisted", "cron.add", ""):
            with self.assertRaises(GovernanceViolation):
                f.register_handler(bad, lambda p: {})
        with self.assertRaises(TypeError):
            f.register_handler("files.read", "not callable")
        f.register_handler("files.read", lambda p: {})
        with self.assertRaises(ValueError):
            f.register_handler("files.read", lambda p: {})

    def test_handler_must_return_dict(self):
        f = fw()
        f.register_handler("files.read", lambda p: "text")
        with self.assertRaises(GovernanceViolation) as cm:
            f.execute("files.read", {})
        self.assertEqual(cm.exception.code, "DG-G-006")

    def test_handler_gets_isolated_snapshot_so_check_equals_use(self):
        f = fw()
        got = {}

        def h(p):
            got["p"] = p
            p["mutated"] = True
            return {}
        f.register_handler("files.read", h)
        original = {"path": "/a", "nested": {"k": [1]}}
        f.execute("files.read", original)
        self.assertEqual(original, {"path": "/a", "nested": {"k": [1]}})
        self.assertIsNot(got["p"]["nested"], original["nested"])

    def test_toctou_params_mutated_by_another_thread_cannot_smuggle(self):
        class Racy(dict):
            pass
        f = fw()
        f.register_handler("files.read", lambda p: {"seen": p})
        params = {"path": "/a"}
        out = f.execute("files.read", params)
        params["sudo"] = True                      # mutation after the call must not affect the returned/used snapshot
        self.assertEqual(out["seen"], {"path": "/a"})

    def test_audit_log_has_no_values_and_is_bounded(self):
        f = Firewall(write_policy(), audit_size=5)
        for i in range(20):
            try:
                f.execute("files.read", {"k": "4111111111111111"})
            except GovernanceViolation:
                pass
        log = f.audit_log()
        self.assertEqual(len(log), 5)
        self.assertNotIn("4111", repr(log))
        long_name = "a" * 500
        with self.assertRaises(GovernanceViolation):
            f.execute(long_name, {})
        self.assertEqual(f.audit_log()[-1][0], "<invalid>")

    def test_constructor_variants(self):
        r = DetGovRouter(write_policy(sign=False))
        self.assertIs(Firewall(r).router, r)
        with self.assertRaises(GovernanceViolation) as cm:
            Firewall(write_policy(sign=False), public_key_hex=PK_HEX, enforce_sig=True)
        self.assertEqual(cm.exception.code, "DG-P-002")

    def test_thread_safe_registration_and_execution(self):
        f = fw()
        f.register_handler("files.read", lambda p: {"n": p["n"]})
        errs = []

        def work(i):
            try:
                for j in range(50):
                    assert f.execute("files.read", {"n": i * 100 + j}) == {"n": i * 100 + j}
            except Exception as e:
                errs.append(e)
        ts = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])


class Claude(unittest.TestCase):
    def test_strips_server_side_and_unlisted(self):
        f = fw()
        tools = [
            {"name": "files.read", "description": "read", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"type": "web_search_20250305", "name": "web_search", "max_uses": 3},
            {"type": "code_execution_20250522", "name": "code_execution"},
            {"type": "bash_20250124", "name": "bash"},
            {"type": "computer_20250124", "name": "computer"},
            {"type": "custom", "name": "report.render", "description": "r", "input_schema": {"type": "object"}, "evil": "dropped"},
            {"name": "unlisted.tool", "description": "x", "input_schema": {}},
            {"name": "os.fork", "description": "x", "input_schema": {}},
            {"name": "eval", "description": "x", "input_schema": {}},
            {"name": "files.read", "description": "duplicate shadow", "input_schema": {}},
            {"name": "directory.lookup", "description": 5, "input_schema": {}},
            {"name": "directory.lookup", "description": "ok", "input_schema": "notadict"},
            {"name": None}, "string", 5, None, {"type": "mcp", "name": "files.read"},
        ]
        before = copy.deepcopy(tools)
        out = f.sanitize_claude_tools(tools)
        self.assertEqual(tools, before)
        self.assertEqual([t["name"] for t in out], ["files.read", "report.render"])
        self.assertEqual(out[0]["description"], "read")
        self.assertEqual(set(out[1]), {"name", "description", "input_schema"})
        self.assertIsNot(out[0]["input_schema"], tools[0]["input_schema"])

    def test_misc(self):
        f = fw()
        self.assertEqual(f.sanitize_claude_tools([]), [])
        with self.assertRaises(TypeError):
            f.sanitize_claude_tools("x")
        with self.assertRaises(TypeError):
            f.sanitize_claude_tools(None)
        out = f.sanitize_claude_tools([{"name": "files.read", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral"}}])
        self.assertEqual(out[0]["cache_control"], {"type": "ephemeral"})
        cyc = {}
        cyc["a"] = cyc
        self.assertEqual(f.sanitize_claude_tools([{"name": "files.read", "input_schema": cyc}]), [])
        self.assertEqual(f.sanitize_claude_tools([{"name": "files.read", "input_schema": {"x": object()}}]), [])


class Gemini(unittest.TestCase):
    def test_plain_declarations_and_wrappers(self):
        f = fw()
        decls = [
            {"name": "files.read", "description": "r", "parameters": {"type": "object"}, "extra": 1},
            {"name": "os.fork", "description": "x"},
            {"name": "files.read", "description": "dup"},
            {"google_search": {}}, {"code_execution": {}}, {"google_search_retrieval": {"dynamic_retrieval_config": {}}}, {"url_context": {}},
            {"function_declarations": [{"name": "report.render", "parameters": {}}, {"name": "eval"}, {"name": "unlisted"}]},
            {"functionDeclarations": [{"name": "eval"}]},
            {"function_declarations": "notalist"}, {"function_declarations": []}, "x", 5, None, {"name": 5},
        ]
        before = copy.deepcopy(decls)
        out = f.sanitize_gemini_tools(decls)
        self.assertEqual(decls, before)
        self.assertEqual(out, [{"name": "files.read", "description": "r", "parameters": {"type": "object"}}, {"function_declarations": [{"name": "report.render", "parameters": {}}]}])

    def test_type_checks(self):
        with self.assertRaises(TypeError):
            fw().sanitize_gemini_tools({"name": "files.read"})


class Integration(unittest.TestCase):
    def test_sanitized_tools_can_all_be_executed_when_registered(self):
        f = fw()
        for n in ("files.read", "report.render"):
            f.register_handler(n, lambda p: {"ok": 1})
        tools = f.sanitize_claude_tools([{"name": n, "input_schema": {"type": "object"}} for n in POLICY["allowlist"] + ["os.fork", "eval", "x.y"]])
        self.assertEqual({t["name"] for t in tools}, set(POLICY["allowlist"]))
        for t in tools:
            if t["name"] in ("files.read", "report.render"):
                self.assertEqual(f.execute(t["name"], {}), {"ok": 1})

    def test_underscore_names_are_not_overblocked(self):
        pol = copy.deepcopy(POLICY)
        pol["allowlist"] += ["billing.system_status", "invoice.compile_report_ref", "files.read_all", "ticket.update_status"]
        r = DetGovRouter(write_policy(policy=pol, sign=False))
        for t in ("billing.system_status", "files.read_all"):
            self.assertEqual(r.evaluate_request(t, {})[0], True, t)
        self.assertEqual(r.evaluate_request("invoice.compile_report_ref", {})[0], True)
        self.assertEqual(r.evaluate_request("ticket.update_status", {})[0], True)


if __name__ == "__main__":
    unittest.main()
