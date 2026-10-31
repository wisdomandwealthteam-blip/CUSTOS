import copy
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

from detgov import DetGovRouter, GovernanceViolation
from detgov.core import router as R
from tests.fixtures import GOOD_HASH, ISRC, PK_HEX, POLICY, SK, write_policy
from tests import ed25519_ref

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def mk(**over):
    pol = copy.deepcopy(POLICY)
    pol.update(over)
    return DetGovRouter(write_policy(policy=pol, sign=False))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = mk()

    def code(self, tool, params=None):
        allowed, code, _ = self.r.evaluate_request(tool, params)
        return None if allowed else code

    def assertCode(self, want, tool, params=None):
        self.assertEqual(self.code(tool, params), want, (tool, params))


class Boundary(Base):
    def test_vendor_tools(self):
        for t in ("llm.vendor.openai.search", "google_search", "google_search_retrieval", "hosted_bash", "hosted_python", "web_search_20250305", "code_execution_20250522",
                  "computer_use", "vendor.x", "GOOGLE_SEARCH", "Hosted_Bash"):
            self.assertCode("DG-B-001", t)

    def test_ipc_and_unix_sockets(self):
        for t in ("ipc.send", "uds.connect", "unix_socket.write", "dbus.call", "named_pipe.open"):
            self.assertCode("DG-B-002", t)
        for v in ("unix:///var/run/docker.sock", "/var/run/docker.sock", "/run/user/1000/bus", "/tmp/agent.sock", "\\\\.\\pipe\\mypipe", "npipe:////./pipe/x", "\x00abstract", " unix:/x"):
            self.assertCode("DG-B-002", "files.read", {"path": v})
            self.assertCode("DG-B-002", "files.read", {"a": {"b": [v]}})
        for k in ("unix_socket", "socket_path", "UDS", "docker_socket"):
            self.assertCode("DG-B-002", "files.read", {k: "x"})
        self.assertCode(None, "files.read", {"path": "/home/user/notes.txt"})

    def test_pan_detection(self):
        ep = "https://telemetry.corp.example/in"
        bad = "https://evil.example/x"
        pans = ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111", "5500005555555559", "378282246310005", "6011111111111117", "4222222222222"]
        for pan in pans:
            self.assertCode("DG-B-003", "telemetry.send", {"endpoint": bad, "x": pan})
            self.assertCode("DG-B-003", "telemetry.send", {"x": pan})                                  # no destination at all
            self.assertCode("DG-B-003", "telemetry.send", {"endpoint": bad, "n": {"l": [f"card={pan};ok"]}})
            self.assertCode(None, "telemetry.send", {"endpoint": ep, "x": pan})                        # approved destination
        self.assertCode("DG-B-003", "telemetry.send", {"endpoint": bad, "x": 4111111111111111})       # numeric PAN
        self.assertCode("DG-B-003", "telemetry.send", {"endpoint": bad, "x": "４１１１ １１１１ １１１１ １１１１"})      # full-width digits
        self.assertCode("DG-B-003", "telemetry.send", {"endpoint": ep, "x": "4111111111111111", "url": bad})   # one unapproved destination among several
        for ok in ("4111111111111112", "4111********1111", "1234567890123", "41111111111111111111", "0000", "order 12345"):   # not Luhn / masked / wrong length
            self.assertCode(None, "telemetry.send", {"endpoint": bad, "x": ok})

    def test_endpoint_matching_cannot_be_spoofed(self):
        pan = {"x": "4111111111111111"}
        good = ["https://telemetry.corp.example", "https://telemetry.corp.example/", "https://TELEMETRY.corp.example:443/a?b=1", "telemetry.corp.example/in", "https://telemetry.corp.example./x"]
        for g in good:
            self.assertCode(None, "telemetry.send", {**pan, "endpoint": g})
        evil = ["https://telemetry.corp.example@evil.example/", "https://telemetry.corp.example.evil.example/", "https://evil.example/telemetry.corp.example",
                "http://telemetry.corp.example/", "https://telemetry.corp.example:8443/", "https://telemetry.corp.example\\@evil.example/", "https://telemetry.corp.example evil",
                "https://evil.example#@telemetry.corp.example", "", "https://", "https://telemetry.corp.example:badport/", "https://user:pw@telemetry.corp.example/"]
        for e in evil:
            self.assertCode("DG-B-003", "telemetry.send", {**pan, "endpoint": e})

    def test_explicit_http_entry_and_port(self):
        r = mk(approved_endpoints=["http://plain.corp.example:8080"])
        self.assertEqual(r.evaluate_request("telemetry.send", {"x": "4111111111111111", "endpoint": "http://plain.corp.example:8080/a"})[0], True)
        self.assertEqual(r.evaluate_request("telemetry.send", {"x": "4111111111111111", "endpoint": "https://plain.corp.example:8080/a"})[1], "DG-B-003")
        self.assertEqual(r.evaluate_request("telemetry.send", {"x": "4111111111111111", "endpoint": "http://plain.corp.example/a"})[1], "DG-B-003")


class Causal(Base):
    def test_schema_override(self):
        for t in ("schema.override", "tool.register", "register_tool", "update_tool_description", "set_tool_description", "tools.patch", "override_schema", "tool.redefine",
                  "function.hotpatch", "description.set", "tool-description-update"):
            self.assertCode("DG-C-001", t)
        for k in ("tool_schema", "schema_override", "Tool_Description", "__schema__", "tool_definitions", "system_prompt_override"):
            self.assertCode("DG-C-001", "files.read", {k: "x"})
            self.assertCode("DG-C-001", "files.read", {"n": [{k: 1}]})
        self.assertCode(None, "files.read", {"description": "a normal field", "schema": "public"})

    def test_revoked_entities_matching(self):
        for v in ("ACC-REVOKED-9821", "acc-revoked-9821", "CN=ACC-REVOKED-9821,OU=Users", "user:ACC-REVOKED-9821/x", "ＡＣＣ-ＲＥＶＯＫＥＤ-９８２１", "ACC-REVOKED-98​21"):
            self.assertCode("DG-C-002", "directory.lookup", {"a": {"b": [v]}})
        for v in ("ACC-REVOKED-98210", "XACC-REVOKED-9821", "ACC-REVOKED-982", "ACC-ACTIVE-9821"):
            self.assertCode(None, "directory.lookup", {"a": v})

    def test_isrc(self):
        for v in ("", "X", "USRC1760783", "USRC176078390", "us rc17607839", 12, None, ["USRC17607839"], "USRC17607839\n"):
            self.assertCode("DG-C-003", "media.register", {"m": {"isrc": v}})
        for v in ("USRC17607839", "us-rc1-76-07839", "GBAYE0601498"):
            if v.replace("-", "").upper() == ISRC:
                self.assertCode("DG-C-004", "media.register", {"m": {"isrc": v}})                  # registered, no hash => cannot prove identity
                self.assertCode(None, "media.register", {"m": {"isrc": v, "SHA256": GOOD_HASH.upper()}})
            else:
                self.assertCode(None, "media.register", {"m": {"isrc": v}})
        self.assertCode("DG-C-004", "media.register", {"m": {"ISRC": ISRC, "content_hash": "1" * 64}})
        self.assertCode("DG-C-004", "media.register", {"a": {"isrc": "GBAYE0601498", "content_hash": "1" * 64}, "b": {"isrc": "GBAYE0601498", "content_hash": "2" * 64}})
        self.assertCode(None, "media.register", {"a": {"isrc": "GBAYE0601498", "content_hash": "1" * 64}, "b": {"isrc": "GBAYE0601498", "content_hash": "1" * 64}})


class Routing(Base):
    def test_dynamic_code(self):
        for t in ("eval", "compile", "exec", "python.exec", "js.eval", "code_interpreter", "run_python", "execute_code", "eval_expression", "compile_regex", "EVAL", "repl.run", "lua.interpreter"):
            self.assertCode("DG-R-001", t)
        for k in ("eval", "compile", "dynamic_code", "exec_code"):
            self.assertCode("DG-R-001", "files.read", {k: "1+1"})
        self.assertCode(None, "files.read", {"eval": False})
        self.assertCode("DG-G-002", "os.exec")                                  # process replacement is spawn, not dynamic code


class Temporal(Base):
    def test_always_blocked(self):
        for t in ("cron.add", "crontab", "daemonize", "nohup.run", "systemd.start", "schedule.job", "schedule_task", "scheduler.add", "launchd.load", "autostart.enable", "setsid"):
            self.assertCode("DG-T-001", t)
        for k in ("cron", "daemonize", "schedule", "every", "loop_forever", "run_forever", "Daemon"):
            self.assertCode("DG-T-001", "files.read", {k: "5m"})
        self.assertCode(None, "files.read", {"daemonize": False, "cron": ""})

    def test_background_requires_meter(self):
        for p in ({"background": True}, {"detach": 1}, {"persist": "yes"}, {"background": True, "max_runtime_seconds": 0}, {"background": True, "max_runtime_seconds": 301},
                  {"background": True, "max_runtime_seconds": -5}, {"background": True, "max_runtime_seconds": True}, {"background": True, "max_runtime_seconds": "60"},
                  {"background": True, "max_runtime_seconds": None}, {"background": True, "a": {"max_runtime_seconds": 10}, "b": {"max_runtime_seconds": 20}}):
            self.assertCode("DG-T-002", "worker.run", p)
        self.assertCode("DG-T-002", "background.run")
        for p in ({"background": True, "max_runtime_seconds": 300}, {"background": True, "max_runtime_seconds": 1}, {"detach": True, "max_runtime_seconds": 12.5}, {"background": False}):
            self.assertCode(None, "worker.run", p)
        r = mk(max_background_seconds=10)
        self.assertEqual(r.evaluate_request("worker.run", {"background": True, "max_runtime_seconds": 10})[0], True)
        self.assertEqual(r.evaluate_request("worker.run", {"background": True, "max_runtime_seconds": 11})[1], "DG-T-002")


class Governance(Base):
    def test_privilege_escalation(self):
        for t in ("sudo", "sudo.run", "su", "setuid", "chown", "chroot", "pkexec", "escalate.privileges", "elevate_access", "privilege_escalation", "grant_admin", "become_root", "run_as_root", "ptrace"):
            self.assertCode("DG-G-001", t)
        for p in ({"privileged": True}, {"sudo": 1}, {"run_as": "root"}, {"user": "ROOT"}, {"uid": 0}, {"euid": "0"}, {"as_user": "Administrator"}, {"user": "NT AUTHORITY\\SYSTEM"},
                  {"cap_add": ["SYS_ADMIN"]}, {"capabilities": ["x"]}, {"n": {"run_as": "root"}}):
            self.assertCode("DG-G-001", "files.read", p)
        for p in ({"user": "alice"}, {"uid": 1000}, {"privileged": False}, {"cap_add": []}):
            self.assertCode(None, "files.read", p)

    def test_spawn(self):
        for t in ("os.fork", "fork", "forkpty", "subprocess.run", "subprocess", "process.spawn", "spawn", "popen", "os.system", "os_system", "shell.run", "bash", "sh", "powershell", "cmd.exe",
                  "os.execve", "os.execvp", "child_process.exec", "multiprocessing.Process", "posix_spawn", "run_shell", "run_command", "execute_command", "run_process", "fork_process"):
            self.assertCode("DG-G-002", t)
        for k in ("shell", "spawn", "fork"):
            self.assertCode("DG-G-002", "files.read", {k: True})

    def test_allowlist(self):
        for t in ("not.listed", "files.write", "FILES.READ", "files.read.", "files.read/x"):
            self.assertCode("DG-G-003", t)
        for t in ("files.read", "directory.lookup", "report.render"):
            self.assertCode(None, t, {})

    def test_malformed(self):
        for t in (None, 5, "", " files.read", "files.read\n", "files.read ", "ｅｖａｌ", "files​.read", "a" * 129, ["x"], b"files.read", "files.read\x00"):
            self.assertCode("DG-G-004", t)
        for p in ("x", 5, [], [("a", 1)], {1: 2}, {"a": object()}, {"a": (1,)}, {"a": {1, 2}}, {"a": b"x"}, {"a": float("nan")}, {"a": float("inf")}, {"a": "x" * (R.MAX_STRING + 1)}):
            self.assertCode("DG-G-004", "files.read", p)

    def test_limits_and_cycles(self):
        deep = cur = {}
        for _ in range(R.MAX_DEPTH - 1):
            cur["a"] = {}
            cur = cur["a"]
        self.assertCode(None, "files.read", deep)
        cur["a"] = {}
        self.assertCode("DG-G-004", "files.read", deep)
        cyc = {}
        cyc["self"] = cyc
        self.assertCode("DG-G-004", "files.read", cyc)
        lst = []
        lst.append(lst)
        self.assertCode("DG-G-004", "files.read", {"x": lst})
        self.assertCode(None, "files.read", {"x": list(range(R.MAX_NODES - 1))})
        self.assertCode("DG-G-004", "files.read", {"x": list(range(R.MAX_NODES))})
        self.assertCode("DG-G-004", "files.read", {"x": "y" * 5, **{str(i): 0 for i in range(R.MAX_NODES)}})

    def test_subclasses_rejected(self):
        class D(dict):
            def items(self):
                return [("evil", 1)]
        self.assertCode("DG-G-004", "files.read", D(a=1))
        class S(str):
            pass
        self.assertCode("DG-G-004", "files.read", {"a": S("x")})
        self.assertCode("DG-G-004", S("files.read"))

    def test_none_params_means_empty(self):
        self.assertCode(None, "files.read", None)


class Ordering(Base):
    def test_fixed_precedence_B_C_R_T_G(self):
        both = {"endpoint": "https://evil.example", "pan": "4111111111111111", "acct": "ACC-REVOKED-9821", "sudo": True, "cron": "x", "eval": "1"}
        self.assertCode("DG-B-003", "not.listed", both)
        del both["pan"]
        self.assertCode("DG-C-002", "not.listed", both)
        del both["acct"]
        self.assertCode("DG-R-001", "not.listed", both)
        del both["eval"]
        self.assertCode("DG-T-001", "not.listed", both)
        del both["cron"]
        self.assertCode("DG-G-001", "not.listed", both)
        self.assertCode("DG-B-001", "google_search", {"sudo": True})

    def test_hard_rules_ignore_allowlist(self):
        r = mk(allowlist=["os.fork", "eval", "google_search", "cron.add", "sudo", "ipc.send"])
        for t, c in (("os.fork", "DG-G-002"), ("eval", "DG-R-001"), ("google_search", "DG-B-001"), ("cron.add", "DG-T-001"), ("sudo", "DG-G-001"), ("ipc.send", "DG-B-002")):
            self.assertEqual(r.evaluate_request(t, {})[1], c)


class RationaleHygiene(Base):
    def test_rationale_never_echoes_values(self):
        secrets = ["4111111111111111", "ACC-REVOKED-9821", "hunter2-secret", "USRC17607839"]
        for tool, p in (("telemetry.send", {"endpoint": "https://e.x", "k": secrets[0]}), ("directory.lookup", {"k": secrets[1]}), ("files.read", {"sudo": True, "pw": secrets[2]}),
                        ("media.register", {"m": {"isrc": "bad-" + secrets[2]}})):
            a, c, why = self.r.evaluate_request(tool, p)
            self.assertFalse(a)
            for s in secrets:
                self.assertNotIn(s, why)
            self.assertIn(c, R.CODES)


class Determinism(Base):
    VECTORS = [("directory.lookup", {"account": "ACC-REVOKED-9821"}), ("telemetry.send", {"endpoint": "https://e.x", "x": "4111111111111111"}), ("os.fork", {}), ("eval", {}),
               ("media.register", {"m": {"isrc": "bad"}}), ("files.read", {"a": 1}), ("cron.add", {}), ("sudo", {}), ("nope", {}), ("worker.run", {"background": True})]

    def test_same_verdicts_across_hash_seeds_and_runs(self):
        policy = write_policy()
        script = ("import json,sys\nfrom detgov import DetGovRouter\nr=DetGovRouter(sys.argv[1])\nv=json.loads(sys.argv[2])\n"
                  "print(json.dumps([r.evaluate_request(t,p) for t,p in v]+[r.policy_digest]))")
        outs = set()
        for seed in ("0", "1", "4242", "random"):
            env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=ROOT)
            o = subprocess.run([sys.executable, "-c", script, policy, json.dumps(self.VECTORS)], capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(o.returncode, 0, o.stderr)
            outs.add(o.stdout)
        self.assertEqual(len(outs), 1)
        local = [list(self.r.evaluate_request(t, p)) for t, p in self.VECTORS]
        self.assertEqual(json.loads(outs.pop())[:-1], local)

    def test_params_not_mutated_and_key_order_irrelevant(self):
        p = {"b": {"z": [1, {"y": 2}]}, "a": "ACC-REVOKED-9821"}
        before = copy.deepcopy(p)
        a = self.r.evaluate_request("directory.lookup", p)
        self.assertEqual(p, before)
        self.assertEqual(a, self.r.evaluate_request("directory.lookup", dict(reversed(list(p.items())))))

    def test_policy_digest_is_formatting_independent(self):
        a = DetGovRouter(write_policy(sign=False)).policy_digest
        d = tempfile.mkdtemp()
        path = os.path.join(d, "policy.json")
        json.dump(POLICY, open(path, "w"), separators=(",", ":"), sort_keys=True)
        self.assertEqual(a, DetGovRouter(path).policy_digest)


class Fuzz(Base):
    def test_arbitrary_input_never_raises_and_unlisted_names_never_allowed(self):
        r = random.Random(77)
        names = ["files.read", "x", "eval", "os.fork", "", None, 5, "a" * 200, "files.read\n", "ＥＶＡＬ", "cron", "unknown.tool", "report.render"]
        leaf = [None, True, 0, 1, -1, 2 ** 70, 1.5, "", "x", "ACC-REVOKED-9821", "4111111111111111", "/run/x.sock", "root", {"a": 1}, [1, [2]], "\ud800", b"x", object(), float("nan")]

        def gen(d=0):
            c = r.random()
            if d > 3 or c < 0.5:
                return r.choice(leaf)
            if c < 0.75:
                return [gen(d + 1) for _ in range(r.randint(0, 3))]
            return {r.choice(["a", "user", "sudo", "endpoint", "isrc", "background", 7, "cron", "tool_schema"]): gen(d + 1) for _ in range(r.randint(0, 3))}
        for _ in range(4000):
            name, params = r.choice(names), gen()
            allowed, code, why = self.r.evaluate_request(name, params)
            self.assertIsInstance(allowed, bool)
            if allowed:
                self.assertIn(name, POLICY["allowlist"])
                self.assertEqual((code, why), ("", "allowed"))
            else:
                self.assertIn(code, R.CODES)

    def test_benign_allowlisted_requests_are_not_blocked(self):
        r = random.Random(78)
        words = ["alpha", "beta", "report", "q3", "hello world", "user@example.com", "2026-10-16", "x" * 50]
        for _ in range(2000):
            params = {r.choice(["title", "body", "path", "count", "tags", "meta"]): r.choice(words + [r.randint(0, 999), [r.choice(words)], {"k": r.choice(words)}]) for _ in range(r.randint(0, 4))}
            self.assertEqual(self.r.evaluate_request(r.choice(["files.read", "report.render", "directory.lookup"]), params), (True, "", "allowed"), params)


class Loading(unittest.TestCase):
    def test_signature_enforcement(self):
        p = write_policy()
        r = DetGovRouter(p, PK_HEX, enforce_sig=True)
        self.assertTrue(r.signature_verified)
        self.assertTrue(DetGovRouter(p, PK_HEX).signature_verified)
        self.assertFalse(DetGovRouter(p).signature_verified)
        other = ed25519_ref.public_key(b"\x01" * 32).hex()
        with self.assertRaises(GovernanceViolation) as cm:
            DetGovRouter(p, other, enforce_sig=True)
        self.assertEqual(cm.exception.code, "DG-P-002")
        self.assertFalse(DetGovRouter(p, other).signature_verified)           # not enforced: loads, flagged unverified
        with self.assertRaises(GovernanceViolation) as cm:
            DetGovRouter(p, enforce_sig=True)
        self.assertEqual(cm.exception.code, "DG-P-003")
        q = write_policy(sign=False)
        with self.assertRaises(GovernanceViolation) as cm:
            DetGovRouter(q, PK_HEX, enforce_sig=True)                          # missing .sig
        self.assertEqual(cm.exception.code, "DG-P-002")

    def test_tampered_policy_rejected_when_enforced(self):
        p = write_policy()
        text = open(p).read().replace('"allowlist": [', '"allowlist": [\n    "os.fork",')
        open(p, "w").write(text)
        with self.assertRaises(GovernanceViolation) as cm:
            DetGovRouter(p, PK_HEX, enforce_sig=True)
        self.assertEqual(cm.exception.code, "DG-P-002")

    def test_invalid_policies(self):
        bad = [None, [], {}, {"policy_version": 2}, {"policy_version": 1, "extra": 1}, {"policy_version": 1, "allowlist": "x"}, {"policy_version": 1, "allowlist": [5]},
               {"policy_version": 1, "allowlist": ["bad name"]}, {"policy_version": 1, "allowlist": ["x\n"]}, {"policy_version": 1, "allowlist": [""]},
               {"policy_version": 1, "revoked_entities": [None]}, {"policy_version": 1, "approved_endpoints": {"a": 1}},
               {"policy_version": 1, "isrc_registry": {"bad": "0" * 64}}, {"policy_version": 1, "isrc_registry": {ISRC: "short"}}, {"policy_version": 1, "isrc_registry": []},
               {"policy_version": 1, "max_background_seconds": 0}, {"policy_version": 1, "max_background_seconds": 86401}, {"policy_version": 1, "max_background_seconds": True},
               {"policy_version": 1, "max_background_seconds": "5"}, {"policy_version": True}]
        for pol in bad:
            d = tempfile.mkdtemp()
            path = os.path.join(d, "policy.json")
            json.dump(pol, open(path, "w"))
            with self.assertRaises(GovernanceViolation, msg=str(pol)) as cm:
                DetGovRouter(path)
            self.assertEqual(cm.exception.code, "DG-P-001")
        for content in ('{"policy_version":1,"policy_version":1}', "{", "", '{"policy_version":1,"max_background_seconds":1.5}', '{"policy_version":NaN}'):
            d = tempfile.mkdtemp()
            path = os.path.join(d, "policy.json")
            open(path, "w").write(content)
            with self.assertRaises(GovernanceViolation) as cm:
                DetGovRouter(path)
            self.assertEqual(cm.exception.code, "DG-P-001", content)
        with self.assertRaises(GovernanceViolation):
            DetGovRouter("/nonexistent/policy.json")

    def test_minimal_policy_denies_everything_by_default(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "policy.json")
        json.dump({"policy_version": 1}, open(path, "w"))
        self.assertEqual(DetGovRouter(path).evaluate_request("files.read", {}), (False, "DG-G-003", R.CODES["DG-G-003"]))

    def test_violation_object(self):
        v = GovernanceViolation("DG-C-002")
        self.assertEqual((v.code, v.invariant), ("DG-C-002", "I_C"))
        for code in R.CODES:
            self.assertIn(R.invariant_of(code), {"I_B", "I_C", "I_R", "I_T", "I_G", "I_P"})
        with self.assertRaises(ValueError):
            GovernanceViolation("NOPE")


if __name__ == "__main__":
    unittest.main()
