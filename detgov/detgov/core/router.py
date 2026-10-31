"""Deterministic governance router: loads a (optionally signed) policy and decides tool requests.

Decisions are pure functions of (policy, tool name, params): no clock, RNG, I/O or global state. Hard structural rejections are checked
in a fixed order (B, C, R, T, G) and cannot be relaxed by policy; the allowlist is checked last. Rationales never echo parameter values.
"""
import hashlib
import re
import unicodedata
from typing import Dict, List, Tuple
from urllib.parse import urlsplit

from . import crypto

# ---------------------------------------------------------------- error codes
CODES = {
    # Boundary I_B
    "DG-B-001": "vendor-hosted external tool",
    "DG-B-002": "IPC / UNIX-domain socket escape",
    "DG-B-003": "unmasked PAN to unapproved endpoint",
    # Causal / provenance I_C
    "DG-C-001": "runtime schema / tool-description override",
    "DG-C-002": "revoked enterprise entity",
    "DG-C-003": "invalid ISRC",
    "DG-C-004": "ISRC metadata collision",
    # Routing I_R
    "DG-R-001": "dynamic code entrypoint",
    # Temporal I_T
    "DG-T-001": "background persistence / cron / daemonisation",
    "DG-T-002": "unmetered background execution",
    # Governance I_G
    "DG-G-001": "privilege escalation",
    "DG-G-002": "process spawn",
    "DG-G-003": "tool not on allowlist",
    "DG-G-004": "malformed request",
    "DG-G-005": "no handler registered",
    "DG-G-006": "handler contract violated",
    # Policy
    "DG-P-001": "invalid policy",
    "DG-P-002": "policy signature verification failed",
    "DG-P-003": "signature enforcement misconfigured",
}
INVARIANT = {"B": "I_B", "C": "I_C", "R": "I_R", "T": "I_T", "G": "I_G", "P": "I_P"}


def invariant_of(code: str) -> str:
    return INVARIANT.get(code.split("-")[1], "?") if code in CODES else "?"


class GovernanceViolation(Exception):
    """Raised for rejected requests and unusable policy. `.code` is a formal code from CODES, `.invariant` its category."""

    def __init__(self, code: str, rationale: str = ""):
        if code not in CODES:
            raise ValueError(f"unknown error code {code!r}")
        self.code = code
        self.invariant = invariant_of(code)
        self.rationale = rationale or CODES[code]
        super().__init__(f"{code} [{self.invariant}]: {self.rationale}")


# ---------------------------------------------------------------- limits
MAX_NAME = 128
MAX_DEPTH = 64
MAX_NODES = 100_000
MAX_STRING = 1024 * 1024
_NAME_RE = re.compile(r"[A-Za-z0-9_.:/\-]{1,128}")


def _bad(msg="malformed request"):
    return GovernanceViolation("DG-G-004", msg)


def snapshot_params(params):
    """Deep, validated copy of JSON-like params (exact types only; cycles/oversize rejected). Raises GovernanceViolation(DG-G-004)."""
    if params is None:
        return {}
    if type(params) is not dict:
        raise _bad("params must be a JSON object")
    root = {}
    stack = [(params, root, 1)]
    nodes = 0
    while stack:
        src, dst, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise _bad("params nested too deeply")
        items = list(src.items()) if type(src) is dict else list(enumerate(src))
        for k, v in items:
            nodes += 1
            if nodes > MAX_NODES:
                raise _bad("params too large")
            if type(src) is dict and type(k) is not str:
                raise _bad("params keys must be strings")
            t = type(v)
            if t is dict:
                c = {}
                stack.append((v, c, depth + 1))
            elif t is list:
                c = [None] * len(v)
                stack.append((v, c, depth + 1))
            elif t is str:
                if len(v) > MAX_STRING:
                    raise _bad("string too long")
                c = v
            elif t is int or t is bool or v is None:
                c = v
            elif t is float:
                if v != v or v in (float("inf"), float("-inf")):
                    raise _bad("non-finite number")
                c = v
            else:
                raise _bad("params contain a non-JSON value")
            dst[k] = c
    return root


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Cf")
    return s.casefold()


def _truthy(v):
    return v not in (None, False, 0, "", [], {}, "false", "False", "0", "no", "off")


# ---------------------------------------------------------------- name rules
_SPLIT = re.compile(r"[.:/\-]+")
_SPLIT_US = re.compile(r"[._:/\-]+|_")

VENDOR_PREFIXES = ("llm.vendor.", "google_search", "hosted_bash", "hosted_", "web_search", "code_execution", "computer_use", "vendor.")
IPC_NAME_PREFIXES = ("ipc.", "ipc_", "uds.", "uds_", "unix_socket", "unix.", "dbus", "named_pipe", "namedpipe")
RUNTIME_TOKENS = {"eval", "evaluate", "compile", "exec", "interpreter", "repl", "runpy"}
RUNTIME_FIRST = {"eval", "compile"}
RUNTIME_EXACT = {"run_python", "run_code", "run_script", "execute_code", "execute_script", "code_interpreter", "python_exec", "js_eval", "exec_code"}
SPAWN_TOKENS = {"fork", "vfork", "forkpty", "spawn", "popen", "subprocess", "system", "shell", "child_process", "multiprocessing", "powershell", "cmd", "bash", "sh",
                "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe", "posix_spawn"}
SPAWN_FIRST = {"fork", "spawn", "popen", "subprocess"}
SPAWN_EXACT = {"os_system", "run_shell", "run_command", "execute_command", "execute_shell", "run_process"}
PRIV_TOKENS = {"sudo", "su", "doas", "setuid", "setgid", "seteuid", "setegid", "setresuid", "chown", "chroot", "pkexec", "setcap", "insmod", "ptrace", "runas", "privileged",
               "escalate", "elevate"}
PRIV_EXACT = {"privilege_escalation", "grant_admin", "become_root", "run_as_root"}
TEMPORAL_TOKENS = {"cron", "crontab", "anacron", "daemon", "daemonize", "daemonise", "nohup", "setsid", "systemd", "launchd", "schedule", "scheduler", "autostart", "keepalive"}
TEMPORAL_FIRST = {"schedule", "cron", "daemon"}
BACKGROUND_TOKENS = {"background"}
SCHEMA_NOUNS = {"schema", "description", "descriptions"}
SCHEMA_VERBS = {"override", "set", "patch", "update", "modify", "redefine", "overwrite", "replace", "rewrite", "mutate", "inject"}
TOOL_NOUNS = {"tool", "tools", "function", "functions", "handler"}
TOOL_VERBS = {"register", "unregister", "redefine", "patch", "hotpatch", "monkeypatch", "overwrite", "override", "modify", "mutate", "rewrite", "inject", "replace", "update", "set"}

# ---------------------------------------------------------------- param rules (keys are NFKC-casefolded)
IPC_KEYS = {"unix_socket", "socket_path", "uds", "ipc_path", "pipe_name", "dbus_address", "unix_socket_path", "docker_socket"}
SCHEMA_KEYS = {"tool_schema", "schema_override", "override_schema", "description_override", "tool_description", "tool_descriptions", "input_schema_override",
               "__schema__", "$schema_override", "function_schema", "new_schema", "tool_definition", "tool_definitions", "system_prompt_override"}
RUNTIME_KEYS = {"eval", "eval_expr", "compile", "dynamic_code", "exec_code"}
SPAWN_KEYS = {"shell", "spawn", "fork"}
PRIV_KEYS = {"privileged", "sudo", "setuid", "escalate"}
PRIV_USER_KEYS = {"run_as", "user", "runas", "as_user", "uid", "euid"}
PRIV_USER_VALUES = {"root", "0", "administrator", "system", "nt authority\\system"}
TEMPORAL_ALWAYS_KEYS = {"cron", "crontab", "daemonize", "daemon", "setsid", "nohup", "schedule", "every", "repeat_every", "interval_seconds", "loop_forever", "run_forever",
                        "systemd_unit", "launchd"}
TEMPORAL_METERED_KEYS = {"background", "detach", "persist", "persistent", "keepalive", "keep_alive"}
DEST_KEYS = {"endpoint", "url", "uri", "host", "hostname", "destination", "dest", "target", "address", "sink", "server", "webhook", "callback_url", "collector"}
HASH_KEYS = {"content_hash", "sha256", "audio_sha256", "media_hash"}

_PAN_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)")
_ISRC_RE = re.compile(r"[A-Z]{2}[A-Z0-9]{3}[0-9]{7}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _is_ipc_string(s: str) -> bool:
    s = s.strip()
    return (s.startswith(("unix:", "npipe:", "\x00", "/var/run/", "/run/")) or "unix://" in s or "\\\\.\\pipe\\" in s or s.endswith((".sock", ".socket")))


def _endpoint_approved(candidate: str, approved: Tuple[str, ...]) -> bool:
    if not isinstance(candidate, str) or not candidate or any(c.isspace() or c == "\\" or ord(c) < 32 for c in candidate):
        return False
    try:
        c = urlsplit(candidate if "//" in candidate else "https://" + candidate)
        if c.username is not None or c.password is not None or not c.hostname:
            return False
        c_scheme, c_host, c_port = c.scheme.lower(), c.hostname.lower().rstrip("."), c.port
        for entry in approved:
            e = urlsplit(entry if "//" in entry else "https://" + entry)
            e_host = (e.hostname or "").lower().rstrip(".")
            if e_host != c_host:
                continue
            explicit = "//" in entry
            e_scheme = e.scheme.lower() if explicit else "https"
            default = {"https": 443, "http": 80}
            if c_scheme != e_scheme:
                continue
            if (c_port or default.get(c_scheme)) != (e.port or default.get(e_scheme)):
                continue
            return True
    except ValueError:
        return False
    return False


class _Policy:
    def __init__(self, obj):
        allowed = {"policy_version", "allowlist", "revoked_entities", "approved_endpoints", "isrc_registry", "max_background_seconds"}
        if type(obj) is not dict or set(obj) - allowed or type(obj.get("policy_version")) is not int or obj.get("policy_version") != 1:
            raise GovernanceViolation("DG-P-001", "policy must be an object with policy_version 1 and only known fields")
        def strlist(key, check=None):
            v = obj.get(key, [])
            if type(v) is not list or len(v) > 10000 or not all(type(x) is str and x and len(x) <= 512 and (check is None or check(x)) for x in v):
                raise GovernanceViolation("DG-P-001", f"{key} must be a list of valid strings")
            return v
        self.allowlist = frozenset(strlist("allowlist", lambda x: _NAME_RE.fullmatch(x) is not None))
        self.revoked = tuple(sorted({_norm(x) for x in strlist("revoked_entities")}))
        self.approved_endpoints = tuple(sorted(set(strlist("approved_endpoints"))))
        reg = obj.get("isrc_registry", {})
        if type(reg) is not dict or len(reg) > 1_000_000:
            raise GovernanceViolation("DG-P-001", "isrc_registry must be an object")
        self.isrc_registry: Dict[str, str] = {}
        for k, v in reg.items():
            nk = k.replace("-", "").upper() if type(k) is str else ""
            if not _ISRC_RE.fullmatch(nk) or type(v) is not str or not _HEX64.fullmatch(v.lower()):
                raise GovernanceViolation("DG-P-001", "isrc_registry maps valid ISRCs to sha256 hex")
            self.isrc_registry[nk] = v.lower()
        mb = obj.get("max_background_seconds", 300)
        if type(mb) is not int or not 1 <= mb <= 86400:
            raise GovernanceViolation("DG-P-001", "max_background_seconds must be an integer 1..86400")
        self.max_background_seconds = mb
        self.revoked_res = [re.compile(r"(?<![a-z0-9])" + re.escape(r) + r"(?![a-z0-9])") for r in self.revoked]


class _Facts:
    """Flat view of a params snapshot."""
    def __init__(self, params):
        self.keys: List[Tuple[str, object]] = []        # (normalised key, value node)
        self.leaves: List[Tuple[str, object]] = []      # (nearest normalised key, scalar)
        self.dicts: List[dict] = []
        stack = [(params, "")]
        while stack:
            node, near = stack.pop()
            if type(node) is dict:
                self.dicts.append(node)
                for k, v in node.items():
                    nk = _norm(k)
                    self.keys.append((nk, v))
                    stack.append((v, nk))
            elif type(node) is list:
                for v in node:
                    stack.append((v, near))
            else:
                self.leaves.append((near, node))
        self.strings = [(k, _norm(v)) for k, v in self.leaves if type(v) is str]


class DetGovRouter:
    def __init__(self, policy_path: str, public_key_hex: str = None, enforce_sig: bool = False):
        self.signature_verified = False
        if enforce_sig and public_key_hex is None:
            raise GovernanceViolation("DG-P-003", "enforce_sig requires public_key_hex")
        try:
            raw = crypto.read_limited(policy_path, crypto.MAX_POLICY_BYTES)
            obj = crypto.loads_strict(raw)
            canon = crypto.canonical_json_bytes(obj)
        except (OSError, ValueError, TypeError) as e:
            raise GovernanceViolation("DG-P-001", "policy file unreadable or not canonicalisable JSON") from e
        if public_key_hex is not None:
            try:
                sig = crypto.read_limited(str(policy_path) + ".sig", crypto.MAX_SIG_FILE_BYTES).decode("ascii")
            except (OSError, ValueError):
                sig = ""
            self.signature_verified = crypto.verify_policy_bytes(raw, public_key_hex, sig)
            if enforce_sig and not self.signature_verified:
                raise GovernanceViolation("DG-P-002")
        self._policy = _Policy(obj)
        self.policy_digest = hashlib.sha256(canon).hexdigest()

    # ---- public API
    @property
    def allowlist(self):
        return self._policy.allowlist

    def evaluate_request(self, tool_name: str, params: dict = None) -> Tuple[bool, str, str]:
        """(allowed, error_code, rationale). Never raises; anything unexpected is denied (DG-G-004)."""
        try:
            self._evaluate(tool_name, params)
            return True, "", "allowed"
        except GovernanceViolation as v:
            return False, v.code, v.rationale
        except Exception:
            return False, "DG-G-004", CODES["DG-G-004"]

    # ---- implementation
    def _evaluate(self, name, params):
        if type(name) is not str or not _NAME_RE.fullmatch(name):
            raise _bad("malformed tool name")
        facts = _Facts(snapshot_params(params))
        n = name.casefold()
        tokens = set(_SPLIT.split(n))
        words = _SPLIT_US.split(n)
        wordset = set(words)
        self._boundary(n, facts)
        self._causal(n, wordset, facts)
        self._routing(n, tokens, words, facts)
        self._temporal(n, tokens, words, facts)
        self._governance(name, n, tokens, words, facts)

    def _boundary(self, n, f):
        if n.startswith(VENDOR_PREFIXES) or "llm.vendor." in n:
            raise GovernanceViolation("DG-B-001")
        if n.startswith(IPC_NAME_PREFIXES) or any(k in IPC_KEYS for k, _ in f.keys) or any(_is_ipc_string(s) for _, s in f.strings):
            raise GovernanceViolation("DG-B-002")
        found_pan = False
        for _, v in f.leaves:
            if type(v) is str:
                cands = [re.sub(r"\D", "", m.group()) for m in _PAN_RE.finditer(_norm(v))]
            elif type(v) is int and not isinstance(v, bool) and 13 <= len(str(abs(v))) <= 19:
                cands = [str(abs(v))]
            else:
                continue
            if any(13 <= len(c) <= 19 and luhn_ok(c) for c in cands):
                found_pan = True
                break
        if found_pan:
            dests = [v for k, v in f.leaves if k in DEST_KEYS and type(v) is str]
            if not dests or not all(_endpoint_approved(d, self._policy.approved_endpoints) for d in dests):
                raise GovernanceViolation("DG-B-003")

    def _causal(self, n, w, f):
        if (w & SCHEMA_NOUNS and w & SCHEMA_VERBS) or (w & TOOL_NOUNS and w & TOOL_VERBS) or any(k in SCHEMA_KEYS for k, _ in f.keys):
            raise GovernanceViolation("DG-C-001")
        for rx in self._policy.revoked_res:
            if any(rx.search(s) for _, s in f.strings) or any(type(v) is int and rx.search(str(v)) for _, v in f.leaves):
                raise GovernanceViolation("DG-C-002")
        seen = {}
        for d in f.dicts:
            for k, v in d.items():
                if _norm(k) != "isrc":
                    continue
                isrc = _norm(v).replace("-", "").upper() if type(v) is str else None
                if isrc is None or not _ISRC_RE.fullmatch(isrc):
                    raise GovernanceViolation("DG-C-003")
                h = None
                for hk, hv in d.items():
                    if _norm(hk) in HASH_KEYS and type(hv) is str:
                        h = hv.strip().lower()
                        break
                reg = self._policy.isrc_registry.get(isrc)
                if reg is not None and h != reg:
                    raise GovernanceViolation("DG-C-004")
                if isrc in seen and seen[isrc] != h:
                    raise GovernanceViolation("DG-C-004")
                seen[isrc] = h

    def _routing(self, n, tokens, words, f):
        rt = tokens & RUNTIME_TOKENS
        if rt == {"exec"} and (tokens & SPAWN_TOKENS or "os" in tokens):
            rt = set()                           # os.exec / child_process.exec: process execution is spawn (I_G), not dynamic code
        if rt or words[0] in RUNTIME_FIRST or n in RUNTIME_EXACT or any(k in RUNTIME_KEYS and _truthy(v) for k, v in f.keys):
            raise GovernanceViolation("DG-R-001")

    def _temporal(self, n, tokens, words, f):
        if tokens & TEMPORAL_TOKENS or words[0] in TEMPORAL_FIRST or any(k in TEMPORAL_ALWAYS_KEYS and _truthy(v) for k, v in f.keys):
            raise GovernanceViolation("DG-T-001")
        wants_bg = bool(tokens & BACKGROUND_TOKENS) or any(k in TEMPORAL_METERED_KEYS and _truthy(v) for k, v in f.keys)
        if wants_bg:
            limits = [v for k, v in f.keys if k == "max_runtime_seconds"]
            ok = len(limits) == 1 and type(limits[0]) in (int, float) and not isinstance(limits[0], bool) and 0 < limits[0] <= self._policy.max_background_seconds
            if not ok:
                raise GovernanceViolation("DG-T-002")

    def _governance(self, name, n, tokens, words, f):
        spawn_tokens = tokens & SPAWN_TOKENS
        os_exec = "exec" in tokens and "os" in tokens
        if (tokens & PRIV_TOKENS or n in PRIV_EXACT or words[0] in ("sudo", "escalate", "elevate")
                or any(k in PRIV_KEYS and _truthy(v) for k, v in f.keys)):
            raise GovernanceViolation("DG-G-001")
        for k, v in f.leaves:
            if k in PRIV_USER_KEYS and (_norm(v) if type(v) is str else str(v)) in PRIV_USER_VALUES and type(v) is not bool:
                raise GovernanceViolation("DG-G-001")
        if any(k in ("cap_add", "capabilities") and _truthy(v) for k, v in f.keys):
            raise GovernanceViolation("DG-G-001")
        if spawn_tokens or os_exec or words[0] in SPAWN_FIRST or n in SPAWN_EXACT or any(k in SPAWN_KEYS and _truthy(v) for k, v in f.keys):
            raise GovernanceViolation("DG-G-002")
        if name not in self._policy.allowlist:
            raise GovernanceViolation("DG-G-003")
