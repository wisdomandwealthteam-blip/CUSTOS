"""Credential scrubbing for params, results, logs and LLM-facing text.

Known secrets (this tenant's vault contents, incl. base64/hex/URL/JSON-escaped forms) become their handle; unknown credential-shaped
strings are redacted as `[REDACTED:<kind>]`. Reports contain kinds/counts only, never values.
NOT detected: arbitrary transformations (rot13, splitting across fields, compression), secrets shorter than 8 bytes.
"""
import re
from typing import Dict, List, Tuple

from .errors import CustosError
from .vault import HANDLE_RE, SecretVault, secret_variants

SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "client_secret", "api_key", "apikey", "token", "access_token", "refresh_token", "auth_token", "authorization",
                  "private_key", "credentials", "credential", "connection_string", "conn_str", "dsn", "bearer", "x_api_key", "session_token"}
MAX_NODES = 100_000
MAX_DEPTH = 64

_PATTERNS: List[Tuple[str, "re.Pattern", str]] = [
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----[\s\S]{0,16384}?-----END [A-Z ]{0,30}PRIVATE KEY-----"), "[REDACTED:pem_private_key]"),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----"), "[REDACTED:pem_private_key]"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_access_key]"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "[REDACTED:github_token]"),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), "[REDACTED:github_token]"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "[REDACTED:slack_token]"),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"), "[REDACTED:stripe_key]"),
    ("api_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}"), "[REDACTED:api_key]"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED:google_api_key]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "[REDACTED:jwt]"),
    ("bearer", re.compile(r"(?i)\bBearer\s+(?!cst_sec_)[A-Za-z0-9._~+/=\-]{16,}"), "Bearer [REDACTED:bearer]"),
]
_URL_PASSWORD = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@]{1,100}:)(?!\[REDACTED)([^\s@/]{1,200})(@)")
_KV = re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)(\s*[=:]\s*[\"']?)(?!cst_sec_|\[REDACTED)([^\s\"',;&]{8,})")


class ScrubReport:
    def __init__(self):
        self.kinds: Dict[str, int] = {}
        self.known_handles: List[str] = []

    def add(self, kind, n=1):
        self.kinds[kind] = self.kinds.get(kind, 0) + n

    @property
    def leaks(self) -> bool:
        return bool(self.kinds)

    def __repr__(self):
        return f"<ScrubReport {self.kinds}>"


def _norm_key(k: str) -> str:
    return k.casefold().replace("-", "_").replace(" ", "_")


class Scrubber:
    def __init__(self, vault: SecretVault):
        self._vault = vault

    def scrub(self, tenant_id: str, obj):
        """Return (clean_copy, ScrubReport). `obj` must be JSON-like (dict/list/str/int/float/bool/None)."""
        report = ScrubReport()
        material = self._vault.scan_material(tenant_id)
        try:
            table = []
            for handle, buf in material:
                for v in secret_variants(bytes(buf)):
                    table.append((v, handle.encode()))
            table.sort(key=lambda t: -len(t[0]))
            clean = self._walk(obj, table, report)
        finally:
            for _, buf in material:
                buf[:] = bytes(len(buf))
        return clean, report

    def scrub_text(self, tenant_id: str, text: str) -> str:
        return self.scrub(tenant_id, text)[0]

    # ----------------------------------------------------------- internals
    def _known(self, s: str, table, report) -> str:
        if s and table:
            try:
                b = s.encode("utf-8", "surrogatepass")
            except Exception:
                b = None
            if b is not None:
                changed = False
                for needle, handle in table:
                    if len(needle) <= len(b) and needle in b:
                        report.add("known_secret", b.count(needle))
                        if handle.decode() not in report.known_handles:
                            report.known_handles.append(handle.decode())
                        b = b.replace(needle, handle)
                        changed = True
                if changed:
                    s = b.decode("utf-8", "surrogatepass")
        return s

    def _string(self, s: str, table, report) -> str:
        if not s:
            return s
        s = self._known(s, table, report)
        for kind, rx, repl in _PATTERNS:
            s, n = rx.subn(repl, s)
            if n:
                report.add(kind, n)
        s, n = _URL_PASSWORD.subn(lambda m: m.group(1) + "[REDACTED:url_password]" + m.group(3), s)
        if n:
            report.add("url_password", n)
        s, n = _KV.subn(lambda m: m.group(1) + m.group(2) + "[REDACTED:keyed_value]", s)
        if n:
            report.add("keyed_value", n)
        return s

    def _walk(self, obj, table, report):
        root_holder = [None]
        stack = [(obj, root_holder, 0, 1, "")]
        nodes = 0
        while stack:
            node, dst, slot, depth, key = stack.pop()
            nodes += 1
            if nodes > MAX_NODES or depth > MAX_DEPTH:
                raise CustosError("CS-G-003", "value too large or too deeply nested to scrub")
            t = type(node)
            if t is dict:
                c = {}
                dst[slot] = c
                for k, v in node.items():
                    if type(k) is not str:
                        raise CustosError("CS-G-003", "object keys must be strings")
                    nk = self._string(k, table, report)
                    while nk in c:
                        nk += "~dup"
                    c[nk] = None
                    if type(v) is str and _norm_key(k) in SENSITIVE_KEYS and len(v) >= 8 and not v.startswith("[REDACTED"):
                        v2 = self._known(v, table, report)
                        if HANDLE_RE.search(v2):
                            c[nk] = self._string(v2, table, report)
                        else:
                            report.add("keyed_value")
                            c[nk] = "[REDACTED:keyed_value]"
                    else:
                        stack.append((v, c, nk, depth + 1, k))
            elif t is list:
                c = [None] * len(node)
                dst[slot] = c
                for i, v in enumerate(node):
                    stack.append((v, c, i, depth + 1, key))
            elif t is str:
                dst[slot] = self._string(node, table, report)
            elif t is int or t is float or t is bool or node is None:
                dst[slot] = node
            else:
                raise CustosError("CS-G-003", "non-JSON value cannot be scrubbed")
        return root_holder[0]
