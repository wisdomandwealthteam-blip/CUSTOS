"""Developer-facing firewall: binds allowlisted tool names to local handlers and sanitises provider tool payloads."""
import threading
from collections import deque
from typing import Callable, Dict, List

from .router import CODES, DetGovRouter, GovernanceViolation, snapshot_params

_CLAUDE_KEYS = ("name", "description", "input_schema", "cache_control")
_GEMINI_KEYS = ("name", "description", "parameters", "response")
_GEMINI_WRAPPERS = ("function_declarations", "functionDeclarations")


class Firewall:
    """`Firewall(router)` or `Firewall("policy.json", public_key_hex=..., enforce_sig=True)`.

    Every execution evaluates a validated deep copy of the params and dispatches that same copy (no check/use gap).
    The audit log keeps (tool name, allowed, code) only: never parameter values.
    """

    def __init__(self, router_or_policy_path, public_key_hex: str = None, enforce_sig: bool = False, audit_size: int = 10000):
        if isinstance(router_or_policy_path, DetGovRouter):
            self.router = router_or_policy_path
        else:
            self.router = DetGovRouter(router_or_policy_path, public_key_hex, enforce_sig)
        self._handlers: Dict[str, Callable] = {}
        self._audit = deque(maxlen=int(audit_size))
        self._lock = threading.Lock()

    # ---- handlers
    def register_handler(self, name: str, func: Callable) -> None:
        if not callable(func):
            raise TypeError("handler must be callable")
        allowed, code, why = self.router.evaluate_request(name, {})
        if not allowed:
            raise GovernanceViolation(code, why)
        with self._lock:
            if name in self._handlers:
                raise ValueError(f"handler for {name!r} already registered")
            self._handlers[name] = func

    def execute(self, name: str, params: dict = None) -> dict:
        try:
            snap = snapshot_params(params)
        except GovernanceViolation as v:
            self._log(name, False, v.code)
            raise
        allowed, code, why = self.router.evaluate_request(name, snap)
        if not allowed:
            self._log(name, False, code)
            raise GovernanceViolation(code, why)
        handler = self._handlers.get(name)
        if handler is None:
            self._log(name, False, "DG-G-005")
            raise GovernanceViolation("DG-G-005", f"no handler registered for {name}")
        self._log(name, True, "")
        result = handler(snap)
        if type(result) is not dict:
            raise GovernanceViolation("DG-G-006", "handler must return a dict")
        return result

    def audit_log(self) -> List[tuple]:
        with self._lock:
            return list(self._audit)

    def _log(self, name, allowed, code):
        with self._lock:
            self._audit.append((name if isinstance(name, str) and len(name) <= 128 else "<invalid>", allowed, code))

    # ---- provider adapters
    def _tool_ok(self, name) -> bool:
        if type(name) is not str:
            return False
        allowed, code, _ = self.router.evaluate_request(name, {})
        self._log(name, allowed, code)
        return allowed

    def sanitize_claude_tools(self, tools: list) -> list:
        """Keep only client-side custom tools that are allowlisted and pass the structural rules; drop server-side/typed tools
        (web_search_*, code_execution_*, bash_*, computer_*, mcp, ...), unknown fields, duplicates and malformed entries. Returns new objects."""
        if type(tools) is not list:
            raise TypeError("tools must be a list")
        out, seen = [], set()
        for t in tools:
            if type(t) is not dict:
                continue
            if t.get("type", "custom") not in ("custom", None):
                self._log(str(t.get("name", "<typed>"))[:128], False, "DG-B-001")
                continue
            name = t.get("name")
            if name in seen or not self._tool_ok(name):
                continue
            desc = t.get("description")
            if desc is not None and type(desc) is not str:
                continue
            try:
                clean = snapshot_params({k: t[k] for k in _CLAUDE_KEYS if k in t})
            except GovernanceViolation:
                continue
            if "input_schema" in clean and type(clean["input_schema"]) is not dict:
                continue
            seen.add(name)
            out.append(clean)
        return out

    def sanitize_gemini_tools(self, declarations: list) -> list:
        """Keep only allowlisted function declarations (plain or wrapped in {'function_declarations': [...]}); drop built-in tools
        (google_search, code_execution, url_context, ...), unknown fields and duplicates. Returns new objects."""
        if type(declarations) is not list:
            raise TypeError("declarations must be a list")
        out, seen = [], set()

        def clean_decl(d):
            if type(d) is not dict:
                return None
            name = d.get("name")
            if name in seen or not self._tool_ok(name):
                return None
            if d.get("description") is not None and type(d.get("description")) is not str:
                return None
            try:
                c = snapshot_params({k: d[k] for k in _GEMINI_KEYS if k in d})
            except GovernanceViolation:
                return None
            seen.add(name)
            return c
        for item in declarations:
            if type(item) is not dict:
                continue
            wrapper = next((w for w in _GEMINI_WRAPPERS if w in item), None)
            if wrapper is not None:
                if type(item[wrapper]) is not list:
                    continue
                kept = [c for c in (clean_decl(d) for d in item[wrapper]) if c is not None]
                if kept:
                    out.append({wrapper: kept})
            elif "name" in item:
                c = clean_decl(item)
                if c is not None:
                    out.append(c)
            else:
                self._log(",".join(sorted(str(k) for k in item))[:128], False, "DG-B-001")     # built-in tool kinds
        return out
