"""CustosGate: DetGov Firewall + credential custody.

Request path for `execute(tenant, tool, params)`:
  1. validated deep copy of params (DetGov's snapshot rules);
  2. scrub inbound credentials: this tenant's known secrets -> handle refs, credential-shaped strings -> [REDACTED:*]
     (leak_policy="reject" turns any detection into CS-G-001);
  3. every handle in the params must belong to this tenant (TenantIsolationError otherwise) and be live (no use consumed yet);
  4. DetGov evaluates the handle-only params (policy denials never consume a handle use, never see plaintext);
  5. only at the final dispatch boundary are handles resolved (one use per distinct handle per call), the handler runs, plaintext is wiped;
  6. the handler's result/exception text is scrubbed (echoed secrets -> handles) before it returns to the caller or any log.
"""
import contextvars
import json
import threading
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from detgov import GovernanceViolation
from detgov.core.router import snapshot_params

from .errors import CustosError, HandlerError, TenantIsolationError
from .scrub import Scrubber
from .tenancy import TenantRegistry
from .vault import HANDLE_RE, SecretLease, SecretVault

MAX_AUDIT_PARAMS = 4096


@dataclass(frozen=True)
class _Call:
    tenant: str
    tool: str


_CALL: "contextvars.ContextVar" = contextvars.ContextVar("custos_call", default=None)


def find_handles(obj) -> List[str]:
    """All distinct handles appearing as (parts of) string VALUES, in first-seen order. A handle inside an object KEY is rejected (CS-G-004)."""
    seen, stack = [], [obj]
    while stack:
        n = stack.pop()
        if type(n) is dict:
            for k, v in n.items():
                if HANDLE_RE.search(k):
                    raise CustosError("CS-G-004", "handles are only allowed as values")
                stack.append(v)
        elif type(n) is list:
            stack.extend(reversed(n))
        elif type(n) is str:
            for m in HANDLE_RE.findall(n):
                if m not in seen:
                    seen.append(m)
    return seen


def _wipe_structure(obj):
    """Best-effort: drop references to plaintext held in a dispatch copy so a handler that retains the dict does not retain secrets."""
    stack = [obj]
    while stack:
        n = stack.pop()
        if type(n) is dict:
            stack.extend(n.values())
            for k in list(n):
                n[k] = None
        elif type(n) is list:
            stack.extend(n)
            for i in range(len(n)):
                n[i] = None


class CustosGate:
    def __init__(self, registry: TenantRegistry, vault: SecretVault, *, leak_policy: str = "replace", audit_size: int = 10000):
        if leak_policy not in ("replace", "reject"):
            raise ValueError("leak_policy must be 'replace' or 'reject'")
        self.registry, self.vault, self.leak_policy = registry, vault, leak_policy
        self.scrubber = Scrubber(vault)
        self._audit = deque(maxlen=int(audit_size))
        self._lock = threading.Lock()
        self._seq = 0
        registry.handler_adapter = self._adapt

    # ---- public API
    def register_handler(self, tenant_id: str, name: str, func: Callable, *, inject: str = "text") -> None:
        """`inject="text"`: handles inside params are replaced by plaintext str at dispatch. `inject="lease"`: params that are exactly a handle
        arrive as `SecretLease` objects (zeroed after the call; embedded handles are refused)."""
        if inject not in ("text", "lease"):
            raise ValueError("inject must be 'text' or 'lease'")
        self.registry.register_handler(tenant_id, name, func, inject=inject)

    def sanitize(self, tenant_id: str, obj):
        """Scrub any JSON-like value (e.g. text bound for the LLM or a log) for this tenant."""
        return self.scrubber.scrub(tenant_id, obj)[0]

    def execute(self, tenant_id: str, name: str, params: dict = None) -> dict:
        state = self.registry.state(tenant_id)                # CS-T-002 for unknown tenants
        handles: List[str] = []
        clean = None
        kinds: Dict[str, int] = {}
        try:
            try:
                snap = snapshot_params(params)
            except GovernanceViolation as v:
                self._record(tenant_id, name, "denied", v.code, handles, None, kinds)
                raise
            clean, report = self.scrubber.scrub(tenant_id, snap)
            kinds = dict(report.kinds)
            if self.leak_policy == "reject" and report.leaks:
                raise CustosError("CS-G-001", ", ".join(sorted(kinds)))
            handles = find_handles(clean)
            for h in handles:
                self.vault.peek(tenant_id, h, name)                  # isolation / liveness first; consumes nothing
            token = _CALL.set(_Call(tenant_id, name))
            try:
                result = state.firewall.execute(name, clean)
            finally:
                _CALL.reset(token)
        except GovernanceViolation as v:
            self._record(tenant_id, name, "denied", v.code, handles, clean, kinds)
            raise
        except CustosError as e:
            self._record(tenant_id, name, "error", e.code, handles, clean, kinds)
            raise
        self._record(tenant_id, name, "allowed", "", handles, clean, kinds)
        return result

    def audit_log(self) -> List[dict]:
        with self._lock:
            return list(self._audit)

    # ---- internals
    def _record(self, tenant, tool, outcome, code, handles, clean, kinds):
        text = ""
        if clean is not None:
            try:
                text = json.dumps(clean, sort_keys=True, separators=(",", ":"))[:MAX_AUDIT_PARAMS]
            except (TypeError, ValueError):
                text = "<unserialisable>"
        with self._lock:
            self._seq += 1
            self._audit.append({"seq": self._seq, "tenant": tenant, "tool": tool if isinstance(tool, str) and len(tool) <= 128 else "<invalid>",
                                "outcome": outcome, "code": code, "handles": list(handles), "leaks": dict(kinds), "params": text})

    def _adapt(self, tenant_id: str, name: str, func: Callable, options: dict) -> Callable:
        mode = options.get("inject", "text")

        def dispatch(params):
            ctx = _CALL.get()
            if ctx is None or ctx.tenant != tenant_id or ctx.tool != name:
                raise CustosError("CS-G-005")
            leases: Dict[str, SecretLease] = {}
            plain = None
            failure = None
            result = None
            try:
                for h in find_handles(params):
                    leases[h] = self.vault.lease(tenant_id, h, name)          # authorise + consume; raises Tenant/Handle errors
                plain = self._inject(params, leases, mode)
                try:
                    raw = func(plain)
                except CustosError:
                    raise
                except Exception as e:
                    failure = f"{type(e).__name__}: {e}"
                if failure is None:
                    if type(raw) is not dict:
                        raise CustosError("CS-G-003", "handler must return a dict")
                    result = self.scrubber.scrub(tenant_id, raw)[0]
                else:
                    failure = self.scrubber.scrub(tenant_id, failure[:2000])[0]
            finally:
                for l in leases.values():
                    l.close()
                if plain is not None:
                    _wipe_structure(plain)
            if failure is not None:
                raise HandlerError(failure)
            return result
        return dispatch

    @staticmethod
    def _inject(params, leases: Dict[str, SecretLease], mode: str):
        def conv(s: str):
            if mode == "lease":
                if s in leases:
                    return leases[s]
                if HANDLE_RE.search(s):
                    raise CustosError("CS-G-004", "embedded handle not allowed in lease mode")
                return s
            return HANDLE_RE.sub(lambda m: leases[m.group()].text(), s) if HANDLE_RE.search(s) else s
        root = [None]
        stack = [(params, root, 0)]
        while stack:
            node, dst, slot = stack.pop()
            t = type(node)
            if t is dict:
                c = {}
                dst[slot] = c
                for k, v in node.items():
                    c[k] = None
                    stack.append((v, c, k))
            elif t is list:
                c = [None] * len(node)
                dst[slot] = c
                for i, v in enumerate(node):
                    stack.append((v, c, i))
            elif t is str:
                dst[slot] = conv(node)
            else:
                dst[slot] = node
        return root[0]
