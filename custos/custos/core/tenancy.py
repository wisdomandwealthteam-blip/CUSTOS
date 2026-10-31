"""Tenant isolation and policy-key custody for DetGov routers.

Each tenant owns: a set of Ed25519 policy-verification keys, a live DetGovRouter and a Firewall bound to it. All three live in one immutable
`_State`; rotation builds and verifies a complete new state first and swaps a single reference (readers never see a half-updated tenant,
in-flight calls finish on the state they started with, and a failed rotation changes nothing).
"""
import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from detgov import DetGovRouter, Firewall, GovernanceViolation
from detgov.core import crypto

from .errors import CustosError
from .vault import valid_tenant_id


def key_id(public_key_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


@dataclass(frozen=True)
class KeySet:
    current_hex: str
    previous: Tuple[Tuple[str, float], ...] = ()          # (public key hex, valid until [clock units])
    version: int = 1

    @property
    def current_id(self) -> str:
        return key_id(self.current_hex)

    def acceptable(self, now: float) -> Tuple[str, ...]:
        return (self.current_hex,) + tuple(pk for pk, until in self.previous if now < until)


@dataclass(frozen=True)
class _State:
    router: DetGovRouter
    firewall: Firewall
    keys: KeySet
    policy_path: str
    version: int


@dataclass(frozen=True)
class RotationResult:
    tenant_id: str
    old_key_id: str
    new_key_id: str
    version: int
    dropped_handlers: Tuple[str, ...]


class _Tenant:
    def __init__(self, tenant_id):
        self.id = tenant_id
        self.lock = threading.Lock()
        self.handlers: Dict[str, Tuple[Callable, dict]] = {}
        self.state: Optional[_State] = None


def _check_pk(public_key_hex):
    pk = crypto.parse_public_key_hex(public_key_hex)
    if pk is None:
        raise CustosError("CS-T-003", "public key must be 64 hex characters")
    return pk


class TenantRegistry:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._tenants: Dict[str, _Tenant] = {}
        self._reg_lock = threading.Lock()
        self._hooks: List[Callable] = []
        self.hook_errors: List[Tuple[str, str]] = []
        self.handler_adapter: Callable = lambda tenant_id, name, func, options: func      # set by CustosGate

    # ---- lookup
    def _tenant(self, tenant_id) -> _Tenant:
        t = self._tenants.get(tenant_id) if valid_tenant_id(tenant_id) else None
        if t is None or t.state is None:
            raise CustosError("CS-T-002")
        return t

    def state(self, tenant_id) -> _State:
        return self._tenant(tenant_id).state          # single reference read: consistent snapshot, no lock

    def router(self, tenant_id) -> DetGovRouter:
        return self.state(tenant_id).router

    def firewall(self, tenant_id) -> Firewall:
        return self.state(tenant_id).firewall

    def keys(self, tenant_id) -> KeySet:
        return self.state(tenant_id).keys

    def tenant_ids(self) -> List[str]:
        return sorted(k for k, t in self._tenants.items() if t.state is not None)

    # ---- lifecycle
    def register_tenant(self, tenant_id: str, policy_path: str, public_key_hex: str) -> None:
        """Verify `policy_path` against `public_key_hex` (signature REQUIRED) and bring the tenant online."""
        if not valid_tenant_id(tenant_id):
            raise CustosError("CS-V-006", "invalid tenant id")
        _check_pk(public_key_hex)
        with self._reg_lock:
            if tenant_id in self._tenants:
                raise CustosError("CS-T-004")
            t = _Tenant(tenant_id)
            self._tenants[tenant_id] = t
        try:
            router = DetGovRouter(policy_path, public_key_hex, enforce_sig=True)
            fw, _ = self._build_firewall(t, router)
            t.state = _State(router, fw, KeySet(public_key_hex.lower()), str(policy_path), 1)
        except GovernanceViolation as e:
            with self._reg_lock:
                self._tenants.pop(tenant_id, None)
            raise CustosError("CS-T-003", f"{e.code}") from None

    def register_handler(self, tenant_id: str, name: str, func: Callable, **options) -> None:
        """Bind `func` to `name` for this tenant (policy must allow it) and keep it across rotations."""
        t = self._tenant(tenant_id)
        if not callable(func):
            raise TypeError("handler must be callable")
        with t.lock:
            if name in t.handlers:
                raise ValueError(f"handler for {name!r} already registered for tenant")
            state = t.state
            state.firewall.register_handler(name, self.handler_adapter(tenant_id, name, func, options))      # raises GovernanceViolation if not allowed
            t.handlers[name] = (func, options)

    def _build_firewall(self, t: _Tenant, router: DetGovRouter):
        fw = Firewall(router)
        dropped = []
        for name, (func, options) in sorted(t.handlers.items()):
            try:
                fw.register_handler(name, self.handler_adapter(t.id, name, func, options))
            except GovernanceViolation:
                dropped.append(name)               # tightened policy no longer allows it -> requests get DG-G-005/DG-G-003
        return fw, tuple(dropped)

    # ---- rotation
    def on_rotate(self, callback: Callable[[RotationResult], None]) -> None:
        """Register a hook called after every successful swap (key rotation or policy reload). Hook errors are recorded, never propagated."""
        self._hooks.append(callback)

    def rotate_key(self, tenant_id: str, new_public_key_hex: str, *, policy_path: Optional[str] = None, grace_seconds: float = 0) -> RotationResult:
        """Atomically switch the tenant's policy-verification key.

        With `policy_path` the policy (re-signed under the NEW key) is loaded and verified first; without it the live router is kept and the
        new key governs the next `reload_policy`. During `grace_seconds` the previous key is still accepted for reloads.
        On any failure the tenant keeps its previous state exactly.
        """
        t = self._tenant(tenant_id)
        _check_pk(new_public_key_hex)
        if isinstance(grace_seconds, bool) or not isinstance(grace_seconds, (int, float)) or not 0 <= grace_seconds <= 30 * 86400 or grace_seconds != grace_seconds:
            raise CustosError("CS-T-003", "grace_seconds must be 0..2592000")
        new_hex = new_public_key_hex.lower()
        with t.lock:
            old = t.state
            if new_hex == old.keys.current_hex:
                raise CustosError("CS-T-003", "new key equals the current key")
            path = str(policy_path) if policy_path is not None else old.policy_path
            if policy_path is not None:
                try:
                    router = DetGovRouter(path, new_hex, enforce_sig=True)
                except GovernanceViolation as e:
                    raise CustosError("CS-T-003", e.code) from None
            else:
                router = old.router
            fw, dropped = self._build_firewall(t, router) if router is not old.router else (old.firewall, ())
            prev = tuple((pk, u) for pk, u in old.keys.previous if self._clock() < u)
            if grace_seconds > 0:
                prev = prev + ((old.keys.current_hex, self._clock() + float(grace_seconds)),)
            t.state = _State(router, fw, KeySet(new_hex, prev, old.keys.version + 1), path, old.version + 1)
            result = RotationResult(tenant_id, old.keys.current_id, key_id(new_hex), t.state.version, dropped)
        self._fire(result)
        return result

    def reload_policy(self, tenant_id: str, policy_path: Optional[str] = None) -> RotationResult:
        """Re-load (and re-verify) the tenant's policy against any currently acceptable key, swapping atomically."""
        t = self._tenant(tenant_id)
        with t.lock:
            old = t.state
            path = str(policy_path) if policy_path is not None else old.policy_path
            router, used = None, None
            for pk in old.keys.acceptable(self._clock()):
                try:
                    router, used = DetGovRouter(path, pk, enforce_sig=True), pk
                    break
                except GovernanceViolation:
                    continue
            if router is None:
                raise CustosError("CS-T-003", "policy does not verify under any acceptable key")
            fw, dropped = self._build_firewall(t, router)
            t.state = _State(router, fw, old.keys, path, old.version + 1)
            result = RotationResult(tenant_id, old.keys.current_id, key_id(used), t.state.version, dropped)
        self._fire(result)
        return result

    def revoke_previous_keys(self, tenant_id: str) -> None:
        t = self._tenant(tenant_id)
        with t.lock:
            old = t.state
            t.state = _State(old.router, old.firewall, KeySet(old.keys.current_hex, (), old.keys.version + 1), old.policy_path, old.version)

    def _fire(self, result):
        for cb in list(self._hooks):
            try:
                cb(result)
            except Exception as e:                # a broken hook must never undo or block a rotation
                self.hook_errors.append((result.tenant_id, type(e).__name__))
