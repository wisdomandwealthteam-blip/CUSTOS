"""SecretVault: in-memory zero-leakage credential store with opaque handles.

Agents hold only handles (`cst_sec_<uuid4>`). Plaintext exists (a) sealed (HMAC-SHA256 CTR stream + HMAC tag, encrypt-then-MAC, keyed per vault)
while stored, and (b) transiently inside a `SecretLease` (a zeroed-on-exit bytearray) at the final dispatch boundary.

HONEST LIMITS: this is defence in depth inside one process, not a security boundary against code that can read process memory or call
vault methods. Python cannot guarantee that no stray copy of a secret exists (str/bytes are immutable; interpreter copies, GC); the lease
buffer is zeroed, but `lease.text()` returns an immutable str that cannot be wiped. Run untrusted agent code out-of-process and give it handles only.
"""
import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .errors import CustosError, TenantIsolationError

HANDLE_PREFIX = "cst_sec_"
HANDLE_RE = re.compile(r"cst_sec_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_TENANT_RE = re.compile(r"[A-Za-z0-9_.\-]{1,64}")
_TOOL_RE = re.compile(r"[A-Za-z0-9_.:/\-]{1,128}")
_DIGITY = re.compile(r"(?:\d[ \-]?){12,}\d")      # handles are re-rolled until they cannot be mistaken for a card number by DetGov's PAN rule
MIN_SECRET_BYTES = 8
MAX_SECRET_BYTES = 64 * 1024
MAX_PER_TENANT = 10_000
MAX_TOTAL = 1_000_000
MAX_LABEL = 200


def valid_tenant_id(tenant_id) -> bool:
    return type(tenant_id) is str and _TENANT_RE.fullmatch(tenant_id) is not None


def new_handle() -> str:
    while True:
        u = str(uuid.uuid4())
        if not _DIGITY.search(u):
            return HANDLE_PREFIX + u


@dataclass(frozen=True)
class HandleInfo:
    handle: str
    tenant_id: str
    label: str
    state: str                       # active | expired | exhausted
    uses_remaining: Optional[int]
    seconds_remaining: Optional[float]
    tools: Optional[Tuple[str, ...]]


class SecretLease:
    """Short-lived plaintext access. Use as a context manager; the buffer is zeroed on exit and the lease becomes unusable."""

    def __init__(self, buf: bytearray):
        self._buf: Optional[bytearray] = buf

    def view(self) -> memoryview:
        if self._buf is None:
            raise CustosError("CS-V-006", "lease already closed")
        return memoryview(self._buf).toreadonly()

    def text(self) -> str:
        """Decode to str. The returned str is immutable and cannot be wiped."""
        if self._buf is None:
            raise CustosError("CS-V-006", "lease already closed")
        return self._buf.decode("utf-8")

    @property
    def closed(self) -> bool:
        return self._buf is None

    def close(self):
        b, self._buf = self._buf, None
        if b is not None:
            b[:] = bytes(len(b))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __repr__(self):
        return "<SecretLease closed>" if self._buf is None else "<SecretLease open>"

    __str__ = __repr__


class _Entry:
    __slots__ = ("tenant", "handle", "nonce", "ct", "tag", "n", "expires", "uses_left", "tools", "label")

    def __init__(self, tenant, handle, nonce, ct, tag, expires, uses_left, tools, label):
        self.tenant, self.handle, self.nonce, self.ct, self.tag = tenant, handle, nonce, ct, tag
        self.n, self.expires, self.uses_left, self.tools, self.label = len(ct), expires, uses_left, tools, label


class SecretVault:
    def __init__(self, clock: Callable[[], float] = time.monotonic, max_per_tenant: int = MAX_PER_TENANT, audit_size: int = 10000):
        master = secrets.token_bytes(32)
        self._k_enc = hmac.new(master, b"custos-enc", hashlib.sha256).digest()
        self._k_mac = hmac.new(master, b"custos-mac", hashlib.sha256).digest()
        del master
        self._clock = clock
        self._max_per_tenant = int(max_per_tenant)
        self._entries: Dict[str, _Entry] = {}
        self._per_tenant: Dict[str, int] = {}
        self._lock = threading.RLock()
        self._audit = deque(maxlen=int(audit_size))
        self._seq = 0
        self._closed = False

    # ------------------------------------------------------------ sealing
    def _stream(self, nonce: bytes, n: int) -> bytes:
        out = bytearray()
        i = 0
        while len(out) < n:
            out += hmac.new(self._k_enc, nonce + i.to_bytes(8, "big"), hashlib.sha256).digest()
            i += 1
        return bytes(out[:n])

    def _tag(self, aad: bytes, nonce: bytes, ct: bytes) -> bytes:
        return hmac.new(self._k_mac, len(aad).to_bytes(4, "big") + aad + nonce + ct, hashlib.sha256).digest()

    def _unseal(self, e: _Entry) -> bytearray:
        aad = e.tenant.encode() + b"\x00" + e.handle.encode()
        if not hmac.compare_digest(self._tag(aad, e.nonce, e.ct), e.tag):
            raise CustosError("CS-V-006", "sealed entry failed integrity check")
        ks = self._stream(e.nonce, e.n)
        return bytearray(a ^ b for a, b in zip(e.ct, ks))

    # ------------------------------------------------------------ internals
    def _log(self, kind, tenant, handle, tool, code=""):
        self._seq += 1
        self._audit.append((self._seq, kind, tenant, handle, tool, code))

    def _need_open(self):
        if self._closed:
            raise CustosError("CS-V-008")

    def _state(self, e: _Entry) -> str:
        if e.uses_left is not None and e.uses_left <= 0:
            return "exhausted"
        if e.expires is not None and self._clock() >= e.expires:
            return "expired"
        return "active"

    def _entry(self, tenant_id, handle, tool=None) -> _Entry:
        """Look up and authorise (tenant, tool). Raises; never consumes."""
        self._need_open()
        if not valid_tenant_id(tenant_id):
            raise CustosError("CS-V-006", "invalid tenant id")
        e = self._entries.get(handle) if type(handle) is str else None
        if e is None:
            self._log("resolve", tenant_id, "?", tool, "CS-V-001")
            raise CustosError("CS-V-001")
        if e.tenant != tenant_id:
            self._log("resolve", tenant_id, handle, tool, "CS-T-001")
            raise TenantIsolationError("handle belongs to a different tenant")
        st = self._state(e)
        if st != "active":
            code = "CS-V-002" if st == "expired" else "CS-V-003"
            self._log("resolve", tenant_id, handle, tool, code)
            raise CustosError(code)
        if e.tools is not None and (tool is None or tool not in e.tools):
            self._log("resolve", tenant_id, handle, tool, "CS-V-005")
            raise CustosError("CS-V-005")
        return e

    # ------------------------------------------------------------ public API
    def store(self, tenant_id: str, secret, *, ttl_seconds: Optional[float] = None, max_uses: Optional[int] = None,
              tools: Optional[Iterable[str]] = None, label: str = "") -> str:
        """Seal `secret` (str or bytes/bytearray; a bytearray is zeroed after sealing) and return its opaque handle."""
        with self._lock:
            self._need_open()
            if not valid_tenant_id(tenant_id):
                raise CustosError("CS-V-006", "invalid tenant id")
            wipe = secret if isinstance(secret, bytearray) else None
            if isinstance(secret, str):
                try:
                    raw = secret.encode("utf-8")
                except UnicodeEncodeError:
                    raise CustosError("CS-V-006", "secret is not encodable as UTF-8")
            elif isinstance(secret, (bytes, bytearray)):
                raw = bytes(secret)
            else:
                raise CustosError("CS-V-006", "secret must be str or bytes")
            if not MIN_SECRET_BYTES <= len(raw) <= MAX_SECRET_BYTES:
                raise CustosError("CS-V-006", f"secret length must be {MIN_SECRET_BYTES}..{MAX_SECRET_BYTES} bytes")
            if ttl_seconds is not None and (isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or not 0 < ttl_seconds < 10 ** 9 or ttl_seconds != ttl_seconds):
                raise CustosError("CS-V-006", "ttl_seconds must be a positive number")
            if max_uses is not None and (isinstance(max_uses, bool) or not isinstance(max_uses, int) or not 1 <= max_uses <= 10 ** 9):
                raise CustosError("CS-V-006", "max_uses must be a positive integer")
            tool_set = None
            if tools is not None:
                if isinstance(tools, str):
                    raise CustosError("CS-V-006", "tools must be a collection of names")
                tool_set = frozenset(tools)
                if not tool_set or not all(type(t) is str and _TOOL_RE.fullmatch(t) for t in tool_set):
                    raise CustosError("CS-V-006", "tools must be a non-empty collection of valid tool names")
            if type(label) is not str or len(label) > MAX_LABEL:
                raise CustosError("CS-V-006", "label must be a string up to 200 chars")
            if self._per_tenant.get(tenant_id, 0) >= self._max_per_tenant or len(self._entries) >= MAX_TOTAL:
                raise CustosError("CS-V-007")
            handle = new_handle()
            while handle in self._entries:
                handle = new_handle()
            nonce = secrets.token_bytes(16)
            ct = bytes(a ^ b for a, b in zip(raw, self._stream(nonce, len(raw))))
            tag = self._tag(tenant_id.encode() + b"\x00" + handle.encode(), nonce, ct)
            expires = None if ttl_seconds is None else self._clock() + float(ttl_seconds)
            self._entries[handle] = _Entry(tenant_id, handle, nonce, ct, tag, expires, max_uses, tool_set, label)
            self._per_tenant[tenant_id] = self._per_tenant.get(tenant_id, 0) + 1
            self._log("store", tenant_id, handle, None)
            if wipe is not None:
                wipe[:] = bytes(len(wipe))
            return handle

    def peek(self, tenant_id: str, handle: str, tool: Optional[str] = None) -> HandleInfo:
        """Validate that `handle` is usable by `tenant_id` for `tool` without consuming a use. Raises like `lease`."""
        with self._lock:
            return self._info(self._entry(tenant_id, handle, tool))

    def lease(self, tenant_id: str, handle: str, tool: Optional[str] = None) -> SecretLease:
        """Atomically authorise and CONSUME one invocation, then return a zero-on-exit plaintext lease."""
        with self._lock:
            e = self._entry(tenant_id, handle, tool)
            buf = self._unseal(e)
            if e.uses_left is not None:
                e.uses_left -= 1
            self._log("lease", tenant_id, handle, tool)
            return SecretLease(buf)

    def info(self, tenant_id: str, handle: str) -> HandleInfo:
        """Metadata for a handle of this tenant in any state (never the secret)."""
        with self._lock:
            self._need_open()
            e = self._entries.get(handle) if type(handle) is str else None
            if e is None:
                raise CustosError("CS-V-001")
            if e.tenant != tenant_id:
                raise TenantIsolationError("handle belongs to a different tenant")
            return self._info(e)

    def _info(self, e: _Entry) -> HandleInfo:
        rem = None if e.expires is None else max(0.0, e.expires - self._clock())
        return HandleInfo(e.handle, e.tenant, e.label, self._state(e), e.uses_left, rem, None if e.tools is None else tuple(sorted(e.tools)))

    def handles(self, tenant_id: str) -> List[str]:
        with self._lock:
            return sorted(h for h, e in self._entries.items() if e.tenant == tenant_id)

    def revoke(self, tenant_id: str, handle: str) -> bool:
        """Destroy a secret. False if the handle does not exist; TenantIsolationError if it belongs to someone else."""
        with self._lock:
            self._need_open()
            e = self._entries.get(handle) if type(handle) is str else None
            if e is None:
                return False
            if e.tenant != tenant_id:
                self._log("revoke", tenant_id, handle, None, "CS-T-001")
                raise TenantIsolationError("handle belongs to a different tenant")
            self._drop(e)
            self._log("revoke", tenant_id, handle, None)
            return True

    def revoke_tenant(self, tenant_id: str) -> int:
        with self._lock:
            self._need_open()
            doomed = [e for e in self._entries.values() if e.tenant == tenant_id]
            for e in doomed:
                self._drop(e)
            self._log("revoke_tenant", tenant_id, "*", None)
            return len(doomed)

    def purge(self) -> int:
        """Remove expired/exhausted entries (their sealed bytes are erased)."""
        with self._lock:
            doomed = [e for e in self._entries.values() if self._state(e) != "active"]
            for e in doomed:
                self._drop(e)
            return len(doomed)

    def _drop(self, e: _Entry):
        self._entries.pop(e.handle, None)
        self._per_tenant[e.tenant] = max(0, self._per_tenant.get(e.tenant, 1) - 1)
        e.ct = b""
        e.n = 0

    def scan_material(self, tenant_id: str) -> List[Tuple[str, bytearray]]:
        """INTERNAL (used by the scrubber): transient plaintexts of this tenant's secrets that are still stored. Caller MUST wipe the buffers."""
        with self._lock:
            self._need_open()
            return [(e.handle, self._unseal(e)) for e in self._entries.values() if e.tenant == tenant_id and e.n]

    def audit_log(self) -> List[tuple]:
        with self._lock:
            return list(self._audit)

    def close(self):
        """Erase everything and the sealing keys; the vault is unusable afterwards."""
        with self._lock:
            for e in list(self._entries.values()):
                self._drop(e)
            self._entries.clear()
            self._k_enc = self._k_mac = b"\x00" * 32
            self._closed = True

    def __len__(self):
        return len(self._entries)

    def __repr__(self):
        return f"<SecretVault entries={len(self._entries)} closed={self._closed}>"


def secret_variants(secret: bytes) -> List[bytes]:
    """Encodings of a secret that the scrubber also recognises (longest first)."""
    out = {secret,
           base64.b64encode(secret), base64.b64encode(secret).rstrip(b"="),
           base64.urlsafe_b64encode(secret), base64.urlsafe_b64encode(secret).rstrip(b"="),
           secret.hex().encode(), secret.hex().upper().encode()}
    from urllib.parse import quote_from_bytes
    out.add(quote_from_bytes(secret, safe="").encode())
    try:
        import json
        out.add(json.dumps(secret.decode("utf-8"))[1:-1].encode())
    except UnicodeDecodeError:
        pass
    return sorted((v for v in out if len(v) >= MIN_SECRET_BYTES), key=lambda v: (-len(v), v))
