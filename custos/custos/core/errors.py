"""Formal Custos errors. Messages never contain secret material."""

CODES = {
    "CS-V-001": "unknown secret handle",
    "CS-V-002": "secret handle expired",
    "CS-V-003": "secret handle exhausted (invocation limit reached)",
    "CS-V-005": "secret handle not permitted for this tool",
    "CS-V-006": "invalid secret or vault argument",
    "CS-V-007": "vault capacity limit",
    "CS-V-008": "vault closed",
    "CS-T-001": "tenant isolation violation",
    "CS-T-002": "unknown tenant",
    "CS-T-003": "key rotation / policy reload failed (previous state retained)",
    "CS-T-004": "tenant already registered",
    "CS-G-001": "raw credential detected in request (leak policy: reject)",
    "CS-G-002": "tool handler failed",
    "CS-G-003": "handler result is not JSON-like",
    "CS-G-004": "handle used where it cannot be injected",
    "CS-G-005": "handler invoked outside the Custos gate",
}


class CustosError(Exception):
    def __init__(self, code: str, detail: str = ""):
        if code not in CODES:
            raise ValueError(f"unknown error code {code!r}")
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {CODES[code]}" + (f" ({detail})" if detail else ""))


class TenantIsolationError(CustosError):
    """A handle, key or resource belonging to one tenant was used under another tenant's context."""

    def __init__(self, detail: str = ""):
        super().__init__("CS-T-001", detail)


class HandlerError(CustosError):
    """A tool handler raised; `.detail` is the scrubbed exception text (type name + message)."""

    def __init__(self, detail: str = ""):
        super().__init__("CS-G-002", detail)
