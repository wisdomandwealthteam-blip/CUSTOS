# custos 1.0.0 — credential custody and zero-knowledge broker for DetGov-governed tool calls

Pure Python ≥3.9, standard library only (no kernel code, no subprocesses, no network). Depends only on the sibling stdlib-only package `detgov>=1.0.0`
(`SecretVault` and the scrubber work standalone; tenancy and the gate use DetGov).

```python
from custos import SecretVault, CustosGate, TenantRegistry, TenantIsolationError
vault, registry = SecretVault(), TenantRegistry()
gate = CustosGate(registry, vault)                                   # leak_policy="replace" (default) or "reject"
registry.register_tenant("acme", "policy.json", PUBLIC_KEY_HEX)      # signature REQUIRED (DetGov enforce_sig)
gate.register_handler("acme", "http.post", send_request)             # handler(params) -> dict
h = vault.store("acme", "sk_live_...", ttl_seconds=900, max_uses=20, tools=["http.post"])   # -> "cst_sec_<uuid4>"
gate.execute("acme", "http.post", {"url": "...", "headers": {"Authorization": f"Bearer {h}"}})
```
The agent only ever sees `h`. The handler receives the real credential at the final dispatch boundary; the return value reaches the caller with any echoed secret turned back into `h`.

## Guarantees (all covered by tests)
- **Handles**: `cst_sec_<uuid4>` from the OS CSPRNG (re-rolled if the string could be mistaken for a card number by DetGov's PAN rule). Unknown/malformed handles → `CS-V-001`.
- **Sealed at rest**: secrets live in memory as HMAC-SHA256-CTR ciphertext + HMAC tag bound to (tenant, handle); splicing/tampering fails closed. `repr`/audit/info never show plaintext.
- **Leases**: plaintext only inside a `SecretLease` (bytearray zeroed on close, read-only memoryview). A `bytearray` passed to `store()` is zeroed.
- **TTL / invocation limits / tool binding** per handle (monotonic clock, injectable). One use is consumed per distinct handle per dispatched call, atomically under a lock; DetGov denials and refused attempts consume nothing; a handler failure still consumes (fail closed).
- **Tenant isolation**: a handle used under another tenant raises `TenantIsolationError` (`CS-T-001`) from every API (lease, peek, info, revoke, gate) without consuming or revealing anything. Handlers, policies and keys are per tenant.
- **Key rotation**: `rotate_key` / `reload_policy` build and verify a complete new (router, firewall, keyset) state and swap one reference atomically; failure changes nothing; in-flight calls finish on their old state; optional grace window for the previous key; hooks (`on_rotate`) run after the swap and cannot break it. Tools no longer allowed by a tightened policy are dropped (fail closed, reported in `RotationResult.dropped_handlers`).
- **Gate**: inbound scrubbing (known secrets, incl. base64/hex/URL/JSON forms → handle; credential-shaped strings and sensitive keys → `[REDACTED:*]`), handle ownership check, DetGov evaluation on handle-only params, injection at dispatch, result/exception scrubbing, audit with handle-substituted params only. Handlers cannot be run outside the gate (`CS-G-005`).

## Honest limits
- **Not a process boundary.** Anyone who can run code in this process can read memory or call the vault. Python cannot guarantee that no stray copy of a secret exists (`lease.text()` and `inject="text"` hand the handler an immutable `str`; interpreter/GC copies). Use `inject="lease"` for wipeable buffers, and run untrusted agent code out-of-process with handles only.
- Sealing keys live in the same process: this protects against accidental disclosure (logs, repr, dumps of the entry table), not a memory-reading attacker.
- Scrubbing is pattern + known-secret based. Not detected: arbitrary transformations (rot13, splitting across fields), secrets < 8 bytes (refused at store), other tenants' raw secrets (pattern detection only, by design: no cross-tenant plaintext scanning).
- A handler you register can still exfiltrate what it is given; DetGov's allowlist and your handler code are the boundary. In-memory only: no persistence, HA or external KMS.
- `os.urandom` (via `secrets`/`uuid4`) is the only OS interaction.

## Verification
`PYTHONPATH=.:/path/to/detgov python3 -m unittest discover -s tests -t .` (needs `detgov` importable). Includes concurrency (use-count never exceeded; rotation under live traffic with zero errors), seeded fuzz, pathological-regex timing, and mutation testing (`MUT_PYTHONPATH=.:/path/to/detgov python3 tools_mutate.py custos/core/*.py`).
