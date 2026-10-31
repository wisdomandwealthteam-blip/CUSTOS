# detgov 1.0.0 — deterministic governance gate (userspace Python package)

Authorization gate and compliance router for agent/tool calls. Pure Python ≥3.9, **zero dependencies** (Ed25519 verification is RFC 8032 pure Python).
Out of scope by design: kernel / eBPF / C / Rust runtimes (separate SOW) — this package is the policy, crypto and arbitration layer only.

```python
from detgov import Firewall, GovernanceViolation
fw = Firewall("policy.json", public_key_hex="<64 hex>", enforce_sig=True)   # refuses to start on a bad/missing signature
fw.register_handler("files.read", lambda params: {"data": read(params["path"])})
fw.execute("files.read", {"path": "/srv/a.txt"})            # dispatches, or raises GovernanceViolation(code, invariant, rationale)
tools = fw.sanitize_claude_tools(request_tools)             # strips server-side / non-allowlisted tools from Anthropic payloads
decls = fw.sanitize_gemini_tools(function_declarations)     # same for Google GenAI
```
CLI: `python -m detgov canon policy.json` (bytes to sign) · `verify POLICY PUBKEY [SIG]` · `check POLICY TOOL [PARAMS_JSON] [--pubkey HEX --enforce]`.

## Policy file (`policy.json`, `policy_version: 1`, unknown fields rejected)
`allowlist` (exact tool names), `revoked_entities`, `approved_endpoints` (origin `https://host[:port]` or bare host = https/443), `isrc_registry` {ISRC: sha256 hex}, `max_background_seconds` (int, default 300).
Signature: hex Ed25519 over `canonical_json_bytes(policy)` in `policy.json.sig` (sorted keys, `,`/`:` separators, UTF-8; **no floats** — use integers/strings). Formatting of the file on disk does not matter; duplicate keys and NaN are rejected. Sign offline: `python -m detgov canon policy.json > msg && openssl pkeyutl -sign -inkey key.pem -rawin -in msg | xxd -p -c256 > policy.json.sig`.

## Invariants and codes (checked in fixed order B, C, R, T, G; never relaxed by policy; allowlist last)
| Code | Invariant | Rejects |
|---|---|---|
| DG-B-001 | I_B | vendor-hosted tools: `llm.vendor.*`, `google_search*`, `hosted_*`, `web_search*`, `code_execution*`, `computer_use`, `vendor.*` |
| DG-B-002 | I_B | IPC / UNIX-domain escapes: `ipc.*`, `uds.*`, `dbus*`, `unix:` / `*.sock` / `/run/…` / `\\.\pipe\` values, socket-path keys |
| DG-B-003 | I_B | Luhn-valid unmasked PAN (13–19 digits, spaces/dashes/full-width ok) unless **every** destination (`endpoint`/`url`/`host`/…) is on `approved_endpoints`; no destination = deny |
| DG-C-001 | I_C | runtime schema/tool-description override and tool (re)registration (names and param keys) |
| DG-C-002 | I_C | revoked enterprise entities anywhere in params (boundary-aware, NFKC/casefold, zero-width stripped) |
| DG-C-003 / 004 | I_C | invalid ISRC / ISRC registered to different media (or no hash supplied for a registered ISRC) |
| DG-R-001 | I_R | `eval`, `compile`, `exec`, interpreters/REPLs, `run_python`, `execute_code`, eval-style param keys |
| DG-T-001 / 002 | I_T | cron/daemon/systemd/schedule names and keys; background/detach/persist without `max_runtime_seconds` ≤ policy limit |
| DG-G-001 | I_G | privilege escalation (`sudo`, `setuid`, `run_as: root`, `privileged`, `cap_add`, …) |
| DG-G-002 | I_G | process spawn (`fork`, `spawn`, `subprocess`, `os.system`, `os.exec*`, shells) |
| DG-G-003 / 004 | I_G | tool not on allowlist / malformed request (bad name, non-JSON or oversized/cyclic params) |
| DG-G-005 / 006 | I_G | no handler registered / handler returned a non-dict |
| DG-P-001/002/003 | I_P | invalid policy / signature failure / `enforce_sig` without a key |

`evaluate_request` never raises (anything unexpected → DG-G-004), rationales never echo parameter values, the firewall dispatches the **same validated deep copy** it checked, and the audit log stores names/codes only. Decisions are pure functions of (policy, name, params): verified identical across `PYTHONHASHSEED` values.

## Honest limits
- Heuristic name/key/value matching is a **deny-list on top of a deny-by-default allowlist**; the allowlist is the real boundary. A hostile handler you allowlist can still do anything its code does.
- PAN detection covers contiguous/separated digit runs in single values (not digits split across fields). Endpoint approval is string/URL-based, not DNS- or network-level.
- Ed25519 is verification-only, pure Python (≈10 ms/verify, not constant-time — public data only). Key distribution, rotation and revocation of the signing key are yours.
- This gate sees tool *requests*; it does not sandbox execution (that is the separate kernel/eBPF SOW).
- Thread-safe; no persistence.

## Verification
`PYTHONPATH=. python3 -m unittest discover -s tests -t .` — RFC 8032 vectors, cross-check against `cryptography` when installed, single-bit-flip tamper fuzz, TC-PROV-001…005, per-invariant evasion suites, ordering, hash-seed determinism, fuzz. `python3 tools_mutate.py detgov/core/*.py` for mutation testing.
