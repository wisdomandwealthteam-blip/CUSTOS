# Verification results

Verified on 2026-10-31 using Python 3.12.3, Node.js v26.12.1, and npm 11.20.0.
Python and TypeScript verification ran alongside each other.

| Suite | Passed | Failures | Errors | Skipped | Output |
| --- | ---: | ---: | ---: | ---: | --- |
| DetGov invariants, firewall runtime, policy signatures, and governance | 79 | 0 | 0 | 0 | [python-detgov.txt](python-detgov.txt) |
| CUSTOS credential/token gate runtime, vault, tenant isolation, and rotation | 81 | 0 | 0 | 0 | [python-custos.txt](python-custos.txt) |
| TypeScript governance and full agent pipeline | 25 | 0 | 0 | 0 | [typescript.txt](typescript.txt) |

`npm run build` also exited with status 0; see
[typescript-build.txt](typescript-build.txt). The Python suites emit existing
`ResourceWarning` messages for unclosed test fixture files; these are warnings,
not failures. Production sources and all DetGov files match the archives.
Only the `RAW` constants in CUSTOS's `test_scrub_middleware.py` and
`test_vault.py` differ: live-key-shaped literals were replaced with synthetic
test-key fixtures after GitHub push protection rejected the original values.
The fixtures still exercise the same Stripe-pattern scrubbing behavior.

## Setup

From the repository root, with `setuptools>=61` and `wheel` available:

```sh
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install --no-index --no-build-isolation ./detgov ./custos
.venv/bin/python -m pip install cryptography
npm install --no-package-lock --no-audit --no-fund
```

The local package install never queries PyPI (`--no-index`) and preserves
CUSTOS's declared `detgov>=1.0.0` requirement. Both installed distributions
resolve successfully from the repository root, with local directory origins
confirmed by their `direct_url.json` metadata. See
[python-install.txt](python-install.txt) and
[python-resolution.txt](python-resolution.txt).

`cryptography==50.0.2` was installed only to enable the optional Ed25519
cross-check; neither package gains a production dependency on it.

## Full suites

Run each Python suite in its own directory because both archives name their
test package `tests`.

```sh
(cd detgov && ../.venv/bin/python -m unittest discover -s tests -t . -v)
(cd custos && ../.venv/bin/python -m unittest discover -s tests -t . -v)
npm test
npm run build
```

These commands cover every Python `test_*.py` module in both archives and the
complete TypeScript suite. All 160 Python tests and 25 TypeScript tests passed,
including the optional crypto cross-check, with zero skips, failures, or errors.
