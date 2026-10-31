# 1.0.0
Initial release: canonical JSON + pure-Python Ed25519 verify (strict: canonical encodings, S<L, small-order keys rejected), DetGovRouter (I_B/I_C/I_R/I_T/I_G), Firewall with Claude/Gemini payload sanitisers, CLI, conformance tests TC-PROV-001..005.
Hardening found while testing: full-match regexes (no trailing-newline bypass), strict `policy_version` int (bool rejected), canonical JSON rejects non-string keys and floats.
