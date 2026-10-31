"""python -m detgov canon POLICY            write canonical JSON bytes (the message to sign) to stdout
python -m detgov verify POLICY PUBKEY_HEX [SIG]   exit 0 valid / 1 invalid
python -m detgov check POLICY TOOL [PARAMS_JSON] [--pubkey HEX --enforce]   exit 0 allowed / 1 denied / 2 usage or policy error"""
import json
import sys

from .core import crypto
from .core.router import DetGovRouter, GovernanceViolation


def main(argv):
    try:
        if len(argv) >= 2 and argv[0] == "canon":
            obj = crypto.loads_strict(crypto.read_limited(argv[1], crypto.MAX_POLICY_BYTES))
            sys.stdout.buffer.write(crypto.canonical_json_bytes(obj))
            return 0
        if len(argv) in (3, 4) and argv[0] == "verify":
            ok = crypto.verify_policy_signature(argv[1], argv[2], argv[3] if len(argv) == 4 else None)
            print("VALID" if ok else "INVALID")
            return 0 if ok else 1
        if len(argv) >= 3 and argv[0] == "check":
            rest, pub, enforce, pos = argv[3:], None, False, []
            it = iter(rest)
            for a in it:
                if a == "--pubkey":
                    pub = next(it)
                elif a == "--enforce":
                    enforce = True
                else:
                    pos.append(a)
            params = crypto.loads_strict(pos[0].encode()) if pos else {}
            allowed, code, why = DetGovRouter(argv[1], pub, enforce).evaluate_request(argv[2], params)
            print("ALLOW" if allowed else f"DENY {code} {why}")
            return 0 if allowed else 1
    except (GovernanceViolation, OSError, ValueError, StopIteration, IndexError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
