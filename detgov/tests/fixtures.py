import hashlib
import json
import os
import tempfile

from detgov.core import crypto
from tests import ed25519_ref

SK = hashlib.sha256(b"detgov-test-signing-key").digest()
PK_HEX = ed25519_ref.public_key(SK).hex()
GOOD_HASH = hashlib.sha256(b"original master recording").hexdigest()
ISRC = "USRC17607839"

POLICY = {
    "policy_version": 1,
    "allowlist": ["directory.lookup", "telemetry.send", "media.register", "files.read", "report.render", "worker.run"],
    "revoked_entities": ["ACC-REVOKED-9821"],
    "approved_endpoints": ["https://telemetry.corp.example"],
    "isrc_registry": {ISRC: GOOD_HASH},
    "max_background_seconds": 300,
}


def write_policy(directory=None, policy=None, sign=True, key=SK):
    directory = directory or tempfile.mkdtemp(prefix="detgov-test-")
    path = os.path.join(directory, "policy.json")
    obj = POLICY if policy is None else policy
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)                         # deliberately NOT canonical on disk
    if sign:
        with open(path + ".sig", "w") as f:
            f.write(ed25519_ref.sign(key, crypto.canonical_json_bytes(obj)).hex() + "\n")
    return path
