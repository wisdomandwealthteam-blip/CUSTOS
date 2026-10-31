import hashlib
import json
import os
import tempfile

from detgov.core import crypto
from tests import ed25519_ref

SK_A = hashlib.sha256(b"custos-test-tenant-a").digest()
SK_B = hashlib.sha256(b"custos-test-tenant-b").digest()
SK_NEW = hashlib.sha256(b"custos-test-tenant-a-rotated").digest()
PK_A, PK_B, PK_NEW = (ed25519_ref.public_key(k).hex() for k in (SK_A, SK_B, SK_NEW))

POLICY = {"policy_version": 1, "allowlist": ["http.post", "db.query", "files.read", "report.render"], "revoked_entities": [], "approved_endpoints": [], "max_background_seconds": 300}


def write_policy(directory=None, policy=None, key=SK_A, sign=True, name="policy.json"):
    directory = directory or tempfile.mkdtemp(prefix="custos-test-")
    path = os.path.join(directory, name)
    obj = POLICY if policy is None else policy
    with open(path, "w") as f:
        json.dump(obj, f)
    if sign:
        with open(path + ".sig", "w") as f:
            f.write(ed25519_ref.sign(key, crypto.canonical_json_bytes(obj)).hex())
    return path
