import hashlib
import json
import os
import random
import tempfile
import unittest

from detgov.core import crypto as C
from tests import ed25519_ref as REF
from tests.fixtures import PK_HEX, SK, write_policy

RFC = [  # RFC 8032 section 7.1 TEST 1-3
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


class Ed25519(unittest.TestCase):
    def test_rfc8032_vectors_verify_and_reproduce(self):
        for sk, pk, msg, sig in RFC[:2]:
            sk, pk, msg, sig = map(bytes.fromhex, (sk, pk, msg, sig))
            self.assertEqual(REF.public_key(sk), pk)
            self.assertEqual(REF.sign(sk, msg), sig)
            self.assertTrue(C.ed25519_verify(pk, msg, sig))

    def test_rfc8032_test3_with_derived_key(self):
        sk = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
        pk = REF.public_key(sk)
        msg = bytes.fromhex("af82")
        self.assertEqual(REF.sign(sk, msg).hex(),
                         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
        self.assertTrue(C.ed25519_verify(pk, msg, REF.sign(sk, msg)))

    def test_cross_check_with_cryptography_library_if_installed(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
        except Exception:
            self.skipTest("cryptography not installed")
        r = random.Random(1)
        for _ in range(40):
            seed = bytes(r.randrange(256) for _ in range(32))
            msg = bytes(r.randrange(256) for _ in range(r.randint(0, 300)))
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            pk = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            sig = priv.sign(msg)
            self.assertEqual(REF.public_key(seed), pk)
            self.assertEqual(REF.sign(seed, msg), sig)
            self.assertTrue(C.ed25519_verify(pk, msg, sig))
            bad = bytearray(sig)
            bad[r.randrange(64)] ^= 1 << r.randrange(8)
            self.assertFalse(C.ed25519_verify(pk, msg, bytes(bad)))

    def test_random_roundtrip_and_single_bit_flips(self):
        r = random.Random(2)
        for _ in range(25):
            sk = bytes(r.randrange(256) for _ in range(32))
            pk = REF.public_key(sk)
            msg = bytes(r.randrange(256) for _ in range(r.randint(0, 100)))
            sig = REF.sign(sk, msg)
            self.assertTrue(C.ed25519_verify(pk, msg, sig))
            for i in r.sample(range(512), 6):
                bad = bytearray(sig)
                bad[i // 8] ^= 1 << (i % 8)
                self.assertFalse(C.ed25519_verify(pk, msg, bytes(bad)), i)
            if msg:
                m2 = bytearray(msg)
                m2[r.randrange(len(m2))] ^= 1
                self.assertFalse(C.ed25519_verify(pk, bytes(m2), sig))
            self.assertFalse(C.ed25519_verify(REF.public_key(bytes(32)), msg, sig))

    def test_strictness(self):
        pk, msg = REF.public_key(SK), b"m"
        sig = REF.sign(SK, msg)
        s = int.from_bytes(sig[32:], "little")
        self.assertFalse(C.ed25519_verify(pk, msg, sig[:32] + (s + C._Q).to_bytes(32, "little")))      # malleable S
        for bad_sig in (b"", sig[:63], sig + b"\0", b"\0" * 64, b"\xff" * 64):
            self.assertFalse(C.ed25519_verify(pk, msg, bad_sig))
        for bad_pk in (b"", pk[:31], pk + b"\0", b"\xff" * 32, b"\0" * 32):
            self.assertFalse(C.ed25519_verify(bad_pk, msg, sig))
        identity = (1).to_bytes(32, "little")                                  # small-order public key (the identity point)
        forged = identity + bytes(32)
        self.assertFalse(C.ed25519_verify(identity, msg, forged))
        noncanon = (C._P + 1).to_bytes(32, "little")                          # y >= p
        self.assertFalse(C.ed25519_verify(noncanon, msg, sig))
        for junk in (None, 5, "x"):
            self.assertFalse(C.ed25519_verify(junk, msg, sig))

    def test_pubkey_hex_parsing(self):
        self.assertEqual(len(C.parse_public_key_hex(PK_HEX)), 32)
        for bad in (None, 5, "", PK_HEX[:-1], PK_HEX + "0", "zz" * 32, " " + PK_HEX, PK_HEX + "\n"):
            self.assertIsNone(C.parse_public_key_hex(bad))
        self.assertEqual(C.parse_public_key_hex(PK_HEX.upper()), bytes.fromhex(PK_HEX))


class Canonical(unittest.TestCase):
    def test_sorted_compact_utf8(self):
        self.assertEqual(C.canonical_json_bytes({"b": [1, {"z": None, "a": True}], "a": "é"}), '{"a":"é","b":[1,{"a":true,"z":null}]}'.encode("utf-8"))

    def test_key_order_does_not_matter(self):
        a = {"x": 1, "y": {"p": 1, "q": 2}}
        b = {"y": {"q": 2, "p": 1}, "x": 1}
        self.assertEqual(C.canonical_json_bytes(a), C.canonical_json_bytes(b))

    def test_rejections(self):
        for bad in (float("nan"), {"a": float("inf")}, {"a": 1.5}, {"a": {1, 2}}, {"a": b"x"}, {"a": "\ud800"}, {1: 2}):
            with self.assertRaises((ValueError, TypeError), msg=str(bad)):
                C.canonical_json_bytes(bad)

    def test_strict_loader(self):
        self.assertEqual(C.loads_strict(b'{"a": [1, 2]}'), {"a": [1, 2]})
        for bad in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"\xff", b"{", b"", b"[" * 100000):
            with self.assertRaises(C.StrictJSONError):
                C.loads_strict(bad)


class PolicySignature(unittest.TestCase):
    def test_valid_with_noncanonical_file_layout_and_default_sig_path(self):
        p = write_policy()
        self.assertTrue(C.verify_policy_signature(p, PK_HEX))
        self.assertTrue(C.verify_policy_signature(p, PK_HEX.upper()))

    def test_explicit_sig_path(self):
        p = write_policy()
        alt = p + ".copy"
        os.rename(p + ".sig", alt)
        self.assertFalse(C.verify_policy_signature(p, PK_HEX))
        self.assertTrue(C.verify_policy_signature(p, PK_HEX, alt))

    def test_every_tamper_is_rejected(self):
        p = write_policy()
        orig = open(p).read()
        sig = open(p + ".sig").read()
        mutations = [orig.replace("ACC-REVOKED-9821", "ACC-REVOKED-9822"), orig.replace('"policy_version": 1', '"policy_version": 2'),
                     orig.replace('"allowlist": [', '"allowlist": [\n    "os.fork",'), orig.replace("300", "301")]
        for m in mutations:
            self.assertNotEqual(m, orig)
            open(p, "w").write(m)
            self.assertFalse(C.verify_policy_signature(p, PK_HEX))
        open(p, "w").write(orig)
        self.assertTrue(C.verify_policy_signature(p, PK_HEX))
        wrong_key = REF.public_key(hashlib.sha256(b"other").digest()).hex()
        self.assertFalse(C.verify_policy_signature(p, wrong_key))
        for bad_sig in ("", "zz" * 64, sig.strip()[:-2], sig.strip() + "00", "0" * 128, "\x00"):
            open(p + ".sig", "w").write(bad_sig)
            self.assertFalse(C.verify_policy_signature(p, PK_HEX))

    def test_never_raises(self):
        for args in (("/nonexistent", PK_HEX), (None, PK_HEX), (5, 5), ("/nonexistent", None, "/also/missing")):
            self.assertIs(C.verify_policy_signature(*args), False)
        d = tempfile.mkdtemp()
        big = os.path.join(d, "big.json")
        open(big, "w").write(" " * (C.MAX_POLICY_BYTES + 1))
        open(big + ".sig", "w").write("0" * 128)
        self.assertFalse(C.verify_policy_signature(big, PK_HEX))
        dup = os.path.join(d, "dup.json")
        open(dup, "w").write('{"policy_version":1,"policy_version":1}')
        open(dup + ".sig", "w").write(REF.sign(SK, C.canonical_json_bytes({"policy_version": 1})).hex())
        self.assertFalse(C.verify_policy_signature(dup, PK_HEX))      # duplicate keys can never verify

    def test_signature_covers_content_not_formatting(self):
        p = write_policy()
        obj = json.load(open(p))
        json.dump(obj, open(p, "w"), separators=(",", ":"), sort_keys=True)     # reformat only
        self.assertTrue(C.verify_policy_signature(p, PK_HEX))


if __name__ == "__main__":
    unittest.main()
