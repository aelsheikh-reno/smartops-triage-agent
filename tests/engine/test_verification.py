"""Shared verification per product version (bank/contract/verification.yaml), with planted fixtures under tests/fixtures/.
Run: python3 -m unittest discover -s tests -t ."""
import copy
import os
import sys
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import bank as B  # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "shared_verification", "microsoft-defender-for-endpoint-10.8.yaml")
TABLE, ROW = "microsoft-defender-for-endpoint", "run_status.detectionstatus_prevented"
BANK = B.load()


def with_customer(version="10.8", sample_version="10.8", alerts=20, shared=True):
    b = copy.deepcopy(BANK)
    rec = yaml.safe_load(open(FIXTURE))
    b["shared_verifications"] = {(rec["product"], str(rec["version"])): rec} if shared else {}
    b["customers"]["t"] = {"products": {TABLE: version}, "verifications": [],
                           "sanity_samples": [{"product": TABLE, "product_version": sample_version, "alerts": alerts,
                                               "checked_by": "operator", "checked_on": "2026-10-17"}]}
    return b


class SharedVerification(unittest.TestCase):
    def test_matching_version_with_sanity_sample_is_checked(self):
        b = with_customer()
        self.assertTrue(B.row_verified(b, "t", TABLE, ROW, "2026-10-17"))
        v, trust, _ = B.row_answer(b, "run_status", "pre_execution", {"table": TABLE, "id": ROW, "kind": "unverified"}, ctx={"customer": "t", "today": "2026-10-17"})
        self.assertEqual(trust, "checked")

    def test_customer_on_another_version_is_not_checked(self):
        b = with_customer(version="10.9", sample_version="10.9")
        self.assertFalse(B.row_verified(b, "t", TABLE, ROW, "2026-10-17"))
        self.assertIn("no shared verification", B.shared_problems(b, "t", TABLE, ROW)[0])

    def test_sanity_sample_on_another_version_is_not_checked(self):
        b = with_customer(sample_version="10.7")
        self.assertFalse(B.row_verified(b, "t", TABLE, ROW, "2026-10-17"))

    def test_sanity_sample_too_small_is_not_checked(self):
        self.assertFalse(B.row_verified(with_customer(alerts=19), "t", TABLE, ROW, "2026-10-17"))

    def test_row_not_covered_is_not_checked(self):
        self.assertFalse(B.row_verified(with_customer(), "t", TABLE, "run_status.detectionstatus_blocked", "2026-10-17"))

    def test_no_shared_record_is_not_checked(self):
        self.assertFalse(B.row_verified(with_customer(shared=False), "t", TABLE, ROW, "2026-10-17"))


if __name__ == "__main__":
    unittest.main()
