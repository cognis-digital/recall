"""Smoke tests for RECALL. No network, no external deps."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recall import TOOL_NAME, TOOL_VERSION  # noqa: E402
from recall.cli import main  # noqa: E402
from recall.core import AuditLog, Vault, derive_key, relevant  # noqa: E402


class TestRecall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.vault = os.path.join(self.tmp, "t.vault")
        self.pw = "test-passphrase"

    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "recall")
        self.assertTrue(TOOL_VERSION)

    def test_encrypt_roundtrip_and_wrong_passphrase(self):
        v = Vault(self.vault, self.pw)
        v.add("WiFi", "home wifi password is hunter2", ["home"])
        v.add("Trading", "alpaca paper api key on the ssd", ["trading"])
        # reopen with correct passphrase -> docs present
        v2 = Vault(self.vault, self.pw)
        self.assertEqual(len(v2.documents()), 2)
        # wrong passphrase -> integrity/decrypt failure
        with self.assertRaises(ValueError):
            Vault(self.vault, "wrong-passphrase")

    def test_at_rest_is_not_plaintext(self):
        v = Vault(self.vault, self.pw)
        v.add("secret", "supersecretvalue12345", [])
        with open(self.vault, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"supersecretvalue12345", raw)

    def test_relevant_ranking(self):
        v = Vault(self.vault, self.pw)
        v.add("WiFi", "home wifi network password eero mesh", ["home"])
        v.add("Trading", "alpaca paper trading api key on samsung ssd", ["trading"])
        v.add("Doctor", "annual physical appointment bring insurance card", ["health"])
        res = relevant(self.vault, self.pw, "where is my trading api key", k=3)
        self.assertTrue(res)
        self.assertEqual(res[0]["title"], "Trading")
        self.assertGreater(res[0]["score"], 0)

    def test_audit_chain_integrity(self):
        v = Vault(self.vault, self.pw)
        v.add("a", "alpha document text", [])
        relevant(self.vault, self.pw, "alpha", k=1)
        log = AuditLog(self.vault + ".audit")
        self.assertTrue(log.verify())
        self.assertGreaterEqual(len(log.entries()), 2)
        # tamper: rewrite a detail field, chain must break
        with open(log.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        e = json.loads(lines[0])
        e["detail"]["title"] = "hacked"
        lines[0] = json.dumps(e, sort_keys=True) + "\n"
        with open(log.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        self.assertFalse(log.verify())

    def test_derive_key_deterministic(self):
        salt = b"0123456789abcdef"
        self.assertEqual(derive_key("pw", salt), derive_key("pw", salt))
        self.assertNotEqual(derive_key("pw", salt), derive_key("pw2", salt))

    def test_cli_version(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_cli_add_and_relevant_json(self):
        os.environ["RECALL_PASSPHRASE"] = self.pw
        rc = main(["--vault", self.vault, "add", "Note", "--text", "local rag privacy engine"])
        self.assertEqual(rc, 0)
        rc = main(["--vault", self.vault, "--format", "json", "relevant", "privacy engine"])
        self.assertEqual(rc, 0)
        # no matches -> non-zero exit
        rc = main(["--vault", self.vault, "relevant", "zzzznomatchquery"])
        self.assertEqual(rc, 1)
        del os.environ["RECALL_PASSPHRASE"]


if __name__ == "__main__":
    unittest.main()
