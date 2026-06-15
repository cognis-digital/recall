"""Tests for hardened error handling and edge cases in RECALL."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recall.cli import main  # noqa: E402
from recall.core import AuditLog, Vault, derive_key, relevant  # noqa: E402


class TestHardenedEdgeCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.vault = os.path.join(self.tmp, "h.vault")
        self.pw = "hardening-test"

    # --- AuditLog robustness ---------------------------------------------

    def test_audit_log_entries_skips_malformed_json(self):
        """entries() must not crash on corrupt lines; it skips them."""
        log_path = os.path.join(self.tmp, "corrupt.audit")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("not valid json at all\n")
            f.write("{also: broken}\n")
        log = AuditLog(log_path)
        entries = log.entries()
        self.assertIsInstance(entries, list)
        self.assertEqual(len(entries), 0)

    def test_audit_log_verify_returns_false_on_malformed_json(self):
        """verify() must return False (not raise) when the log has bad JSON."""
        log_path = os.path.join(self.tmp, "bad.audit")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("this is not json\n")
        log = AuditLog(log_path)
        self.assertFalse(log.verify())

    def test_audit_log_append_works_after_partial_corruption(self):
        """_last_hash must skip corrupt lines so append() can still write."""
        log_path = os.path.join(self.tmp, "semi.audit")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("garbage line\n")
        log = AuditLog(log_path)
        h = log.append("test", {"x": 1})
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)

    # --- Vault._load robustness ------------------------------------------

    def test_vault_load_rejects_truncated_file(self):
        """A file shorter than the 20-byte header must raise ValueError."""
        with open(self.vault, "wb") as f:
            f.write(b"RCL")  # only 3 bytes
        with self.assertRaises(ValueError) as cm:
            Vault(self.vault, self.pw)
        self.assertIn("too short", str(cm.exception))

    def test_vault_load_rejects_wrong_magic(self):
        """A file with a wrong magic prefix must raise ValueError."""
        with open(self.vault, "wb") as f:
            f.write(b"BADM" + bytes(100))
        with self.assertRaises(ValueError) as cm:
            Vault(self.vault, self.pw)
        self.assertIn("not a RECALL vault file", str(cm.exception))

    # --- Vault.add validation --------------------------------------------

    def test_vault_add_rejects_empty_title(self):
        """add() must raise ValueError for an empty title."""
        v = Vault(self.vault, self.pw)
        with self.assertRaises(ValueError) as cm:
            v.add("", "some text")
        self.assertIn("title", str(cm.exception).lower())

    def test_vault_add_rejects_whitespace_only_title(self):
        """add() must reject a title that is only whitespace."""
        v = Vault(self.vault, self.pw)
        with self.assertRaises(ValueError):
            v.add("   ", "some text")

    # --- Vault.query / relevant k validation ----------------------------

    def test_query_rejects_k_zero(self):
        """query(k=0) must raise ValueError."""
        v = Vault(self.vault, self.pw)
        v.add("Doc", "some document text here", [])
        with self.assertRaises(ValueError) as cm:
            v.query("document", k=0)
        self.assertIn("k must be at least 1", str(cm.exception))

    def test_query_rejects_negative_k(self):
        """query(k=-1) must raise ValueError."""
        v = Vault(self.vault, self.pw)
        v.add("Doc", "some document text here", [])
        with self.assertRaises(ValueError):
            v.query("document", k=-1)

    def test_relevant_rejects_k_zero(self):
        """relevant() must raise ValueError for k=0."""
        v = Vault(self.vault, self.pw)
        v.add("Note", "relevant testing content", [])
        with self.assertRaises(ValueError):
            relevant(self.vault, self.pw, "testing", k=0)

    # --- Vault.save parent directory check ------------------------------

    def test_vault_save_raises_clear_error_for_missing_directory(self):
        """save() must raise OSError with a clear message when the vault
        directory does not exist."""
        missing_vault = os.path.join(self.tmp, "no_such_dir", "t.vault")
        v = Vault.__new__(Vault)
        v.path = missing_vault
        v.passphrase = self.pw
        v.audit = AuditLog(missing_vault + ".audit")
        v._docs = []
        salt = os.urandom(16)
        key = derive_key(self.pw, salt)
        v._salt = salt
        v._enc_key = key[:32]
        v._mac_key = key[32:]
        with self.assertRaises(OSError) as cm:
            v.save()
        self.assertIn("does not exist", str(cm.exception))

    # --- CLI file validation ---------------------------------------------

    def test_cli_add_file_not_found_exits_2(self):
        """--file pointing at a nonexistent path must exit with code 2."""
        os.environ["RECALL_PASSPHRASE"] = self.pw
        try:
            rc = main([
                "--vault", self.vault, "add", "Title",
                "--file", os.path.join(self.tmp, "nonexistent.txt"),
            ])
        finally:
            del os.environ["RECALL_PASSPHRASE"]
        self.assertEqual(rc, 2)

    def test_cli_relevant_k_zero_exits_nonzero(self):
        """CLI relevant -k 0 must exit non-zero (argparse rejects it)."""
        os.environ["RECALL_PASSPHRASE"] = self.pw
        try:
            rc = main(["--vault", self.vault, "relevant", "query", "-k", "0"])
            nonzero = rc != 0
        except SystemExit as e:
            nonzero = e.code != 0
        finally:
            del os.environ["RECALL_PASSPHRASE"]
        self.assertTrue(nonzero, "k=0 should produce a non-zero exit")

    def test_cli_add_no_text_no_file_exits_nonzero(self):
        """add with neither --text nor --file must exit non-zero."""
        os.environ["RECALL_PASSPHRASE"] = self.pw
        try:
            rc = main(["--vault", self.vault, "add", "SomeTitle"])
            nonzero = rc != 0
        except SystemExit as e:
            nonzero = bool(e.code)
        finally:
            del os.environ["RECALL_PASSPHRASE"]
        self.assertTrue(nonzero)


if __name__ == "__main__":
    unittest.main()
