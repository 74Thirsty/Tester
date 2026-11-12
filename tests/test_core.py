import tempfile
import json
import unittest
from pathlib import Path
from tester import (TesterError, add_account, decrypt, encrypt, generate, make_account, find_account, backup_vault, restore_vault)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_encrypted_round_trip_and_wrong_password(self):
        record = make_account("Private", "private@example.com", "private@example.com", "secret", "", [], "")
        data = {"schema": 1, "accounts": [record]}
        encrypt(self.path, "a-long-test-password", data)
        self.assertEqual(decrypt(self.path, "a-long-test-password"), data)
        with self.assertRaises(TesterError):
            decrypt(self.path, "wrong-password")
        raw = self.path.read_text()
        self.assertNotIn("private@example.com", raw)
        self.assertNotIn("secret", raw)

    def test_create_will_not_overwrite(self):
        encrypt(self.path, "a-long-test-password", {"schema": 1, "accounts": []}, create=True)
        with self.assertRaises(TesterError):
            encrypt(self.path, "another-long-password", {"schema": 1, "accounts": []}, create=True)

    def test_generation(self):
        values = generate("test user", "example.com", 20, False)
        self.assertEqual(len(values), len(set(values)))
        self.assertTrue(all(x.endswith("@example.com") for x in values))
        alias = generate("test", "example.com", 1, True)[0]
        self.assertRegex(alias, r"^test\+[a-z0-9]{6}@example\.com$")
        for bad_domain in ("bad-domain", "a..example.com", "-bad.example.com", "bad_.example.com"):
            with self.subTest(domain=bad_domain), self.assertRaises(TesterError):
                generate("x", bad_domain, 1, False)
        with self.assertRaises(TesterError):
            generate("x" * 58, "example.com", 1, False)

    def test_account_operations(self):
        data = {"accounts": []}
        account = make_account("Example", "a@example.com", "", "secret", "", [], "")
        add_account(data, account)
        self.assertEqual(find_account(data, account["id"]), account)
        with self.assertRaises(TesterError):
            add_account(data, make_account("example", "a@example.com", "", "", "", [], ""))


    def test_create_does_not_clobber_existing_vault(self):
        self.path.write_text("keep me")
        with self.assertRaises(TesterError):
            encrypt(self.path, "a-long-test-password", {"schema": 1, "accounts": []}, create=True)
        self.assertEqual(self.path.read_text(), "keep me")

    def test_symlink_vault_is_rejected(self):
        target = Path(self.tmp.name) / "real.json"
        target.write_text("{}")
        link = Path(self.tmp.name) / "link.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are unavailable on this platform")
        with self.assertRaises(TesterError):
            decrypt(link, "password")
        with self.assertRaises(TesterError):
            encrypt(link, "password", {"schema": 1, "accounts": []})

    def test_invalid_crypto_metadata_and_schema_are_rejected(self):
        encrypt(self.path, "a-long-test-password", {"schema": 1, "accounts": []})
        box = __import__("json").loads(self.path.read_text())
        box["kdf"] = "untrusted"
        self.path.write_text(__import__("json").dumps(box))
        with self.assertRaises(TesterError):
            decrypt(self.path, "a-long-test-password")

    def test_sign_in_url_rejects_embedded_credentials(self):
        with self.assertRaises(TesterError):
            make_account("Example", "a@example.com", "", "", "https://user:pass@example.com/login", [], "")


    def test_encrypted_backup_and_restore(self):
        account = make_account("Example", "a@example.com", "", "secret", "", [], "")
        original = {"schema": 1, "accounts": [account]}
        encrypt(self.path, "a-long-test-password", original)
        backup = Path(self.tmp.name) / "backup.vault"
        backup_vault(self.path, backup, "a-long-test-password")
        restored = Path(self.tmp.name) / "restored.json"
        restore_vault(restored, backup, "a-long-test-password")
        self.assertEqual(decrypt(restored, "a-long-test-password"), original)
        with self.assertRaises(TesterError):
            restore_vault(restored, backup, "a-long-test-password")
        restore_vault(restored, backup, "a-long-test-password", force=True)
        with self.assertRaises(TesterError):
            backup_vault(self.path, backup, "a-long-test-password")

    def test_backup_rejects_wrong_password(self):
        encrypt(self.path, "a-long-test-password", {"schema": 1, "accounts": []})
        with self.assertRaises(TesterError):
            backup_vault(self.path, Path(self.tmp.name) / "bad.vault", "wrong-password")


if __name__ == "__main__":
    unittest.main()
