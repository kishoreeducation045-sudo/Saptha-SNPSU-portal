import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import migrate_legacy_passwords
import server


class PasswordMigrationTests(unittest.TestCase):
    def test_dry_run_lists_identifiers_without_writing_passwords(self):
        records = {
            "24SUUBECS0001": {
                "srn": "24SUUBECS0001",
                "role": "course_coordinator",
                "password": "temporary-secret",
            }
        }
        output = io.StringIO()

        with patch("migrate_legacy_passwords.server.get_firebase_admin_app"), patch(
            "migrate_legacy_passwords.server.firebase_read",
            return_value=records,
        ), patch(
            "migrate_legacy_passwords.server.firebase_db.reference"
        ) as reference, contextlib.redirect_stdout(output):
            result = migrate_legacy_passwords.main([])

        self.assertEqual(result, 0)
        self.assertIn("24SUUBECS0001", output.getvalue())
        self.assertNotIn("temporary-secret", output.getvalue())
        reference.assert_not_called()

    def test_apply_requires_the_reviewed_count_and_fingerprint(self):
        record = {
            "srn": "24SUUBECS0001",
            "name": "Test Coordinator",
            "role": "course_coordinator",
            "batch": "2024",
            "password": "temporary-secret",
        }
        reference = Mock()

        def transact(update):
            reference.record = update(copy.deepcopy(record))

        reference.transaction.side_effect = transact
        reference.get.side_effect = lambda: reference.record
        output = io.StringIO()

        with patch("migrate_legacy_passwords.server.get_firebase_admin_app"), patch(
            "migrate_legacy_passwords.server.firebase_read",
            side_effect=[{"24SUUBECS0001": record}, {}],
        ), patch(
            "migrate_legacy_passwords.server.firebase_db.reference",
            return_value=reference,
        ), contextlib.redirect_stdout(output):
            result = migrate_legacy_passwords.main([
                "--apply",
                "--expected-count",
                "1",
                "--expected-fingerprint",
                migrate_legacy_passwords.identifier_fingerprint([
                    ("24SUUBECS0001", record),
                ]),
            ])

        self.assertEqual(result, 0)
        self.assertNotIn("password", reference.record)
        self.assertTrue(
            server.verify_password("temporary-secret", reference.record["password_hash"])
        )
        self.assertEqual(reference.record["name"], record["name"])
        self.assertEqual(reference.record["role"], record["role"])
        self.assertEqual(reference.record["batch"], record["batch"])
        self.assertNotIn("temporary-secret", output.getvalue())

    def test_apply_aborts_when_the_reviewed_account_set_changes(self):
        record = {
            "srn": "24SUUBECS0001",
            "role": "course_coordinator",
            "password": "temporary-secret",
        }
        reference = Mock()

        with patch("migrate_legacy_passwords.server.get_firebase_admin_app"), patch(
            "migrate_legacy_passwords.server.firebase_read",
            return_value={"24SUUBECS0001": record},
        ), patch(
            "migrate_legacy_passwords.server.firebase_db.reference",
            return_value=reference,
        ), self.assertRaisesRegex(RuntimeError, "account set differs"):
            migrate_legacy_passwords.main([
                "--apply",
                "--expected-count",
                "1",
                "--expected-fingerprint",
                "not-the-reviewed-fingerprint",
            ])

        reference.transaction.assert_not_called()

    def test_local_db_migration_hashes_password_and_preserves_other_data(self):
        record = {
            "srn": "24SUUBECS0001",
            "name": "Test Coordinator",
            "role": "course_coordinator",
            "batch": "2024",
            "password": "temporary-secret",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            db_file = Path(temp_dir) / "saptha_db.json"
            original = {
                "users": {"24SUUBECS0001": record},
                "sessions": {"session-id": {"srn": "24SUUBECS0001"}},
                "content": {"test_collection": [{"value": "preserved"}]},
            }
            db_file.write_text(json.dumps(original), encoding="utf-8")
            fingerprint = migrate_legacy_passwords.identifier_fingerprint([
                ("24SUUBECS0001", record),
            ])
            output = io.StringIO()

            with patch("migrate_legacy_passwords.server.DB_FILE", db_file), (
                contextlib.redirect_stdout(output)
            ):
                result = migrate_legacy_passwords.main([
                    "--source",
                    "local-db",
                    "--apply",
                    "--expected-count",
                    "1",
                    "--expected-fingerprint",
                    fingerprint,
                ])

            saved = json.loads(db_file.read_text(encoding="utf-8"))

        migrated = saved["users"]["24SUUBECS0001"]
        self.assertEqual(result, 0)
        self.assertNotIn("password", migrated)
        self.assertTrue(
            server.verify_password("temporary-secret", migrated["password_hash"])
        )
        self.assertEqual(migrated["name"], record["name"])
        self.assertEqual(migrated["role"], record["role"])
        self.assertEqual(migrated["batch"], record["batch"])
        self.assertEqual(saved["sessions"], original["sessions"])
        self.assertEqual(saved["content"]["test_collection"], original["content"]["test_collection"])
        self.assertNotIn("temporary-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
