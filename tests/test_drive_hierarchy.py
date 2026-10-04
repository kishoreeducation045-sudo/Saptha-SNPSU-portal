import io
import json
import os
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import server
import verify_drive_setup


DEFAULT_USER = object()


class FakeHandler:
    def __init__(self, body=None, headers=None, user=DEFAULT_USER):
        self.body = body
        self.headers = headers or {}
        self.user = (
            {"srn": "24COORDINATOR", "role": "course_coordinator"}
            if user is DEFAULT_USER
            else user
        )
        self.rfile = io.BytesIO(body if isinstance(body, bytes) else b"")
        self.wfile = io.BytesIO()
        self.response = None
        self.response_status = None
        self.response_headers = {}

    def read_json(self):
        return self.body

    def require_user(self):
        if self.user is None:
            self.fail(401, "Unauthorized")
            return None
        return self.user

    def can_write_content(self, user, collection):
        return server.Handler.can_write_content(self, user, collection)

    def content_batch_for_user(self, user, parsed):
        return server.Handler.content_batch_for_user(self, user, parsed)

    def fail(self, status, detail):
        self.response = (status, {"detail": detail})
        return self.response

    def send_json(self, status, body, **kwargs):
        self.response = (status, body)
        return self.response

    def send_response(self, status):
        self.response_status = status

    def send_header(self, name, value):
        self.response_headers[name] = value

    def end_headers(self):
        pass


class DriveHierarchyTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "GOOGLE_DRIVE_ROOT_FOLDER_ID": "drive-root",
                "SAPTHA_FIREBASE_AUTH_TOKEN": "server-write-token",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.cache = dict(server.DRIVE_CACHE)
        server.DRIVE_CACHE.clear()
        self.addCleanup(server.DRIVE_CACHE.clear)
        self.addCleanup(server.DRIVE_CACHE.update, self.cache)

    def test_trusted_origins_normalize_allowlist_and_reject_wildcards(self):
        with patch.dict(
            os.environ,
            {"SAPTHA_TRUSTED_ORIGINS": "https://Portal.Example.edu/,https://api.example.edu"},
        ):
            self.assertEqual(
                server.trusted_origins_from_environment(),
                {"https://portal.example.edu", "https://api.example.edu"},
            )

        with patch.dict(os.environ, {"SAPTHA_TRUSTED_ORIGINS": "*"}):
            with self.assertRaisesRegex(ValueError, "allowlist"):
                server.trusted_origins_from_environment()

        with patch.dict(
            os.environ,
            {"SAPTHA_TRUSTED_ORIGINS": "https://*.example.edu"},
        ):
            with self.assertRaisesRegex(ValueError, "Wildcard hosts"):
                server.trusted_origins_from_environment()

        with patch.dict(os.environ, {"SAPTHA_TRUSTED_ORIGINS": "https://example.edu/path"}):
            with self.assertRaisesRegex(ValueError, "Origins must contain"):
                server.trusted_origins_from_environment()

    def test_migrated_password_hash_preserves_account_data_and_is_idempotent(self):
        original = {
            "srn": "24SUUBECS0001",
            "name": "Test Coordinator",
            "role": "course_coordinator",
            "batch": "2024",
            "password": "temporary-test-password",
        }

        migrated, changed = server.migrate_legacy_password_record(original)
        repeated, changed_again = server.migrate_legacy_password_record(migrated)

        self.assertTrue(changed)
        self.assertFalse(changed_again)
        self.assertNotIn("password", migrated)
        self.assertTrue(server.verify_password("temporary-test-password", migrated["password_hash"]))
        self.assertEqual(
            {key: value for key, value in migrated.items() if key != "password_hash"},
            {key: value for key, value in original.items() if key != "password"},
        )
        self.assertEqual(repeated, migrated)

    def test_json_responses_remove_nested_password_fields(self):
        handler = FakeHandler()

        server.Handler.send_json(
            handler,
            200,
            {
                "user": {
                    "name": "Test",
                    "password": "never-return-this",
                    "password_hash": "never-return-this-either",
                },
                "records": [{
                    "PasswordHash": "also-hidden",
                    "title": "Visible",
                    "url": "https://drive.google.com/file/d/private-id/view",
                }],
            },
        )

        response = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertEqual(
            response,
            {"user": {"name": "Test"}, "records": [{"title": "Visible", "url": ""}]},
        )

    def test_non_student_login_rejects_empty_password(self):
        handler = FakeHandler(
            {"srn": "24SUUBECS0001", "role": "course_coordinator", "password": ""}
        )

        with patch("server.read_db", return_value=server.empty_db()), patch(
            "server.firebase_read",
            return_value={
                "srn": "24SUUBECS0001",
                "role": "course_coordinator",
                "password_hash": server.hash_password(""),
            },
        ):
            result = server.Handler.login(handler)

        self.assertEqual(result[0], 401)

    def test_password_hash_login_succeeds_and_wrong_password_fails(self):
        password_hash = server.hash_password("temporary-test-password")
        account = {
            "srn": "24SUUBECS0001",
            "name": "Test Coordinator",
            "role": "course_coordinator",
            "password_hash": password_hash,
        }
        handler = FakeHandler({
            "srn": "24SUUBECS0001",
            "role": "course_coordinator",
            "password": "temporary-test-password",
        })

        with patch("server.read_db", return_value=server.empty_db()), patch(
            "server.firebase_read", return_value=account
        ), patch("server.firebase_write") as firebase_write, patch("server.write_db"):
            result = server.Handler.login(handler)

        self.assertEqual(result[0], 200)
        self.assertEqual(result[1]["role"], "course_coordinator")
        saved_account = firebase_write.call_args.args[1]
        self.assertEqual(saved_account["password_hash"], password_hash)
        self.assertNotIn("password", saved_account)

        invalid_handler = FakeHandler({
            "srn": "24SUUBECS0001",
            "role": "course_coordinator",
            "password": "wrong-test-password",
        })
        with patch("server.read_db", return_value=server.empty_db()), patch(
            "server.firebase_read", return_value=account
        ):
            invalid = server.Handler.login(invalid_handler)
        self.assertEqual(invalid[0], 401)

    def test_student_login_requires_verified_scrypt_credentials(self):
        account = {
            "srn": "24SUUBECS0001",
            "name": "Student A",
            "role": "student",
            "batch": "2024",
            "password_hash": server.hash_password("student-a-secret"),
        }
        cases = (
            ("valid password", {"password": "student-a-secret"}, 200),
            ("wrong password", {"password": "not-the-password"}, 401),
            ("empty password", {"password": ""}, 401),
            ("missing password", {}, 401),
        )

        for label, credential_fields, expected_status in cases:
            with self.subTest(case=label):
                body = {"srn": account["srn"], "role": "student", **credential_fields}
                handler = FakeHandler(body)
                with patch("server.read_db", return_value=server.empty_db()), patch(
                    "server.firebase_read", return_value=account
                ), patch("server.firebase_write") as firebase_write, patch(
                    "server.write_db"
                ) as write_db:
                    result = server.Handler.login(handler)

                self.assertEqual(result[0], expected_status)
                if expected_status == 200:
                    self.assertEqual(result[1]["srn"], account["srn"])
                    self.assertEqual(result[1]["role"], "student")
                    self.assertEqual(result[1]["batch"], "2024")
                    self.assertNotIn("password", result[1])
                    self.assertNotIn("password_hash", result[1])
                    write_db.assert_called_once()
                    firebase_write.assert_called_once()
                    forged_student = FakeHandler(user=result[1])
                    with patch("server.read_db", return_value=server.empty_db()):
                        denied_write = server.Handler.content(
                            forged_student,
                            "POST",
                            ["sports"],
                            urlparse(
                                "/api/content/sports?role=admin&"
                                "srn=25SUUBECS0002&batch=2025"
                            ),
                        )
                    self.assertEqual(denied_write[0], 403)
                else:
                    write_db.assert_not_called()
                    firebase_write.assert_not_called()

    def test_student_login_rejects_unknown_srn(self):
        handler = FakeHandler({
            "srn": "24SUUBECS9999",
            "role": "student",
            "password": "some-password",
        })
        with patch("server.read_db", return_value=server.empty_db()), patch(
            "server.firebase_read", return_value=None
        ), patch("server.write_db") as write_db:
            result = server.Handler.login(handler)

        self.assertEqual(result[0], 401)
        write_db.assert_not_called()

    def test_student_login_removes_stale_plaintext_when_hash_verifies(self):
        account = {
            "srn": "24SUUBECS0001",
            "name": "Student A",
            "role": "student",
            "batch": "2024",
            "password_hash": server.hash_password("student-a-secret"),
            "password": "legacy-value",
        }
        handler = FakeHandler({
            "srn": account["srn"],
            "role": "student",
            "password": "student-a-secret",
        })
        with patch("server.read_db", return_value=server.empty_db()), patch(
            "server.firebase_read", return_value=account
        ), patch("server.firebase_write") as firebase_write, patch("server.write_db"):
            result = server.Handler.login(handler)

        self.assertEqual(result[0], 200)
        self.assertNotIn("password", firebase_write.call_args.args[1])

    def test_student_login_never_authenticates_from_legacy_plaintext(self):
        account = {
            "srn": "24SUUBECS0001",
            "name": "Student A",
            "role": "student",
            "batch": "2024",
            "password": "legacy-plaintext",
        }
        handler = FakeHandler({
            "srn": account["srn"],
            "role": "student",
            "password": "legacy-plaintext",
        })
        with patch("server.read_db", return_value=server.empty_db()), patch(
            "server.firebase_read", return_value=account
        ), patch("server.firebase_write") as firebase_write, patch(
            "server.write_db"
        ) as write_db:
            result = server.Handler.login(handler)

        self.assertEqual(result[0], 401)
        firebase_write.assert_not_called()
        write_db.assert_not_called()

    def test_student_a_credentials_cannot_create_student_b_session(self):
        student_b = {
            "srn": "25SUUBECS0002",
            "name": "Student B",
            "role": "student",
            "batch": "2025",
            "password_hash": server.hash_password("student-b-secret"),
        }
        handler = FakeHandler({
            "srn": student_b["srn"],
            "role": "student",
            "password": "student-a-secret",
        })
        with patch("server.read_db", return_value=server.empty_db()), patch(
            "server.firebase_read", return_value=student_b
        ), patch("server.write_db") as write_db:
            result = server.Handler.login(handler)

        self.assertEqual(result[0], 401)
        write_db.assert_not_called()

    def test_student_session_uses_firebase_identity_not_forged_role_or_batch(self):
        account = {
            "srn": "24SUUBECS0001",
            "name": "Student A",
            "role": "student",
            "batch": "2024",
            "password_hash": server.hash_password("student-a-secret"),
        }
        handler = FakeHandler({
            "srn": "24SUUBECS0001",
            "role": "admin",
            "batch": "2099",
            "password": "student-a-secret",
        })
        with patch("server.read_db", return_value=server.empty_db()), patch(
            "server.firebase_read", return_value=account
        ), patch("server.firebase_write"), patch("server.write_db"):
            result = server.Handler.login(handler)

        self.assertEqual(result[0], 200)
        self.assertEqual(result[1]["srn"], "24SUUBECS0001")
        self.assertEqual(result[1]["role"], "student")
        self.assertEqual(result[1]["batch"], "2024")

    def test_student_batch_filter_ignores_forged_srn_and_batch_parameters(self):
        student_a = {"srn": "24SUUBECS0001", "role": "student", "batch": "2024"}
        forged_request = urlparse(
            "/api/content/subjects?srn=25SUUBECS0002&batch=2025&role=admin"
        )
        self.assertEqual(
            server.Handler.content_batch_for_user(FakeHandler(user=student_a), student_a, forged_request),
            "2024",
        )

    @patch("server.write_db")
    @patch(
        "server.firebase_read",
        return_value={
            "srn": "24SUUBECS0001",
            "name": "Student A",
            "role": "student",
            "batch": "2024",
            "password_hash": "not-returned",
        },
    )
    @patch(
        "server.read_db",
        return_value={
            "sessions": {
                "student-token": {
                    "token": "student-token",
                    "srn": "24SUUBECS0001",
                    "role": "student",
                    "batch": "2099",
                }
            }
        },
    )
    def test_restored_student_session_uses_firebase_identity(
        self, read_db, firebase_read, write_db
    ):
        handler = FakeHandler(headers={"Authorization": "Bearer student-token"})

        session = server.Handler.auth_user(handler)

        self.assertEqual(session["srn"], "24SUUBECS0001")
        self.assertEqual(session["role"], "student")
        self.assertEqual(session["batch"], "2024")
        self.assertNotIn("password_hash", session)
        write_db.assert_not_called()

    def test_student_cannot_write_coordinator_content(self):
        handler = FakeHandler(
            {"title": "Unauthorized test"},
            user={"srn": "24STUDENT", "role": "student", "batch": "2024"},
        )

        result = server.Handler.content(
            handler,
            "POST",
            ["sports"],
            urlparse("/api/content/sports"),
        )

        self.assertEqual(result[0], 403)

    def test_coordinator_content_roles_persist_and_are_student_visible(self):
        role_collections = {
            "hostel_coordinator": "hostel_info",
            "library_coordinator": "library",
            "sports_coordinator": "sports",
            "hrd_coordinator": "hrd_programs",
            "placement_coordinator": "placements",
            "canteen_coordinator": "canteen_info",
            "dsa_coordinator": "activity_announcements",
        }

        for role, collection in role_collections.items():
            with self.subTest(role=role):
                writes = []
                coordinator = FakeHandler(
                    {"title": "Role matrix test", "batch": "2024"},
                    user={"srn": "24COORDINATOR", "role": role},
                )
                with patch("server.read_db", return_value=server.empty_db()), patch(
                    "server.write_db", side_effect=writes.append
                ):
                    created = server.Handler.content(
                        coordinator,
                        "POST",
                        [collection],
                        urlparse(f"/api/content/{collection}"),
                    )
                    unrelated = server.Handler.content(
                        coordinator,
                        "POST",
                        ["contacts_list"],
                        urlparse("/api/content/contacts_list"),
                    )

                self.assertEqual(created[0], 200)
                self.assertEqual(len(writes), 1)
                persisted = writes[0]
                self.assertEqual(len(persisted["content"][collection]), 1)
                self.assertEqual(unrelated[0], 403)

                student = FakeHandler(
                    user={"srn": "24STUDENT", "role": "student", "batch": "2024"}
                )
                with patch("server.read_db", return_value=persisted):
                    visible = server.Handler.content(
                        student,
                        "GET",
                        [collection],
                        urlparse(f"/api/content/{collection}?batch=2099"),
                    )
                self.assertEqual(visible[0], 200)
                self.assertEqual(len(visible[1]), 1)

        course_coordinator = FakeHandler(
            {"title": "Unauthorized test"},
            user={"srn": "24COORDINATOR", "role": "course_coordinator"},
        )
        with patch("server.read_db", return_value=server.empty_db()):
            unrelated = server.Handler.content(
                course_coordinator,
                "POST",
                ["sports"],
                urlparse("/api/content/sports"),
            )
        self.assertEqual(unrelated[0], 403)

    @patch("server.invalidate_user_sessions")
    @patch("server.firebase_write")
    def test_admin_user_creation_hashes_password_and_redacts_response(
        self, firebase_write, invalidate_sessions
    ):
        handler = FakeHandler(
            {
                "srn": "24SUUBECS0001",
                "name": "Created User",
                "role": "course_coordinator",
                "password": "temporary-test-password",
            },
            user={"srn": "24ADMIN", "role": "admin"},
        )

        result = server.Handler.users_api(handler, "POST", [])

        saved_user = firebase_write.call_args.args[1]
        self.assertNotIn("password", saved_user)
        self.assertTrue(
            server.verify_password("temporary-test-password", saved_user["password_hash"])
        )
        self.assertNotIn("password", result[1]["data"])
        self.assertNotIn("password_hash", result[1]["data"])
        invalidate_sessions.assert_called_once_with("24SUUBECS0001")

    @patch("server.invalidate_user_sessions")
    @patch("server.firebase_write")
    @patch(
        "server.firebase_read",
        return_value={
            "srn": "24SUUBECS0001",
            "name": "Existing Student",
            "role": "student",
            "batch": "2024",
            "other_account_field": "preserved",
        },
    )
    def test_admin_student_password_reset_hashes_and_preserves_account(
        self, firebase_read, firebase_write, invalidate_sessions
    ):
        handler = FakeHandler(
            {"password": "new-individual-student-password"},
            user={"srn": "24ADMIN", "role": "admin"},
        )

        result = server.Handler.users_api(
            handler, "POST", ["24SUUBECS0001", "password"]
        )

        saved_user = firebase_write.call_args.args[1]
        self.assertEqual(result[0], 200)
        self.assertTrue(
            server.verify_password(
                "new-individual-student-password", saved_user["password_hash"]
            )
        )
        self.assertNotIn("password", saved_user)
        self.assertNotIn("password_hash", result[1]["data"])
        self.assertEqual(saved_user["name"], "Existing Student")
        self.assertEqual(saved_user["role"], "student")
        self.assertEqual(saved_user["batch"], "2024")
        self.assertEqual(saved_user["other_account_field"], "preserved")
        invalidate_sessions.assert_called_once_with("24SUUBECS0001")

    def test_admin_cannot_create_student_without_individual_password(self):
        handler = FakeHandler(
            {
                "srn": "24SUUBECS0001",
                "name": "Student",
                "role": "student",
            },
            user={"srn": "24ADMIN", "role": "admin"},
        )
        with patch("server.firebase_write") as firebase_write:
            result = server.Handler.users_api(handler, "POST", [])

        self.assertEqual(result[0], 400)
        firebase_write.assert_not_called()

    def test_non_admin_cannot_set_student_password(self):
        handler = FakeHandler(
            {"password": "not-authorized"},
            user={"srn": "24STUDENT", "role": "student", "batch": "2024"},
        )
        with patch("server.firebase_read") as firebase_read, patch(
            "server.firebase_write"
        ) as firebase_write:
            result = server.Handler.users_api(
                handler, "POST", ["24SUUBECS0001", "password"]
            )

        self.assertEqual(result[0], 403)
        firebase_read.assert_not_called()
        firebase_write.assert_not_called()

    def test_pending_admin_legacy_credential_migrates_to_scrypt_hash(self):
        pending = {
            "srn": "24SUUBECS0001",
            "name": "Pending User",
            "role": "pending_admin",
            "batch": "2024",
            "password": "individual-pending-password",
        }

        migrated = server.migrate_pending_admin_credential(pending)

        self.assertNotIn("password", migrated)
        self.assertTrue(
            server.verify_password(
                "individual-pending-password", migrated["password_hash"]
            )
        )
        for field in ("srn", "name", "role", "batch"):
            self.assertEqual(migrated[field], pending[field])
        self.assertIn("password", pending)

    @patch("server.firebase_db.reference")
    def test_pending_admin_migration_uses_idempotent_firebase_transaction(self, reference):
        pending_reference = Mock()
        reference.return_value = pending_reference
        record = {
            "srn": "24SUUBECS0001",
            "name": "Pending User",
            "password": "legacy-pending-password",
        }

        server.migrate_pending_admin_credentials({"pending-key": record})

        reference.assert_called_once_with("pending_admins/pending-key")
        migration = pending_reference.transaction.call_args.args[0]
        migrated = migration(record)
        migrated_again = migration(migrated)
        self.assertNotIn("password", migrated)
        self.assertEqual(migrated_again, migrated)
        self.assertTrue(
            server.verify_password(
                "legacy-pending-password", migrated["password_hash"]
            )
        )

    @patch("server.firebase_db.reference")
    @patch("server.firebase_read", side_effect=[None, {}])
    def test_admin_registration_stores_only_password_hash(
        self, firebase_read, reference
    ):
        pending_reference = Mock()
        reference.return_value = pending_reference
        handler = FakeHandler(
            {
                "name": "Pending Admin",
                "srn": "24SUUBECS0001",
                "password": "individual-admin-password",
            }
        )

        result = server.Handler.register_admin(handler)

        stored_record = pending_reference.push.call_args.args[0]
        self.assertEqual(result[0], 200)
        self.assertNotIn("password", stored_record)
        self.assertTrue(
            server.verify_password(
                "individual-admin-password", stored_record["password_hash"]
            )
        )
        self.assertNotIn("password", result[1])
        self.assertNotIn("password_hash", result[1])
        firebase_read.assert_any_call("pending_admins")

    @patch(
        "server.firebase_read",
        return_value={
            "pending-key": {
                "srn": "24SUUBECS0001",
                "name": "Pending User",
                "password_hash": "not-returned",
            }
        },
    )
    def test_pending_admin_list_is_admin_only_and_redacts_credentials(self, firebase_read):
        admin_handler = FakeHandler(user={"srn": "24ADMIN", "role": "admin"})

        result = server.Handler.pending_admins_api(admin_handler, "GET", [])

        self.assertNotIn("password_hash", result[1][0]["data"])
        student_handler = FakeHandler(
            user={"srn": "24STUDENT", "role": "student", "batch": "2024"}
        )
        denied = server.Handler.pending_admins_api(student_handler, "GET", [])
        self.assertEqual(denied[0], 403)

    @patch("server.invalidate_user_sessions")
    @patch("server.firebase_read", return_value=None)
    @patch("server.get_firebase_admin_app")
    @patch("server.firebase_db.reference")
    def test_admin_approval_creates_hash_only_user_and_invalidates_sessions(
        self, reference, get_app, firebase_read, invalidate_sessions
    ):
        pending_reference = Mock()
        pending_reference.get.return_value = {
            "srn": "24SUUBECS0001",
            "name": "Approved User",
            "password_hash": server.hash_password("temporary-test-password"),
        }
        reference.return_value = pending_reference
        handler = FakeHandler(
            {"id": "pending-key"},
            user={"srn": "24ADMIN", "role": "admin"},
        )

        result = server.Handler.approve_admin(handler)

        update_payload = pending_reference.update.call_args.args[0]
        saved_user = update_payload["users/24SUUBECS0001"]
        self.assertNotIn("password", saved_user)
        self.assertTrue(
            server.verify_password("temporary-test-password", saved_user["password_hash"])
        )
        self.assertNotIn("password_hash", result[1])
        self.assertEqual(result[0], 200)
        invalidate_sessions.assert_called_once_with("24SUUBECS0001")

    @patch("server.invalidate_user_sessions")
    @patch("server.firebase_read", return_value=None)
    @patch("server.get_firebase_admin_app")
    @patch("server.firebase_db.reference")
    def test_admin_approval_migrates_legacy_plaintext_and_removes_pending_record(
        self, reference, get_app, firebase_read, invalidate_sessions
    ):
        pending_reference = Mock()
        pending_reference.get.return_value = {
            "srn": "24SUUBECS0001",
            "name": "Approved User",
            "password": "legacy-pending-password",
        }
        reference.return_value = pending_reference
        handler = FakeHandler(
            {"id": "pending-key"},
            user={"srn": "24ADMIN", "role": "admin"},
        )

        result = server.Handler.approve_admin(handler)

        update_payload = pending_reference.update.call_args.args[0]
        saved_user = update_payload["users/24SUUBECS0001"]
        self.assertNotIn("password", saved_user)
        self.assertTrue(
            server.verify_password(
                "legacy-pending-password", saved_user["password_hash"]
            )
        )
        self.assertIsNone(update_payload["pending_admins/pending-key"])
        self.assertNotIn("password", result[1])
        self.assertNotIn("password_hash", result[1])
        self.assertEqual(result[0], 200)
        invalidate_sessions.assert_called_once_with("24SUUBECS0001")

    def test_production_does_not_require_student_group_and_requires_https_origins(self):
        with patch.dict(
            os.environ,
            {
                "SAPTHA_ENVIRONMENT": "production",
                "SAPTHA_TRUSTED_ORIGINS": "https://portal.example.edu",
                "GOOGLE_DRIVE_ROOT_FOLDER_ID": "drive-root",
            },
            clear=True,
        ):
            with patch.object(
                server, "FIREBASE_SERVICE_ACCOUNT_FILE", server.BASE_DIR / "server.py"
            ):
                server.validate_production_configuration()

        with patch.dict(
            os.environ,
            {
                "SAPTHA_ENVIRONMENT": "production",
                "SAPTHA_TRUSTED_ORIGINS": "http://portal.example.edu",
                "GOOGLE_DRIVE_ROOT_FOLDER_ID": "drive-root",
            },
            clear=True,
        ):
            with patch.object(
                server, "FIREBASE_SERVICE_ACCOUNT_FILE", server.BASE_DIR / "server.py"
            ), self.assertRaisesRegex(RuntimeError, "must use HTTPS"):
                server.validate_production_configuration()

    def test_production_rejects_wildcard_trusted_origins_without_group_configuration(self):
        with patch.dict(
            os.environ,
            {
                "SAPTHA_ENVIRONMENT": "production",
                "SAPTHA_TRUSTED_ORIGINS": "*",
                "GOOGLE_DRIVE_ROOT_FOLDER_ID": "drive-root",
            },
        ), patch.object(
            server, "FIREBASE_SERVICE_ACCOUNT_FILE", server.BASE_DIR / "server.py"
        ), self.assertRaisesRegex(ValueError, "allowlist"):
            server.validate_production_configuration()

    def test_private_drive_acl_accepts_approved_owner(self):
        service = Mock()
        service.permissions.return_value.list.return_value.execute.return_value = {
            "permissions": [
                {
                    "id": "owner-permission",
                    "type": "user",
                    "emailAddress": server.EXPECTED_DRIVE_OWNER,
                    "role": "owner",
                }
            ],
        }

        self.assertTrue(server.verify_drive_resource_is_private(service, "drive-root"))

    def test_private_drive_acl_rejects_public_domain_and_unapproved_principals(self):
        permissions = [
            {"type": "anyone", "role": "reader"},
            {"type": "domain", "domain": "example.edu", "role": "reader"},
            {"type": "user", "emailAddress": "student@example.edu", "role": "reader"},
            {"type": "group", "emailAddress": "staff@example.edu", "role": "reader"},
        ]
        for permission in permissions:
            with self.subTest(permission=permission):
                service = Mock()
                service.permissions.return_value.list.return_value.execute.return_value = {
                    "permissions": [permission],
                }
                with self.assertRaisesRegex(
                    RuntimeError, "unauthorized permissions"
                ):
                    server.verify_drive_resource_is_private(service, "drive-root")

    def test_drive_tree_acl_audit_checks_descendants(self):
        service = Mock()
        service.files.return_value.list.side_effect = lambda **kwargs: Mock(
            execute=Mock(
                return_value={
                    "files": (
                        [{
                            "id": "subject",
                            "name": "Subject",
                            "mimeType": server.DRIVE_FOLDER_MIME_TYPE,
                        }]
                        if "'root' in parents" in kwargs["q"]
                        else [{"id": "note", "name": "note.pdf", "mimeType": "application/pdf"}]
                        if "'subject' in parents" in kwargs["q"]
                        else []
                    )
                }
            )
        )

        def permission_list(**kwargs):
            file_id = kwargs["fileId"]
            permission = (
                {
                    "type": "user",
                    "emailAddress": server.EXPECTED_DRIVE_OWNER,
                    "role": "owner",
                }
                if file_id in {"root", "subject"}
                else {
                    "type": "anyone",
                    "role": "reader",
                }
            )
            return Mock(execute=Mock(return_value={"permissions": [permission]}))

        service.permissions.return_value.list.side_effect = permission_list
        root_permissions, descendants = verify_drive_setup.audit_drive_tree(
            service, "root"
        )

        self.assertEqual(root_permissions, [])
        self.assertEqual([child["id"] for child, _ in descendants], ["subject", "note"])
        self.assertEqual(descendants[0][1], [])
        self.assertEqual(descendants[1][1][0]["type"], "anyone")

    def test_untrusted_request_origin_is_rejected(self):
        handler = FakeHandler(headers={"Origin": "https://attacker.example"})

        with patch("server.TRUSTED_ORIGINS", {"https://portal.example.edu"}):
            self.assertFalse(server.Handler.request_origin_allowed(handler))

        handler.headers["Origin"] = "https://portal.example.edu/"
        with patch("server.TRUSTED_ORIGINS", {"https://portal.example.edu"}):
            self.assertTrue(server.Handler.request_origin_allowed(handler))

    def test_static_server_never_exposes_database_or_configuration_files(self):
        self.assertTrue(server.is_public_static_path("/index.html"))
        self.assertFalse(server.is_public_static_path("/saptha_db.json"))
        self.assertFalse(server.is_public_static_path("/.env"))
        self.assertFalse(server.is_public_static_path("/server.py"))
        self.assertFalse(server.is_public_static_path("/../outside.html"))

    @patch("server.write_db")
    @patch(
        "server.firebase_read",
        return_value={"role": "student"},
    )
    @patch(
        "server.read_db",
        return_value={
            "sessions": {
                "stale-token": {
                    "token": "stale-token",
                    "srn": "24COORDINATOR",
                    "role": "course_coordinator",
                }
            }
        },
    )
    def test_session_is_revoked_when_firebase_role_changes(
        self, read_db, firebase_read, write_db
    ):
        handler = FakeHandler(headers={"Authorization": "Bearer stale-token"})

        user = server.Handler.auth_user(handler)

        self.assertIsNone(user)
        self.assertNotIn("stale-token", write_db.call_args.args[0]["sessions"])

    @patch("server.write_db")
    @patch(
        "server.read_db",
        return_value={"sessions": {"valid-token": {"role": "course_coordinator"}}},
    )
    def test_logout_invalidates_bearer_session(self, read_db, write_db):
        handler = FakeHandler(headers={"Authorization": "Bearer valid-token"})

        result = server.Handler.logout(handler)

        self.assertEqual(result, (200, {"ok": True}))
        self.assertNotIn("valid-token", write_db.call_args.args[0]["sessions"])
        restored = FakeHandler(headers={"Authorization": "Bearer valid-token"})
        self.assertIsNone(server.Handler.auth_user(restored))

    @patch("googleapiclient.http.MediaIoBaseDownload")
    @patch("server.get_drive_service")
    @patch(
        "server.firebase_find_record",
        return_value={
            "id": "module-key",
            "data": {
                "id": "module-key",
                "title": "Module 1",
                "batch": "2026",
                "driveFolderId": "module-folder",
            },
        },
    )
    def test_student_download_proxy_checks_batch_and_drive_parent(
        self, find_module, get_service, media_download
    ):
        service = Mock()
        get_service.return_value = service
        service.files.return_value.get.return_value.execute.return_value = {
            "id": "drive-file",
            "name": "notes.txt",
            "mimeType": "text/plain",
            "parents": ["module-folder"],
        }

        class FakeDownloader:
            def __init__(self, target, request):
                self.target = target

            def next_chunk(self):
                self.target.write(b"protected file content")
                return None, True

        media_download.side_effect = FakeDownloader
        handler = FakeHandler(
            user={"srn": "26STUDENT", "role": "student", "batch": "2026"}
        )

        server.Handler.download_drive_file(
            handler,
            urlparse("/api/drive/files/drive-file?moduleId=module-key"),
            "drive-file",
        )

        self.assertEqual(handler.response_status, 200)
        self.assertEqual(handler.wfile.getvalue(), b"protected file content")
        self.assertEqual(handler.response_headers["Cache-Control"], "private, no-store")
        self.assertNotIn("drive.google.com", handler.response_headers["Content-Disposition"])

        wrong_batch_handler = FakeHandler(
            user={"srn": "25STUDENT", "role": "student", "batch": "2025"}
        )
        server.Handler.download_drive_file(
            wrong_batch_handler,
            urlparse("/api/drive/files/drive-file?moduleId=module-key"),
            "drive-file",
        )
        self.assertEqual(wrong_batch_handler.response[0], 403)

    @patch("server.get_drive_service")
    @patch(
        "server.firebase_find_record",
        return_value={
            "id": "module-key",
            "data": {
                "id": "module-key",
                "title": "Module 1",
                "batch": "2026",
                "driveFolderId": "module-folder",
            },
        },
    )
    def test_student_download_proxy_rejects_file_outside_module_parent(
        self, find_module, get_service
    ):
        service = Mock()
        get_service.return_value = service
        service.files.return_value.get.return_value.execute.return_value = {
            "id": "drive-file",
            "name": "notes.txt",
            "mimeType": "text/plain",
            "parents": ["another-module-folder"],
        }
        handler = FakeHandler(
            user={"srn": "26STUDENT", "role": "student", "batch": "2026"}
        )

        result = server.Handler.download_drive_file(
            handler,
            urlparse("/api/drive/files/drive-file?moduleId=module-key"),
            "drive-file",
        )

        self.assertEqual(result[0], 404)

    def test_unauthenticated_student_cannot_download_drive_file(self):
        handler = FakeHandler(user=None)

        result = server.Handler.download_drive_file(
            handler,
            urlparse("/api/drive/files/drive-file?moduleId=module-key"),
            "drive-file",
        )

        self.assertIsNone(result)
        self.assertEqual(handler.response[0], 401)
    @patch("server.firebase_write")
    @patch("server.find_firebase_record", return_value=(None, None))
    @patch("server.ensure_drive_folder", side_effect=["year-id", "subject-id"])
    @patch("server.get_drive_service")
    def test_subject_creation_creates_year_and_subject_and_persists_ids(
        self, get_service, ensure_folder, find_record, write
    ):
        result = server.create_hierarchy_record(
            "subject",
            {
                "name": "Data Structures",
                "desc": "Algorithms course",
                "sem": "3",
                "branch": "CSE",
                "batch": "2025",
            },
        )

        self.assertTrue(result["created"])
        details = result["record"]["data"]
        self.assertEqual(details["driveYearFolderId"], "year-id")
        self.assertEqual(details["driveFolderId"], "subject-id")
        self.assertEqual(details["scope"], "CSE_3")
        self.assertEqual(ensure_folder.call_args_list[0].args[1:], (
            "2nd Year Engineering",
            "drive-root",
        ))
        self.assertEqual(ensure_folder.call_args_list[1].args[1:], (
            "Data Structures",
            "year-id",
        ))
        write.assert_called_once()

    @patch("server.firebase_write")
    @patch(
        "server.find_firebase_record",
        side_effect=[
            (
                "subject-key",
                {
                    "id": "subject-key",
                    "data": {
                        "id": "subject-key",
                        "name": "Data Structures",
                        "sem": "3",
                        "branch": "CSE",
                        "scope": "CSE_3",
                        "batch": "2025",
                    },
                },
            ),
            (None, None),
        ],
    )
    @patch(
        "server.ensure_drive_folder",
        side_effect=["year-id", "subject-folder-id", "module-folder-id"],
    )
    @patch("server.get_drive_service")
    def test_module_creation_validates_subject_and_saves_drive_folder_ids(
        self, get_service, ensure_folder, find_record, write
    ):
        result = server.create_hierarchy_record(
            "module",
            {
                "subjectId": "subject-key",
                "title": "Module 1",
                "desc": "Arrays",
                "sem": "3",
                "branch": "CSE",
                "batch": "2025",
            },
        )

        self.assertTrue(result["created"])
        details = result["record"]["data"]
        self.assertEqual(details["subjectId"], "subject-key")
        self.assertEqual(details["driveYearFolderId"], "year-id")
        self.assertEqual(details["driveSubjectFolderId"], "subject-folder-id")
        self.assertEqual(details["driveFolderId"], "module-folder-id")
        self.assertEqual(ensure_folder.call_args_list[2].args[1:], (
            "Module 1",
            "subject-folder-id",
        ))
        write.assert_called_once()

    @patch("server.firebase_write")
    @patch(
        "server.find_firebase_record",
        return_value=(
            "existing-key",
            {
                "id": "existing-key",
                "created_at": "earlier",
                "data": {
                    "name": "Data Structures",
                    "sem": "3",
                    "branch": "CSE",
                    "batch": "2025",
                },
            },
        ),
    )
    @patch("server.ensure_drive_folder", side_effect=["year-id", "subject-id"])
    @patch("server.get_drive_service")
    def test_repeated_subject_creation_reuses_firebase_record_and_drive_folders(
        self, get_service, ensure_folder, find_record, write
    ):
        result = server.create_hierarchy_record(
            "subject",
            {
                "name": "data structures",
                "sem": "3",
                "branch": "CSE",
                "batch": "2025",
            },
        )

        self.assertFalse(result["created"])
        self.assertEqual(result["record"]["id"], "existing-key")
        self.assertEqual(result["record"]["data"]["driveFolderId"], "subject-id")
        self.assertEqual(ensure_folder.call_count, 2)
        write.assert_called_once()

    @patch("server.firebase_write")
    @patch(
        "server.find_firebase_record",
        return_value=(
            "existing-key",
            {
                "id": "existing-key",
                "data": {
                    "name": "Data Structures",
                    "sem": "3",
                    "branch": "CSE",
                    "batch": "2025",
                    "driveFolderId": "existing-subject-folder",
                },
            },
        ),
    )
    @patch("server.drive_folder_id_under_parent", return_value="existing-subject-folder")
    @patch("server.ensure_drive_folder", return_value="year-id")
    @patch("server.get_drive_service")
    def test_subject_creation_reuses_stored_drive_folder_reference(
        self, get_service, ensure_folder, validate_folder, find_record, write
    ):
        result = server.create_hierarchy_record(
            "subject",
            {
                "name": "Data Structures",
                "sem": "3",
                "branch": "CSE",
                "batch": "2025",
            },
        )

        self.assertFalse(result["created"])
        self.assertEqual(result["record"]["data"]["driveFolderId"], "existing-subject-folder")
        validate_folder.assert_called_once_with(
            get_service.return_value, "existing-subject-folder", "year-id"
        )
        ensure_folder.assert_called_once_with(
            get_service.return_value, "2nd Year Engineering", "drive-root"
        )
        write.assert_called_once()

    @patch("server.firebase_write")
    @patch("server.ensure_drive_folder")
    @patch(
        "server.firebase_find_record",
        return_value={
            "id": "subject-key",
            "data": {"id": "subject-key", "name": "Data Structures"},
        },
    )
    @patch(
        "server.find_firebase_record",
        return_value=(
            "module-key",
            {
                "id": "module-key",
                "data": {
                    "id": "module-key",
                    "driveYearFolderId": "year-id",
                    "driveSubjectFolderId": "subject-folder",
                    "driveFolderId": "module-folder",
                    "subjectId": "subject-key",
                },
            },
        ),
    )
    @patch("server.get_drive_service")
    def test_upload_resolves_and_reuses_the_stored_module_folder(
        self, get_service, module_record, find_record, ensure_folder, write
    ):
        service = Mock()
        get_service.return_value = service
        ensure_folder.return_value = "year-id"
        service.files.return_value.get.return_value.execute.side_effect = [
            {"id": "subject-folder", "mimeType": server.DRIVE_FOLDER_MIME_TYPE, "parents": ["year-id"]},
            {"id": "module-folder", "mimeType": server.DRIVE_FOLDER_MIME_TYPE, "parents": ["subject-folder"]},
        ]
        find_record.return_value = {
            "id": "subject-key",
            "data": {"id": "subject-key", "name": "Data Structures"},
        }

        folder_id = server.resolve_upload_module_folder(
            service,
            "module-key",
            {
                "subjectId": "subject-key",
                "subject": "Data Structures",
                "title": "Module 1",
                "driveYearFolderId": "year-id",
                "driveSubjectFolderId": "subject-folder",
                "driveFolderId": "module-folder",
            },
            3,
        )

        self.assertEqual(folder_id, "module-folder")
        ensure_folder.assert_called_once_with(
            service, "2nd Year Engineering", "drive-root"
        )
        write.assert_not_called()

    def test_student_cannot_create_subject_or_module(self):
        for kind in ("subject", "module"):
            handler = FakeHandler(
                {"record": {}},
                user={"srn": "24STUDENT", "role": "student"},
            )
            server.Handler.create_drive_hierarchy(handler, kind)
            self.assertEqual(handler.response[0], 403)

    def test_other_coordinators_cannot_create_course_resources_or_upload(self):
        roles = (
            "hostel_coordinator",
            "library_coordinator",
            "sports_coordinator",
            "hrd_coordinator",
            "placement_coordinator",
            "canteen_coordinator",
            "dsa_coordinator",
        )
        for role in roles:
            with self.subTest(role=role):
                handler = FakeHandler(
                    {"record": {}},
                    user={"srn": "24COORDINATOR", "role": role},
                )
                result = server.Handler.create_drive_hierarchy(handler, "subject")
                self.assertEqual(result[0], 403)

                upload_handler = FakeHandler(
                    user={"srn": "24COORDINATOR", "role": role}
                )
                upload = server.Handler.upload_drive_file(upload_handler)
                self.assertEqual(upload[0], 403)

    @patch(
        "server.create_hierarchy_record",
        return_value={"created": True, "record": {"id": "subject-id"}},
    )
    def test_course_coordinator_can_create_via_protected_endpoint(
        self, create
    ):
        handler = FakeHandler({
            "record": {"name": "Data Structures"},
        })

        server.Handler.create_drive_hierarchy(handler, "subject")

        self.assertEqual(handler.response, (201, {"id": "subject-id"}))
        create.assert_called_once_with("subject", {"name": "Data Structures"})

    def test_missing_session_cannot_create_subject_or_module(self):
        for kind in ("subject", "module"):
            handler = FakeHandler({"record": {}}, user=None)
            server.Handler.create_drive_hierarchy(handler, kind)
            self.assertEqual(handler.response[0], 401)

    def test_generic_content_endpoint_cannot_bypass_hierarchy_creation(self):
        for collection in ("subjects", "modules", "module_files"):
            handler = FakeHandler()
            result = server.Handler.content(handler, "POST", [collection], None)
            self.assertEqual(result[0], 403)

    @patch(
        "server.firebase_read",
        side_effect=[
            {
                "subject-key": {
                    "id": "subject-key",
                    "data": {"name": "Test Subject", "scope": "CSE_8", "batch": "2026"},
                }
            },
            {
                "module-key": {
                    "id": "module-key",
                    "data": {
                        "title": "Test Module",
                        "scope": "CSE_8_Test Subject",
                        "batch": "2026",
                    },
                }
            },
        ],
    )
    @patch("server.read_db", return_value=server.empty_db())
    def test_academic_content_get_reads_firebase_hierarchy(
        self, read_db, firebase_read
    ):
        handler = FakeHandler(user={"srn": "26STUDENT", "role": "student", "batch": "2026"})
        handler.content_batch_for_user = lambda user, parsed: (
            server.Handler.content_batch_for_user(handler, user, parsed)
        )

        subject_status, subjects = server.Handler.content(
            handler,
            "GET",
            ["subjects"],
            urlparse("/api/content/subjects?scope=CSE_8&batch=2025"),
        )
        module_status, modules = server.Handler.content(
            handler,
            "GET",
            ["modules"],
            urlparse("/api/content/modules?scope=CSE_8_Test%20Subject&batch=2025"),
        )

        self.assertEqual(subject_status, 200)
        self.assertEqual([item["id"] for item in subjects], ["subject-key"])
        self.assertEqual(module_status, 200)
        self.assertEqual([item["id"] for item in modules], ["module-key"])
        self.assertEqual(firebase_read.call_args_list[0].args, ("subjects",))
        self.assertEqual(firebase_read.call_args_list[1].args, ("modules",))

    def test_student_cannot_upload_even_with_direct_api_request(self):
        boundary = "test-boundary"
        parts = [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"notes.pdf\"\r\nContent-Type: application/pdf\r\n\r\nPDF\r\n",
            f"--{boundary}--\r\n",
        ]
        body = "".join(parts).encode()
        handler = FakeHandler(
            body,
            {
                "Content-Length": str(len(body)),
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            user={"srn": "24STUDENT", "role": "student"},
        )
        handler.rfile = io.BytesIO(body)

        server.Handler.upload_drive_file(handler)

        self.assertEqual(handler.response[0], 403)

    def test_missing_session_cannot_upload(self):
        handler = FakeHandler(user=None)

        server.Handler.upload_drive_file(handler)

        self.assertEqual(handler.response[0], 401)


if __name__ == "__main__":
    unittest.main()
