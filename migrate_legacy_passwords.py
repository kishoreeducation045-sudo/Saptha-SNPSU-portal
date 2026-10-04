import argparse
import hashlib
import sys
from urllib.parse import quote

import server


def legacy_user_records(source):
    if source == "firebase":
        records = server.firebase_read("users") or {}
    else:
        records = server.read_db().get("users", {})
    return [
        (str(key), record)
        for key, record in server.firebase_record_items(records)
        if isinstance(record, dict) and "password" in record
    ]


def identifier_fingerprint(records):
    identifiers = sorted(key for key, _ in records)
    return hashlib.sha256("\n".join(identifiers).encode("utf-8")).hexdigest()


def prepare_migrations(records):
    prepared = []
    for key, record in records:
        migrated, changed = server.migrate_legacy_password_record(record)
        if not changed:
            raise RuntimeError(f"Legacy password disappeared for user {key} during preflight.")
        password = record.get("password")
        if password is None:
            password = ""
        prepared.append((key, dict(record), migrated, password))
    return prepared


def apply_firebase_migrations(prepared):
    database = server.firebase_db
    for key, snapshot, migrated, password in prepared:
        reference = database.reference(f"users/{quote(key, safe='')}")

        def migrate_if_unchanged(current):
            if current == snapshot:
                return migrated
            if isinstance(current, dict) and "password" not in current:
                return current
            raise RuntimeError(
                f"User {key} changed during migration; no update was applied to that record."
            )

        reference.transaction(migrate_if_unchanged)
        saved = reference.get()
        if not isinstance(saved, dict) or "password" in saved:
            raise RuntimeError(f"Password migration verification failed for user {key}.")
        if not server.verify_password(password, saved.get("password_hash")):
            raise RuntimeError(f"Password hash verification failed for user {key}.")
        if {field: value for field, value in saved.items() if field != "password_hash"} != {
            field: value for field, value in snapshot.items()
            if field not in {"password", "password_hash"}
        }:
            raise RuntimeError(f"Non-password account data changed for user {key}.")


def apply_local_migrations(prepared):
    data = server.read_db()
    users = data.get("users", {})
    for key, snapshot, _, _ in prepared:
        if users.get(key) != snapshot:
            raise RuntimeError(
                f"Local user {key} changed during migration; no records were changed."
            )
    for key, _, migrated, _ in prepared:
        users[key] = migrated
    server.write_db(data)

    saved_users = server.read_db().get("users", {})
    for key, snapshot, migrated, password in prepared:
        saved = saved_users.get(key)
        if not isinstance(saved, dict) or "password" in saved:
            raise RuntimeError(f"Password migration verification failed for local user {key}.")
        if not server.verify_password(password, saved.get("password_hash")):
            raise RuntimeError(f"Password hash verification failed for local user {key}.")
        if {field: value for field, value in saved.items() if field != "password_hash"} != {
            field: value for field, value in snapshot.items()
            if field not in {"password", "password_hash"}
        }:
            raise RuntimeError(f"Non-password account data changed for local user {key}.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Safely migrate legacy user passwords to the portal's scrypt hashes."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the migration. Without this flag, the command is read-only.",
    )
    parser.add_argument(
        "--source",
        choices=("firebase", "local-db"),
        default="firebase",
        help="Select Firebase users (default) or users in saptha_db.json.",
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        help="Required with --apply; abort unless this exact number of records is found.",
    )
    parser.add_argument(
        "--expected-fingerprint",
        help="Required with --apply; the account-ID fingerprint printed by the dry run.",
    )
    args = parser.parse_args(argv)

    if args.apply and (args.expected_count is None or not args.expected_fingerprint):
        parser.error("--apply requires both --expected-count and --expected-fingerprint.")
    if not args.apply and (args.expected_count is not None or args.expected_fingerprint):
        parser.error("Expected count and fingerprint are only accepted with --apply.")

    if args.source == "firebase":
        server.get_firebase_admin_app()
    records = legacy_user_records(args.source)
    print(f"Legacy plaintext-password records found: {len(records)}")
    for key, record in records:
        print(f"Account: {key}; role: {record.get('role', '<missing>')}")
    fingerprint = identifier_fingerprint(records)
    print(f"Account-ID fingerprint: {fingerprint}")

    if not args.apply:
        prepare_migrations(records)
        print(f"DRY RUN ONLY. No {args.source} records were changed.")
        return 0

    if len(records) != args.expected_count:
        raise RuntimeError(
            f"Expected {args.expected_count} legacy records but found {len(records)}; "
            "no records were changed."
        )
    if fingerprint != args.expected_fingerprint:
        raise RuntimeError(
            "The legacy account set differs from the reviewed dry run; no records were changed."
        )

    prepared = prepare_migrations(records)
    if args.source == "firebase":
        apply_firebase_migrations(prepared)
    else:
        apply_local_migrations(prepared)

    remaining = legacy_user_records(args.source)
    if remaining:
        raise RuntimeError(
            f"Migration incomplete: {len(remaining)} user records still contain plaintext passwords."
        )
    print(f"Successfully migrated and verified {len(prepared)} {args.source} user records.")
    print(f"No {args.source} user record contains a plaintext password field.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Password migration failed: {error}", file=sys.stderr)
        sys.exit(1)
