# SAPTHA Student Portal

SAPTHA is the Sapthagiri NPS University student portal for announcements,
academic resources, library content, campus services, and coordinator-managed
content. The repository contains the static frontend and a Python HTTP API.
Firebase Realtime Database stores application records; Google Drive stores
course-resource files.

## Features

- Student and coordinator sign-in.
- Role-protected administration and coordinator tools.
- Announcements, events, placements, sports, hostel, canteen, HRD, DSA, and
  library content.
- Course subjects and modules organized in Google Drive.
- Coordinator file uploads and student file listing/download through
  authenticated backend endpoints.
- Admin approval and user management, including individual password
  provisioning.

## Project layout

- `index.html`, other page files, `style.css`, and `script.js`: browser UI.
- `server.py`: Python API, authentication/session handling, Firebase access,
  coordinator authorization, and Drive operations.
- `verify_drive_setup.py`: production Drive ownership, ACL, and hierarchy
  verification.
- `migrate_legacy_passwords.py`: guarded dry-run/apply migration for legacy
  password records.
- `migrate_module_files_to_drive.py`: guarded migration for legacy
  Base64-backed course files.
- `seed_admin.py`: administrative bootstrap utility.
- `tests/`: authentication, password-migration, authorization, and Drive
  hierarchy regression tests.
- `DRIVE_SETUP.md`: detailed Google Drive and production environment setup.
- `.vscode/tasks.json`: local frontend, API, and Drive verification tasks.

## Requirements

- Python 3.10 or newer (the project is tested with Python 3.13).
- Node.js for serving the static frontend locally and checking JavaScript.
- Firebase Admin service-account credentials for Firebase-backed API features.
- Google Drive API access for course hierarchy and file operations.

Install the Python dependencies:

```sh
python3 -m pip install -r requirements.txt
```

Keep credentials outside the repository. The VS Code API task sources
`$HOME/.config/saptha/drive.env`; see [DRIVE_SETUP.md](./DRIVE_SETUP.md) for
creating that file and configuring the Firebase service-account JSON.

## Run locally

The VS Code task **Run Saptha Portal** serves the static files at
`http://127.0.0.1:5173`. **Run Saptha Drive API** starts `server.py`, normally
at `http://127.0.0.1:8000`. The frontend uses the local API for localhost
origins.

Alternatively, from the repository root:

```sh
python3 server.py
```

The API defaults to binding on `127.0.0.1:8000`. Set `SAPTHA_HOST` and
`SAPTHA_PORT` when a different local or hosted bind address is required.

## Authentication and account security

- Login requires both the registered SRN and its correct non-empty password.
- Passwords are verified on the server using the project's scrypt password
  hash implementation. New account creation stores a hash, not plaintext.
- Sessions are bearer-token sessions. The server revalidates the account role
  and batch from the Firebase user record rather than trusting client-provided
  identity fields.
- Password and password-hash fields are removed from API responses.
- Students without a valid individual password cannot sign in. An
  administrator must verify the user's identity and provision an individual
  password; do not use a shared/default password or SRN-only login.
- Pending admin requests are approved by an existing administrator. New
  registrations store password hashes; the API migrates legacy pending
  plaintext password records transactionally before listing/approval.

Never remove the student password requirement without deploying and verifying
a secure replacement authentication method. SRN-only access permits identity
impersonation.

## Authorization and data access

- Coordinators may manage only their assigned content areas.
- Course subject/module creation and Drive uploads require the
  `course_coordinator` role.
- Student resource access is authorized using the authenticated server-side
  account and its batch.
- Students access course files through authenticated backend listing and
  download routes. Browser clients do not receive Drive credentials or direct
  Drive permissions.
- Library content is stored separately from the course-file Drive hierarchy.
- Production trusted origins must be explicit HTTPS origins. Wildcards are
  rejected.

## Google Drive model

Course files use the hierarchy:

```text
Drive root
└── Year
    └── Subject
        └── Module
            └── Uploaded files
```

Drive remains private to the approved server/owner identity. No student
Google Group is required, and files must never be made public or shared
directly with students. The backend authorizes access before proxying a
download.

Before deployment, run the verifier using the production environment:

```sh
python3 verify_drive_setup.py
```

It checks the configured root, every descendant's ACL, coordinator account
availability, and Firebase module-to-Drive folder mappings. A passing ACL
audit alone does not mean mapping verification passed: the verifier also
requires module records with matching Drive folders.

See [DRIVE_SETUP.md](./DRIVE_SETUP.md) for the full environment-variable
reference, OAuth setup, private ACL requirements, and migration procedures.

## Password migration

The legacy password migration utility performs a read-only preflight by
default. Review the affected account identifiers and fingerprint before
applying a migration. Apply requires the expected count and fingerprint
reported by that preflight:

```sh
python3 migrate_legacy_passwords.py
python3 migrate_legacy_passwords.py --apply \
  --expected-count <reviewed-count> \
  --expected-fingerprint <reviewed-fingerprint>
```

Do not put passwords, tokens, OAuth secrets, or service-account JSON files in
command arguments, logs, source files, or version control. For the separate
legacy course-file migration, review its dry run before using `--apply`:

```sh
python3 migrate_module_files_to_drive.py
```

## Tests and checks

Run the complete unit-test suite:

```sh
python3 -m unittest discover -s tests -q
```

Run syntax and patch checks:

```sh
python3 -m py_compile server.py verify_drive_setup.py
node --check script.js
git diff --check
```

The live Drive verifier requires valid Firebase and Drive configuration and
access to the configured production data. Do not create fake mappings or
weaken the verifier to obtain a passing result.

## Deployment status and prerequisites

The static frontend has previously been published on Vercel at
<https://sapthasnpsuportal.vercel.app/>. The Python API must also be deployed
to a production-capable host and routed from the frontend over HTTPS. A static
frontend deployment by itself does not provide the Python API. The deployed
API must expose the application's `/api` routes and return a successful
`GET /api/health` response.

Before production release, the deployment operator must:

1. Provision a host for the existing Python API; configure Python dependencies
   and a secure HTTPS reverse proxy or equivalent.
2. Configure `SAPTHA_ENVIRONMENT=production` and
   `SAPTHA_TRUSTED_ORIGINS` with the exact approved HTTPS frontend origin(s).
3. Configure the Firebase service-account path and Google Drive credentials
   through that host's secret manager. Do not commit credentials.
4. Configure the frontend API base or same-origin `/api` routing to point at
   the deployed backend.
5. Create genuine subject/module records using the Course Coordinator
   workflow, then run `verify_drive_setup.py` and confirm the full verifier
   reports `PASS`.
6. Confirm authentication, role authorization, student batch isolation,
   listing, upload, and download behavior against the deployed environment.

No student Google Group configuration is needed. Do not claim deployment
readiness while the production API is unavailable, the Drive mapping verifier
fails, or required production configuration is missing.
