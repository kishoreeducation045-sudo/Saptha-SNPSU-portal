# Google Drive Notes Setup

Google Drive owned by `saptha.snpsu@gmail.com` stores the actual module files. The portal is the source of truth for creating the Year / Subject / Module hierarchy: adding a subject or module in the portal creates or reuses the corresponding Drive folders and saves their IDs on the Firebase records. The portal lists Drive contents directly; note uploads do not read or write Firebase `module_files`. Firebase continues to provide users, roles, subjects, and modules.

## Server Configuration

The API task reads secrets from `$HOME/.config/saptha/drive.env`, outside the repository and frontend. Create it locally and restrict access:

```sh
mkdir -p "$HOME/.config/saptha"
chmod 700 "$HOME/.config/saptha"
nano "$HOME/.config/saptha/drive.env"
chmod 600 "$HOME/.config/saptha/drive.env"
```

Put these variables in that file, replacing placeholders. Never commit or send the file:

```sh
export SAPTHA_ENVIRONMENT='production'
export SAPTHA_TRUSTED_ORIGINS='https://REPLACE_WITH_PRODUCTION_PORTAL_ORIGIN'
export GOOGLE_OAUTH_CLIENT_ID='...'
export GOOGLE_OAUTH_CLIENT_SECRET='...'
export GOOGLE_OAUTH_REFRESH_TOKEN='...'
export GOOGLE_DRIVE_ROOT_FOLDER_ID='...'
export SAPTHA_FIREBASE_DATABASE_URL='https://saptha-college-default-rtdb.firebaseio.com'
export SAPTHA_FIREBASE_SERVICE_ACCOUNT_FILE="$HOME/.config/saptha/firebase/service-account.json"
export SAPTHA_HOST='127.0.0.1'
export SAPTHA_PORT='8000'
```

Do not leave either `REPLACE_WITH_...` value in production. Use the exact HTTPS origin of the deployed portal (scheme and host, plus a non-default port if applicable) for `SAPTHA_TRUSTED_ORIGINS`. Multiple approved origins may be comma-separated. Wildcards, paths, credentials, and non-HTTPS production origins are rejected. The application rejects API requests carrying an untrusted `Origin`; requests without an `Origin` remain usable for command-line/server clients but still require bearer authentication on protected routes.

No student Google Group is required. Drive is intentionally private to the configured server/owner identity; the verifier's explicit approved-principal allowlist is the existing `saptha.snpsu@gmail.com` Drive owner used by server OAuth. Students do not receive Drive permissions. Students list and download course files through SAPTHA's bearer-authenticated backend, which checks their server-side identity, module association, Drive parent, and batch before streaming file bytes. Never make Drive files public or grant students direct Drive access.

## Environment variable reference

Configure these values in the host's secret/environment-variable manager. Locally, the provided VS Code API task sources `$HOME/.config/saptha/drive.env`. The service-account JSON must remain outside the repository and be readable only by the server account.

| Variable | Required | Secret? | Purpose and behavior if missing |
| --- | --- | --- | --- |
| `SAPTHA_ENVIRONMENT` | Yes in production | No | Set to `production` to enable strict deployment validation. Defaults to `development`; any other value is rejected. |
| `SAPTHA_TRUSTED_ORIGINS` | Yes in production | No | Comma-separated exact approved HTTPS portal origins. Missing, malformed, wildcard, localhost, or HTTP values fail production startup. Development defaults to the local portal/API origins. |
| `GOOGLE_DRIVE_ROOT_FOLDER_ID` | Yes in production and for hierarchy/upload | No | Private Drive root used for course folders/files. Missing value fails production startup or the corresponding Drive operation. |
| `SAPTHA_FIREBASE_SERVICE_ACCOUNT_FILE` | Yes for Firebase operations | Path, not secret value | Path to the Firebase Admin service-account JSON. Defaults to `$HOME/.config/saptha/firebase/service-account.json`; a missing file prevents Firebase operations. Keep the JSON secret and outside source control. |
| `SAPTHA_FIREBASE_DATABASE_URL` | Required if not using the built-in project | No | Firebase Realtime Database URL. Defaults to the existing Saptha project URL in `server.py`. |
| `GOOGLE_OAUTH_CLIENT_ID` | Optional as a group | Sensitive configuration | Used with the client secret and refresh token for Drive API access. If any OAuth value is set, all three must be set; otherwise Google Application Default Credentials are used. |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Optional as a group | **Secret** | OAuth client secret; same all-or-none rule. |
| `GOOGLE_OAUTH_REFRESH_TOKEN` | Optional as a group | **Secret** | Drive owner's OAuth refresh token; same all-or-none rule. |
| `SAPTHA_HOST` | No | No | Bind address; defaults to `127.0.0.1`. Use a reverse proxy or an intentional deployment bind configuration for external traffic. |
| `SAPTHA_PORT` | No | No | API listen port; defaults to `8000`. The API task uses this configured value; choose an unused port if another local process already owns it. |

`SAPTHA_FIREBASE_AUTH_TOKEN` is not used by the portal backend. It is an optional server-side credential for the standalone legacy migration utility only; do not configure it for the live API unless that tool specifically needs it.

For local development, leave `SAPTHA_ENVIRONMENT` unset (or set it to `development`) and use the localhost allowlist defaults. If the local portal is served from another origin/port, add that exact local origin to `SAPTHA_TRUSTED_ORIGINS`; do not use `*`.

## Configure Google OAuth and Drive

1. In Google Cloud Console, select/create a project and enable **Google Drive API**.
2. Configure the OAuth consent screen. For the personal Gmail owner account, choose **External** and add `saptha.snpsu@gmail.com` as a test user while setting up.
3. Create an OAuth client ID of type **Web application** and add `https://developers.google.com/oauthplayground` as an authorized redirect URI.
4. Open OAuth 2.0 Playground settings, enable **Use your own OAuth credentials**, and enter that client ID and client secret. Request scope `https://www.googleapis.com/auth/drive`, authorize as `saptha.snpsu@gmail.com`, exchange the code, and copy the **refresh token**. This is not the Google account password. Store the client ID, client secret, and refresh token in the external `drive.env` file above.
5. In Drive, signed in as `saptha.snpsu@gmail.com`, create a root folder named `Saptha Portal`. Copy the folder ID from `https://drive.google.com/drive/folders/FOLDER_ID` into `GOOGLE_DRIVE_ROOT_FOLDER_ID`. Keep the root and all descendants private to the approved server/owner identity.
6. Install dependencies with `python3 -m pip install -r requirements.txt`. Start **Run Saptha Portal** and **Run Saptha Drive API**, then run **Verify Saptha Drive Setup**. Production verification must audit the ACL on the configured root and every descendant. It fails on public, domain-wide, student, or any other unapproved user/group permission, and also fails if Drive permissions or descendants cannot be fully inspected.

OAuth consent apps left in **Testing** can have refresh tokens expire after seven days. Production use requires publishing/configuring the consent app and completing any Google verification required for the Drive scope. Google Workspace sharing policies may block sharing from a personal Gmail account; if so, a Workspace admin must allow it or provide an institution-managed Drive owner.

The API creates or reuses `Year Engineering / Subject / Module / File` beneath the configured root. Coordinators create subjects from the existing semester page and modules from the subject page; no Year, Subject, or Module folders need to be created manually. Folder IDs are saved with the Firebase subject/module records and reused for uploads. The backend verifies the bearer session's exact `course_coordinator` role for hierarchy creation and uploads; the admin dashboard remains read-only for subject/module creation. The portal lists files directly from Drive, caches folder IDs for six hours and file listings for 60 seconds, and routes downloads through the authenticated API. Coordinators upload using the Drive owner's OAuth permission. Students do not receive direct Drive permissions; the portal API checks batch authorization before serving file bytes. Do not enable public link access.

After setting production origins, run the **Run Saptha Drive API** task. Production startup checks that the Drive root is private. Then run **Verify Saptha Drive Setup** (`python3 verify_drive_setup.py` from the repository with the same environment loaded). It audits the root and all nested folders/files, reports root and descendant ACL status plus any unauthorized permission, and exits nonzero for any ACL violation or missing module-to-Drive mapping. Remove all unapproved sharing grants before deployment. This audit is required because students access files only through backend authorization; no group permission or public link sharing is needed.

The API task sources `$HOME/.config/saptha/drive.env` and starts `server.py` using `SAPTHA_HOST` and `SAPTHA_PORT`. If the selected port is already listening, inspect the process before stopping it; for a parallel local verification instance, set `SAPTHA_PORT` to another unused port in that shell. Production startup must use `SAPTHA_ENVIRONMENT=production` and the exact HTTPS portal origin(s). No Google Group configuration is used or required.

## Migrate Legacy User Passwords

The migration uses the existing scrypt password hash and preserves each user's other fields. For Firebase, source the server environment and run the read-only preflight:

```sh
set -a
source "$HOME/.config/saptha/drive.env"
set +a
python3 migrate_legacy_passwords.py
```

Review the listed account identifiers and count; the dry run prints no password values and makes no Firebase changes. To apply, pass the exact count and account-ID fingerprint printed by that dry run:

```sh
python3 migrate_legacy_passwords.py --apply \
  --expected-count <reviewed-count> \
  --expected-fingerprint <reviewed-fingerprint>
```

The script aborts if the account set changed, preflights all passwords before writing, uses an RTDB transaction for each record, retains a valid existing hash where present, verifies each resulting hash, and confirms no user still has a `password` field. Never place plaintext passwords in command arguments or logs.

The same guarded utility can migrate legacy users in the local `saptha_db.json`. Stop the API first to avoid concurrent database writes, review its dry run, then apply only the exact reviewed account count and fingerprint:

```sh
python3 migrate_legacy_passwords.py --source local-db
python3 migrate_legacy_passwords.py --source local-db --apply \
  --expected-count <reviewed-count> \
  --expected-fingerprint <reviewed-fingerprint>
```

This mode does not contact Firebase and preserves the rest of the local database. Never place plaintext passwords in command arguments or logs.

## Student Password Provisioning

Student login requires a non-empty password that verifies against the student's server-side `password_hash` using the application's scrypt verifier. SRN alone is never sufficient. The server takes the account role and batch from the Firebase user record, creates a bearer session only after verification, and removes password fields from API responses.

Existing accounts without a valid hash cannot log in until an administrator has verified the student's identity and set an individual password. Do not assign a shared/default password or infer one from the SRN. In the admin dashboard's **Users** list, use **Set Password** for each verified student and deliver the password using the institution's approved secure channel. This admin-only operation is `POST /api/users/<SRN>/password` with `{"password":"<individual password>"}` over HTTPS. It hashes the password server-side, removes any legacy plaintext field, preserves the rest of the account record, and invalidates that user's existing sessions. Student account creation also requires an individual password; the API stores only its hash.

The latest October 2026 credential audit found 63 Firebase student records: 2 with structurally valid scrypt hashes and 61 without a valid hash; no student plaintext password fields were found. Hash format alone does not prove the student's password is known or usable. A separate local-database audit found 5 student records with no valid hash. Verify and provision each account individually before enabling student access. Never record passwords in tickets, terminal output, or application logs.

## Migrate Existing Base64 Files

Run a dry-run first, then apply after Drive and Firebase access are configured:

```sh
python3 migrate_module_files_to_drive.py
python3 migrate_module_files_to_drive.py --apply
```

The migration uploads each legacy Base64 record to the matching module folder, then replaces its Firebase payload with lightweight Drive metadata. It is safe to rerun after an interrupted migration. Firebase rules must allow the migration process to update those records, or set `SAPTHA_FIREBASE_AUTH_TOKEN` in the server environment. Do not use `--apply` until migration is explicitly approved.

Production must serve `/api` over HTTPS through a backend/reverse proxy; set `SAPTHA_HOST` and `SAPTHA_PORT` for the Python API host. Do not deploy the API with the default loopback binding for external users.