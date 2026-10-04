import os
import re
import sys

from server import (
    APPROVED_DRIVE_PRINCIPALS,
    DRIVE_FOLDER_MIME_TYPE,
    EXPECTED_DRIVE_OWNER,
    FIREBASE_DATABASE_URL,
    audit_drive_resource_acl,
    firebase_read,
    firebase_record_items,
    find_drive_folder,
    get_drive_service,
    record_data,
    year_folder_name,
)


def audit_drive_tree(service, root_id):
    root_unauthorized = audit_drive_resource_acl(
        service,
        root_id,
        APPROVED_DRIVE_PRINCIPALS,
        require_approved_principal=True,
    )
    descendants = []
    pending = [root_id]
    visited = {root_id}

    while pending:
        parent_id = pending.pop()
        page_token = None
        while True:
            result = service.files().list(
                q=f"'{parent_id}' in parents and trashed = false",
                pageSize=1000,
                pageToken=page_token,
                fields="nextPageToken,files(id,name,mimeType,parents)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
            ).execute()
            for child in result.get("files", []):
                child_id = str(child.get("id") or "").strip()
                if not child_id:
                    raise RuntimeError(
                        f"Drive returned a descendant without an ID under {parent_id}."
                    )
                if child_id in visited:
                    continue
                visited.add(child_id)
                unauthorized = audit_drive_resource_acl(
                    service, child_id, APPROVED_DRIVE_PRINCIPALS
                )
                descendants.append((child, unauthorized))
                if child.get("mimeType") == DRIVE_FOLDER_MIME_TYPE:
                    pending.append(child_id)
            page_token = result.get("nextPageToken")
            if not page_token:
                break

    return root_unauthorized, descendants


def verify():
    root_id = os.getenv("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip()
    if not root_id:
        raise RuntimeError("GOOGLE_DRIVE_ROOT_FOLDER_ID is missing.")
    oauth_names = (
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
        "GOOGLE_OAUTH_REFRESH_TOKEN",
    )
    missing_oauth = [name for name in oauth_names if not os.getenv(name, "").strip()]
    if missing_oauth:
        raise RuntimeError(
            "Missing server-side Drive OAuth configuration: " + ", ".join(missing_oauth)
        )

    service = get_drive_service()
    account = service.about().get(fields="user(emailAddress)").execute()["user"]
    account_email = str(account.get("emailAddress", "")).lower()
    print(f"OAuth account: {account_email or 'unknown'}")
    if account_email != EXPECTED_DRIVE_OWNER:
        raise RuntimeError(f"OAuth must authorize {EXPECTED_DRIVE_OWNER}.")

    root = service.files().get(
        fileId=root_id,
        fields="id,name,mimeType,capabilities(canAddChildren,canListChildren)",
        supportsAllDrives=True,
    ).execute()
    if root.get("mimeType") != DRIVE_FOLDER_MIME_TYPE:
        raise RuntimeError("Configured Drive root ID is not a folder.")
    capabilities = root.get("capabilities", {})
    print(f"Root folder: {root.get('name')} ({root.get('id')})")
    print(f"Owner can list children: {bool(capabilities.get('canListChildren'))}")
    print(f"Owner can upload children: {bool(capabilities.get('canAddChildren'))}")
    if not capabilities.get("canListChildren") or not capabilities.get("canAddChildren"):
        raise RuntimeError("Drive owner lacks list or upload permission on the root folder.")

    root_unauthorized, descendants = audit_drive_tree(service, root_id)
    root_ok = not root_unauthorized
    descendants_ok = all(not permissions for _, permissions in descendants)
    print(f"Root ACL status: {'PASS' if root_ok else 'FAIL'}")
    print(
        f"Descendant ACL status: {'PASS' if descendants_ok else 'FAIL'} "
        f"({len(descendants)} descendants audited)"
    )
    unauthorized_count = len(root_unauthorized) + sum(
        len(permissions) for _, permissions in descendants
    )
    if unauthorized_count:
        print("Unauthorized permissions:")
        for permission in root_unauthorized:
            principal = (
                permission.get("emailAddress")
                or permission.get("domain")
                or "unknown"
            )
            print(
                f"  root {root_id}: {permission.get('type')}:{principal} "
                f"({permission.get('role') or 'unknown role'})"
            )
        for resource, permissions in descendants:
            for permission in permissions:
                principal = (
                    permission.get("emailAddress")
                    or permission.get("domain")
                    or "unknown"
                )
                print(
                    f"  {resource.get('name', 'unnamed')} ({resource.get('id')}): "
                    f"{permission.get('type')}:{principal} "
                    f"({permission.get('role') or 'unknown role'})"
                )
    else:
        print("Unauthorized permissions: none")

    try:
        users = firebase_read("users") or {}
    except Exception as error:
        raise RuntimeError(
            f"Could not read Firebase users at {FIREBASE_DATABASE_URL}: {error}"
        ) from error
    coordinators = []
    for key, record in firebase_record_items(users):
        user = record_data(record)
        if user.get("role") == "course_coordinator":
            coordinators.append(str(user.get("srn") or key))
    print(f"Firebase Course Coordinator accounts: {len(coordinators)}")
    if not coordinators:
        print(
            "Coordinator upload role: NOT VERIFIED; add a Firebase user with "
            "role course_coordinator."
        )
    else:
        print(
            "Coordinator upload role: verified by Firebase role records; "
            "backend upload checks this exact role."
        )

    try:
        modules = firebase_read("modules") or {}
    except Exception as error:
        raise RuntimeError(f"Could not read Firebase modules: {error}") from error
    mapped = 0
    missing = []
    for _, record in firebase_record_items(modules):
        module = record_data(record)
        if not module.get("title") or not module.get("subject"):
            continue
        try:
            semester = int(module.get("sem"))
        except (TypeError, ValueError):
            scope_match = re.match(
                r"^[A-Z]+_(\d+)(?:_|$)", str(module.get("scope", ""))
            )
            semester = int(scope_match.group(1)) if scope_match else 0
        if not 1 <= semester <= 8:
            missing.append(
                f"{module.get('subject')} / {module.get('title')}: invalid semester"
            )
            continue
        year_id = find_drive_folder(service, year_folder_name(semester), root_id)
        subject_id = (
            find_drive_folder(service, str(module["subject"]), year_id) if year_id else None
        )
        module_folder_id = (
            find_drive_folder(service, str(module["title"]), subject_id)
            if subject_id
            else None
        )
        if module_folder_id:
            mapped += 1
        else:
            missing.append(
                f"{year_folder_name(semester)} / {module['subject']} / {module['title']}"
            )

    print(f"Firebase modules with matching Drive folders: {mapped}")
    for path in missing:
        print(f"Missing/mismatched Drive folder: {path}")
    if not modules:
        print("Folder mapping: NOT VERIFIED; Firebase modules collection is empty.")

    passed = (
        root_ok
        and descendants_ok
        and bool(coordinators)
        and not missing
        and bool(modules)
    )
    print(f"Final result: {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(verify())
    except Exception as error:
        print("Root ACL status: NOT VERIFIED")
        print("Descendant ACL status: NOT VERIFIED")
        print("Unauthorized permissions: audit incomplete")
        print("Final result: FAIL")
        print(f"Drive setup verification failed: {error}", file=sys.stderr)
        sys.exit(1)
