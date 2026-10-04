import argparse
import base64
import json
import mimetypes
import os
from io import BytesIO
from urllib.parse import quote, urlencode
from urllib.request import Request

from server import (
    FIREBASE_DATABASE_URL,
    MAX_DRIVE_UPLOAD_BYTES,
    ensure_drive_folder,
    get_drive_service,
    firebase_record_items,
    drive_proxy_url,
    record_data,
    trusted_urlopen,
    year_folder_name,
)


def read_firebase(path):
    request = Request(f"{FIREBASE_DATABASE_URL}/{path}.json")
    with trusted_urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def write_firebase(path, value):
    url = f"{FIREBASE_DATABASE_URL}/{path}.json"
    auth_token = os.getenv("SAPTHA_FIREBASE_AUTH_TOKEN", "").strip()
    if auth_token:
        url = f"{url}?{urlencode({'auth': auth_token})}"
    request = Request(
        url,
        data=json.dumps(value).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    with trusted_urlopen(request, timeout=30) as response:
        response.read()


def decode_file_data(value):
    if not isinstance(value, str) or "," not in value:
        raise ValueError("Expected a Base64 data URL.")
    header, encoded = value.split(",", 1)
    if ";base64" not in header:
        raise ValueError("Expected Base64-encoded file data.")
    mime_type = header[5:].split(";", 1)[0] or "application/octet-stream"
    content = base64.b64decode(encoded, validate=True)
    if not content or len(content) > MAX_DRIVE_UPLOAD_BYTES:
        raise ValueError("File is empty or exceeds the 50 MB migration limit.")
    return mime_type, content


def find_previously_migrated(service, module_folder_id, record_id):
    escaped_id = record_id.replace("\\", "\\\\").replace("'", "\\'")
    query = (
        f"'{module_folder_id}' in parents and trashed = false and "
        f"appProperties has {{ key='sapthaRecordId' and value='{escaped_id}' }}"
    )
    response = service.files().list(
        q=query,
        pageSize=10,
        fields="files(id,name,mimeType,size)",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
    ).execute()
    files = response.get("files", [])
    return files[0] if files else None


def migrate(apply_changes):
    records = read_firebase("module_files") or {}
    modules = read_firebase("modules") or {}
    module_by_id = {}
    for module_key, module_record in firebase_record_items(modules):
        module = record_data(module_record)
        module_id = module.get("id") or (
            module_record.get("id") if isinstance(module_record, dict) else None
        ) or module_key
        module_by_id[str(module_id)] = module

    candidates = []
    for record_key, record in firebase_record_items(records):
        record_id = record.get("id") if isinstance(record, dict) else None
        record_id = str(record_id or record_key)
        details = record_data(record)
        if not details.get("data") or details.get("driveFileId"):
            continue
        module_id = str(details.get("moduleId") or "")
        module = module_by_id.get(module_id, {})
        if not module.get("title") or not module.get("subject"):
            print(f"SKIP {record_id} ({details.get('name') or 'unnamed file'}): matching module record is missing")
            continue
        if (
            details.get("subject") and details["subject"] != module["subject"]
        ) or (
            details.get("scope") and module.get("scope") and details["scope"] != module["scope"]
        ):
            print(
                f"SKIP {record_id} ({details.get('name') or 'unnamed file'}): "
                f"record subject/scope ({details.get('subject')}, {details.get('scope')}) "
                f"does not match module ({module.get('subject')}, {module.get('scope')})"
            )
            continue
        try:
            mime_type, content = decode_file_data(details["data"])
            semester = int(module.get("sem"))
        except (KeyError, TypeError, ValueError) as error:
            print(f"SKIP {record_id}: {error}")
            continue
        if not 1 <= semester <= 8:
            print(f"SKIP {record_id}: invalid semester {semester}")
            continue
        candidates.append((record_key, record_id, record, details, module, semester, mime_type, content))

    print(f"Found {len(candidates)} Base64 module file(s).")
    if not apply_changes:
        for _, record_id, _, details, module, semester, _, content in candidates:
            print(
                f"WOULD MIGRATE {record_id}: {details.get('name') or 'unnamed file'} "
                f"({len(content)} bytes) -> {year_folder_name(semester)} / "
                f"{module['subject']} / {module['title']}"
            )
        print("DRY RUN ONLY. No Drive uploads or Firebase writes were performed.")
        return

    root_folder_id = os.getenv("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip()
    if not root_folder_id:
        raise RuntimeError("Set GOOGLE_DRIVE_ROOT_FOLDER_ID before using --apply.")
    service = get_drive_service()
    from googleapiclient.http import MediaIoBaseUpload

    for record_key, record_id, record, details, module, semester, mime_type, content in candidates:
        year_id = ensure_drive_folder(service, year_folder_name(semester), root_folder_id)
        subject_id = ensure_drive_folder(service, module["subject"], year_id)
        module_folder_id = ensure_drive_folder(service, module["title"], subject_id)
        drive_file = find_previously_migrated(service, module_folder_id, record_id)
        if not drive_file:
            file_name = str(details.get("name") or "notes").replace("\\", "/").split("/")[-1]
            drive_file = service.files().create(
                body={
                    "name": file_name,
                    "parents": [module_folder_id],
                    "appProperties": {"sapthaRecordId": record_id},
                },
                media_body=MediaIoBaseUpload(
                    BytesIO(content),
                    mimetype=mime_type or mimetypes.guess_type(file_name)[0] or "application/octet-stream",
                    resumable=False,
                ),
                fields="id,name,mimeType,size",
                supportsAllDrives=True,
            ).execute()

        updated_details = dict(details)
        updated_details.pop("data", None)
        updated_details.update({
            "driveFileId": drive_file["id"],
            "name": drive_file.get("name") or details.get("name") or "notes",
            "size": int(drive_file.get("size") or len(content)),
            "mimeType": drive_file.get("mimeType") or mime_type,
            "moduleId": str(details.get("moduleId")),
            "subject": module["subject"],
            "scope": details.get("scope") or module.get("scope", ""),
            "url": drive_proxy_url(drive_file["id"], details.get("moduleId")),
        })
        updated_record = dict(record) if isinstance(record, dict) else {}
        if isinstance(updated_record.get("data"), dict):
            updated_record["data"] = updated_details
        else:
            updated_record = updated_details
        write_firebase(f"module_files/{quote(str(record_key), safe='')}", updated_record)
        print(f"MIGRATED {record_id} -> {drive_file['id']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Move legacy Base64 module files into Google Drive.")
    parser.add_argument("--apply", action="store_true", help="Upload files and replace Firebase payloads with Drive metadata.")
    migrate(parser.parse_args().apply)
