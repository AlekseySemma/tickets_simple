import argparse
import mimetypes
import sys
from pathlib import Path
from typing import Iterable


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from main import (  # noqa: E402
    ARCHIVE_UPLOAD_SUBDIR,
    Attachment,
    ReceiptFile,
    S3_BUCKET,
    SessionLocal,
    build_attachment_object_key,
    build_receipt_object_key,
    build_s3_storage_path,
    build_storage_key,
    compute_file_sha256_and_size,
    delete_stored_file,
    get_s3_client,
    parse_s3_storage_path,
    resolve_attachment_disk_path,
)


def build_attachment_target_key(row: Attachment) -> str | None:
    raw_path = (row.file_path or "").strip()
    if parse_s3_storage_path(raw_path):
        return None
    if not raw_path.startswith("/uploads/"):
        return None

    relative = Path(raw_path.replace("/uploads/", "", 1))
    parts = list(relative.parts)
    if not parts:
        return None

    if parts[0] == "attachments":
        return relative.as_posix()
    if parts[0] == ARCHIVE_UPLOAD_SUBDIR and len(parts) >= 3:
        archived_ticket_id = int(parts[1])
        archived_name = Path(*parts[2:]).as_posix()
        return build_attachment_object_key(archived_name, archived_ticket_id=archived_ticket_id)
    return build_attachment_object_key(relative.as_posix())


def build_receipt_target_key(row: ReceiptFile) -> str | None:
    raw_path = (row.file_path or "").strip()
    if parse_s3_storage_path(raw_path):
        return None
    if not raw_path.startswith("/uploads/"):
        return None

    relative = Path(raw_path.replace("/uploads/", "", 1))
    parts = list(relative.parts)
    if not parts:
        return None

    if parts[0] == "receipts":
        return relative.as_posix()
    return build_receipt_object_key(relative.as_posix())


def iter_attachment_rows(db) -> Iterable[tuple[str, int, Attachment, str]]:
    rows = db.query(Attachment).order_by(Attachment.id.asc()).all()
    for row in rows:
        target_key = build_attachment_target_key(row)
        if target_key:
            yield "attachment", int(row.id), row, target_key


def iter_receipt_rows(db) -> Iterable[tuple[str, int, ReceiptFile, str]]:
    rows = db.query(ReceiptFile).order_by(ReceiptFile.id.asc()).all()
    for row in rows:
        target_key = build_receipt_target_key(row)
        if target_key:
            yield "receipt", int(row.id), row, target_key


def upload_local_file_to_s3(source_path: Path, target_key: str) -> tuple[str, int]:
    content_type = mimetypes.guess_type(source_path.name)[0]
    put_kwargs = {
        "Bucket": S3_BUCKET,
        "Key": target_key,
        "Body": source_path.read_bytes(),
    }
    if content_type:
        put_kwargs["ContentType"] = content_type
    get_s3_client().put_object(**put_kwargs)
    return compute_file_sha256_and_size(source_path)


def migrate(kind: str, apply: bool, delete_local: bool, limit: int | None) -> None:
    if not S3_BUCKET:
        raise RuntimeError("S3_BUCKET is empty")

    processed = 0
    migrated = 0
    skipped_missing = 0
    skipped_invalid = 0

    with SessionLocal() as db:
        items: list[tuple[str, int, object, str]] = []
        if kind in {"all", "attachments"}:
            items.extend(iter_attachment_rows(db))
        if kind in {"all", "receipts"}:
            items.extend(iter_receipt_rows(db))

        if limit is not None:
            items = items[:limit]

        if not items:
            print("Nothing to migrate")
            return

        for entity_kind, row_id, row, target_key in items:
            processed += 1
            source_path = resolve_attachment_disk_path(getattr(row, "file_path", None))
            if not source_path or not source_path.exists() or not source_path.is_file():
                skipped_missing += 1
                print(f"[MISS] {entity_kind}#{row_id} -> local file not found: {getattr(row, 'file_path', '')}")
                continue

            target_path = build_s3_storage_path(target_key)
            if not apply:
                print(f"[DRY]  {entity_kind}#{row_id}: {source_path} -> {target_path}")
                continue

            try:
                file_hash, file_size = upload_local_file_to_s3(source_path, target_key)
                row.file_path = target_path
                row.file_sha256 = file_hash
                row.file_size_bytes = file_size
                db.commit()
                migrated += 1
                print(f"[OK]   {entity_kind}#{row_id}: {source_path.name} -> {target_path}")
            except Exception as exc:
                db.rollback()
                skipped_invalid += 1
                print(f"[ERR]  {entity_kind}#{row_id}: {exc}")
                continue

            if delete_local:
                try:
                    source_path.unlink()
                except OSError as exc:
                    print(f"[WARN] {entity_kind}#{row_id}: uploaded but failed to delete local file: {exc}")

    mode = "apply" if apply else "dry-run"
    print("")
    print(f"Mode: {mode}")
    print(f"Processed: {processed}")
    print(f"Migrated: {migrated}")
    print(f"Missing local files: {skipped_missing}")
    print(f"Errors: {skipped_invalid}")
    if apply and not delete_local:
        print("Local files were kept on disk. Re-run with --delete-local after verifying S3.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate locally stored uploads from /uploads/... paths in DB to S3 storage.",
    )
    parser.add_argument(
        "--kind",
        choices=["all", "attachments", "receipts"],
        default="all",
        help="Which file group to migrate.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually upload files to S3 and update DB. Without this flag, the script runs in dry-run mode.",
    )
    parser.add_argument(
        "--delete-local",
        action="store_true",
        help="Delete local files after successful upload and DB update.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process only the first N matched rows.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.delete_local and not args.apply:
        raise SystemExit("--delete-local requires --apply")
    migrate(
        kind=args.kind,
        apply=bool(args.apply),
        delete_local=bool(args.delete_local),
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
