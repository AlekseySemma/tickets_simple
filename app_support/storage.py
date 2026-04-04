import hashlib
from pathlib import Path
import shutil
from urllib.parse import quote, urlsplit
import uuid


class StorageService:
    def __init__(
        self,
        *,
        upload_dir: Path,
        upload_dir_getter=None,
        archive_upload_subdir: str,
        storage_backend: str,
        storage_backend_getter=None,
        s3_bucket: str,
        s3_endpoint_url: str,
        s3_access_key: str,
        s3_secret_key: str,
        s3_region: str,
        s3_addressing_style: str,
        s3_presigned_ttl_seconds: int,
        attachments_storage_prefix: str,
        comment_media_storage_prefix: str,
        receipts_storage_prefix: str,
        allowed_upload_extensions,
        comment_image_extensions,
        comment_audio_extensions,
        comment_media_extensions,
        max_upload_size_bytes: int,
        http_exception_cls,
        redirect_response_cls,
        file_response_cls,
        status_module,
        boto3_available: bool,
        boto3_module,
        boto_config_cls,
        boto_core_error_cls,
        client_error_cls,
    ):
        self.upload_dir = Path(upload_dir)
        self.upload_dir_getter = upload_dir_getter
        self.archive_upload_subdir = archive_upload_subdir
        self.storage_backend = (storage_backend or "local").strip().lower()
        self.storage_backend_getter = storage_backend_getter
        self.s3_bucket = (s3_bucket or "").strip()
        self.s3_endpoint_url = (s3_endpoint_url or "").strip()
        self.s3_access_key = (s3_access_key or "").strip()
        self.s3_secret_key = (s3_secret_key or "").strip()
        self.s3_region = (s3_region or "").strip()
        self.s3_addressing_style = (s3_addressing_style or "").strip().lower()
        self.s3_presigned_ttl_seconds = int(s3_presigned_ttl_seconds)
        self.attachments_storage_prefix = attachments_storage_prefix
        self.comment_media_storage_prefix = comment_media_storage_prefix
        self.receipts_storage_prefix = receipts_storage_prefix
        self.allowed_upload_extensions = set(allowed_upload_extensions)
        self.comment_image_extensions = set(comment_image_extensions)
        self.comment_audio_extensions = set(comment_audio_extensions)
        self.comment_media_extensions = set(comment_media_extensions)
        self.max_upload_size_bytes = int(max_upload_size_bytes)
        self.http_exception_cls = http_exception_cls
        self.redirect_response_cls = redirect_response_cls
        self.file_response_cls = file_response_cls
        self.status_module = status_module
        self.boto3_available = bool(boto3_available)
        self.boto3_module = boto3_module
        self.boto_config_cls = boto_config_cls
        self.boto_core_error_cls = boto_core_error_cls
        self.client_error_cls = client_error_cls
        self._s3_client = None

    def _refresh_runtime_settings(self) -> None:
        if callable(self.upload_dir_getter):
            self.upload_dir = Path(self.upload_dir_getter())
        if callable(self.storage_backend_getter):
            self.storage_backend = (self.storage_backend_getter() or "local").strip().lower()

    def get_s3_client(self):
        self._refresh_runtime_settings()
        if not self.boto3_available:
            raise RuntimeError("boto3 is required for S3 storage support")
        missing_s3 = [
            name
            for name, value in (
                ("S3_ENDPOINT_URL", self.s3_endpoint_url),
                ("S3_BUCKET", self.s3_bucket),
                ("S3_ACCESS_KEY", self.s3_access_key),
                ("S3_SECRET_KEY", self.s3_secret_key),
            )
            if not value
        ]
        if missing_s3:
            raise RuntimeError(f"Missing S3 settings: {', '.join(missing_s3)}")
        if self._s3_client is None:
            config_kwargs = {
                "signature_version": "s3v4",
                "request_checksum_calculation": "when_required",
                "response_checksum_validation": "when_required",
            }
            if self.s3_addressing_style in {"path", "virtual"}:
                config_kwargs["s3"] = {
                    "addressing_style": self.s3_addressing_style,
                    "payload_signing_enabled": False,
                }
            else:
                config_kwargs["s3"] = {"payload_signing_enabled": False}
            self._s3_client = self.boto3_module.client(
                "s3",
                endpoint_url=self.s3_endpoint_url or None,
                aws_access_key_id=self.s3_access_key,
                aws_secret_access_key=self.s3_secret_key,
                region_name=self.s3_region or None,
                config=self.boto_config_cls(**config_kwargs),
            )
        return self._s3_client

    def build_storage_key(self, *parts: str | None) -> str:
        tokens: list[str] = []
        for part in parts:
            value = str(part or "").replace("\\", "/").strip("/")
            if value:
                tokens.append(value)
        return "/".join(tokens)

    def parse_s3_storage_path(self, raw_path: str | None) -> tuple[str, str] | None:
        raw = (raw_path or "").strip()
        if not raw.lower().startswith("s3://"):
            return None
        parsed = urlsplit(raw)
        bucket = (parsed.netloc or "").strip()
        key = parsed.path.lstrip("/")
        if not bucket or not key:
            return None
        return bucket, key

    def build_s3_storage_path(self, object_key: str, bucket: str | None = None) -> str:
        self._refresh_runtime_settings()
        target_bucket = (bucket or self.s3_bucket).strip()
        normalized_key = self.build_storage_key(object_key)
        if not target_bucket or not normalized_key:
            raise self.http_exception_cls(500, "S3 storage is not configured")
        return f"s3://{target_bucket}/{normalized_key}"

    def build_attachment_object_key(self, stored_name: str, archived_ticket_id: int | None = None) -> str:
        if archived_ticket_id is None:
            return self.build_storage_key(self.attachments_storage_prefix, stored_name)
        return self.build_storage_key(
            self.attachments_storage_prefix,
            self.archive_upload_subdir,
            str(archived_ticket_id),
            stored_name,
        )

    def build_comment_media_object_key(self, stored_name: str, archived_ticket_id: int | None = None) -> str:
        if archived_ticket_id is None:
            return self.build_storage_key(self.comment_media_storage_prefix, stored_name)
        return self.build_storage_key(
            self.comment_media_storage_prefix,
            self.archive_upload_subdir,
            str(archived_ticket_id),
            stored_name,
        )

    def build_receipt_object_key(self, stored_name: str) -> str:
        return self.build_storage_key(self.receipts_storage_prefix, stored_name)

    def get_storage_basename(self, raw_path: str | None) -> str:
        s3_ref = self.parse_s3_storage_path(raw_path)
        if s3_ref:
            return Path(s3_ref[1]).name
        raw = (raw_path or "").strip()
        if raw.startswith("/uploads/"):
            return Path(raw.replace("/uploads/", "", 1)).name
        return Path(raw).name

    def build_download_content_disposition(self, filename: str, disposition: str) -> str:
        safe_name = (filename or "file").replace("\\", "_").replace('"', "")
        return f"{disposition}; filename*=UTF-8''{quote(safe_name)}"

    def get_upload_extension(self, filename: str | None) -> str:
        return Path(filename or "").suffix.lower()[:10]

    def detect_comment_media_kind(self, filename: str | None) -> str:
        ext = self.get_upload_extension(filename)
        if ext in self.comment_image_extensions:
            return "photo"
        if ext in self.comment_audio_extensions:
            return "voice"
        if ext in self.allowed_upload_extensions:
            return "file"
        raise self.http_exception_cls(400, "Unsupported comment media type")

    def resolve_attachment_disk_path(self, raw_path: str | None) -> Path | None:
        self._refresh_runtime_settings()
        raw = (raw_path or "").strip()
        if not raw or self.parse_s3_storage_path(raw):
            return None
        if raw.startswith("/uploads/"):
            candidate = self.upload_dir / raw.replace("/uploads/", "", 1)
        else:
            parsed = Path(raw)
            candidate = parsed if parsed.is_absolute() else (self.upload_dir / parsed)
        upload_root = self.upload_dir.resolve(strict=False)
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(upload_root)
        except ValueError:
            return None
        return resolved

    def make_safe_upload_name(
        self,
        filename: str | None,
        *,
        ticket_id: int | None = None,
        allowed_extensions=None,
    ) -> str:
        ext = self.get_upload_extension(filename)
        allowed = allowed_extensions or self.allowed_upload_extensions
        if not ext or ext not in allowed:
            raise self.http_exception_cls(400, "Unsupported file type")
        prefix = f"{ticket_id}_" if ticket_id is not None else ""
        return f"{prefix}{uuid.uuid4().hex}{ext}"

    def write_upload_file(self, upload, destination: Path, max_size: int | None = None) -> None:
        self._refresh_runtime_settings()
        total = 0
        max_allowed = self.max_upload_size_bytes if max_size is None else int(max_size)
        try:
            with destination.open("wb") as out:
                while True:
                    chunk = upload.file.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_allowed:
                        raise self.http_exception_cls(413, "File too large")
                    out.write(chunk)
        except Exception:
            if destination.exists():
                destination.unlink()
            raise

    async def write_upload_file_async(self, upload, destination: Path, max_size: int | None = None) -> None:
        self._refresh_runtime_settings()
        total = 0
        max_allowed = self.max_upload_size_bytes if max_size is None else int(max_size)
        try:
            with destination.open("wb") as out:
                while True:
                    chunk = await upload.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_allowed:
                        raise self.http_exception_cls(413, "File too large")
                    out.write(chunk)
        except Exception:
            if destination.exists():
                destination.unlink()
            raise

    def read_upload_bytes(self, upload, max_size: int | None = None) -> bytes:
        self._refresh_runtime_settings()
        total = 0
        max_allowed = self.max_upload_size_bytes if max_size is None else int(max_size)
        chunks: list[bytes] = []
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_allowed:
                raise self.http_exception_cls(413, "File too large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def read_upload_bytes_async(self, upload, max_size: int | None = None) -> bytes:
        self._refresh_runtime_settings()
        total = 0
        max_allowed = self.max_upload_size_bytes if max_size is None else int(max_size)
        chunks: list[bytes] = []
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_allowed:
                raise self.http_exception_cls(413, "File too large")
            chunks.append(chunk)
        return b"".join(chunks)

    def build_upload_url_from_disk_path(self, path: Path) -> str:
        self._refresh_runtime_settings()
        upload_root = self.upload_dir.resolve(strict=False)
        resolved = path.resolve(strict=False)
        relative = resolved.relative_to(upload_root).as_posix()
        return f"/uploads/{relative}"

    def compute_bytes_sha256_and_size(self, payload: bytes) -> tuple[str, int]:
        return hashlib.sha256(payload).hexdigest(), len(payload)

    def store_bytes_in_storage(self, object_key: str, payload: bytes, content_type: str | None = None) -> str:
        self._refresh_runtime_settings()
        normalized_key = self.build_storage_key(object_key)
        if self.storage_backend == "s3":
            put_kwargs = {
                "Bucket": self.s3_bucket,
                "Key": normalized_key,
                "Body": payload,
            }
            if content_type:
                put_kwargs["ContentType"] = content_type
            self.get_s3_client().put_object(**put_kwargs)
            return self.build_s3_storage_path(normalized_key)

        destination = self.upload_dir / Path(normalized_key)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("wb") as out:
                out.write(payload)
        except Exception:
            if destination.exists():
                destination.unlink()
            raise
        return self.build_upload_url_from_disk_path(destination)

    def compute_file_sha256_and_size(self, path: Path) -> tuple[str, int]:
        hasher = hashlib.sha256()
        size = 0
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                size += len(chunk)
        return hasher.hexdigest(), size

    def store_upload_file_to_storage(self, upload, object_key: str, max_size: int | None = None) -> tuple[str, str, int]:
        self._refresh_runtime_settings()
        normalized_key = self.build_storage_key(object_key)
        max_allowed = self.max_upload_size_bytes if max_size is None else int(max_size)
        if self.storage_backend == "s3":
            payload = self.read_upload_bytes(upload, max_size=max_allowed)
            file_hash, file_size = self.compute_bytes_sha256_and_size(payload)
            stored_path = self.store_bytes_in_storage(normalized_key, payload, content_type=upload.content_type)
            return stored_path, file_hash, file_size

        destination = self.upload_dir / Path(normalized_key)
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.write_upload_file(upload, destination, max_size=max_allowed)
        file_hash, file_size = self.compute_file_sha256_and_size(destination)
        return self.build_upload_url_from_disk_path(destination), file_hash, file_size

    async def store_upload_file_to_storage_async(
        self,
        upload,
        object_key: str,
        max_size: int | None = None,
    ) -> tuple[str, str, int]:
        self._refresh_runtime_settings()
        normalized_key = self.build_storage_key(object_key)
        max_allowed = self.max_upload_size_bytes if max_size is None else int(max_size)
        if self.storage_backend == "s3":
            payload = await self.read_upload_bytes_async(upload, max_size=max_allowed)
            file_hash, file_size = self.compute_bytes_sha256_and_size(payload)
            stored_path = self.store_bytes_in_storage(normalized_key, payload, content_type=upload.content_type)
            return stored_path, file_hash, file_size

        destination = self.upload_dir / Path(normalized_key)
        destination.parent.mkdir(parents=True, exist_ok=True)
        await self.write_upload_file_async(upload, destination, max_size=max_allowed)
        file_hash, file_size = self.compute_file_sha256_and_size(destination)
        return self.build_upload_url_from_disk_path(destination), file_hash, file_size

    def read_stored_file_bytes(self, raw_path: str | None) -> tuple[bytes, str] | None:
        self._refresh_runtime_settings()
        s3_ref = self.parse_s3_storage_path(raw_path)
        if s3_ref:
            bucket, key = s3_ref
            try:
                response = self.get_s3_client().get_object(Bucket=bucket, Key=key)
                body = response.get("Body")
                if body is None:
                    return None
                try:
                    payload = body.read()
                finally:
                    close = getattr(body, "close", None)
                    if callable(close):
                        close()
                return payload, Path(key).name
            except (self.boto_core_error_cls, self.client_error_cls):
                return None

        disk_path = self.resolve_attachment_disk_path(raw_path)
        if not disk_path or not disk_path.exists() or not disk_path.is_file():
            return None
        return disk_path.read_bytes(), disk_path.name

    def delete_stored_file(self, raw_path: str | None) -> None:
        self._refresh_runtime_settings()
        s3_ref = self.parse_s3_storage_path(raw_path)
        if s3_ref:
            bucket, key = s3_ref
            try:
                self.get_s3_client().delete_object(Bucket=bucket, Key=key)
            except (self.boto_core_error_cls, self.client_error_cls, RuntimeError):
                pass
            return

        disk_path = self.resolve_attachment_disk_path(raw_path)
        if not disk_path:
            return
        try:
            if disk_path.exists() and disk_path.is_file():
                disk_path.unlink()
        except OSError:
            pass

    def build_presigned_storage_download_url(self, raw_path: str | None, display_name: str, disposition: str) -> str | None:
        self._refresh_runtime_settings()
        s3_ref = self.parse_s3_storage_path(raw_path)
        if not s3_ref:
            return None
        bucket, key = s3_ref
        params = {
            "Bucket": bucket,
            "Key": key,
            "ResponseContentDisposition": self.build_download_content_disposition(display_name, disposition),
        }
        return str(
            self.get_s3_client().generate_presigned_url(
                "get_object",
                Params=params,
                ExpiresIn=self.s3_presigned_ttl_seconds,
            )
        )

    def serve_stored_file_response(self, raw_path: str | None, display_name: str, disposition: str, not_found_detail: str):
        self._refresh_runtime_settings()
        presigned_url = self.build_presigned_storage_download_url(raw_path, display_name, disposition)
        if presigned_url:
            return self.redirect_response_cls(
                url=presigned_url,
                status_code=self.status_module.HTTP_307_TEMPORARY_REDIRECT,
            )
        disk_path = self.resolve_attachment_disk_path(raw_path)
        if not disk_path or not disk_path.exists() or not disk_path.is_file():
            raise self.http_exception_cls(404, not_found_detail)
        return self.file_response_cls(
            disk_path,
            filename=display_name,
            content_disposition_type=disposition,
        )

    def move_stored_file_to_key(self, raw_path: str | None, target_key: str) -> str | None:
        self._refresh_runtime_settings()
        normalized_key = self.build_storage_key(target_key)
        s3_ref = self.parse_s3_storage_path(raw_path)

        if self.storage_backend == "s3":
            if s3_ref:
                source_bucket, source_key = s3_ref
                target_bucket = self.s3_bucket or source_bucket
                if source_bucket == target_bucket and source_key == normalized_key:
                    return self.build_s3_storage_path(normalized_key, bucket=target_bucket)
                client = self.get_s3_client()
                client.copy_object(
                    Bucket=target_bucket,
                    CopySource={"Bucket": source_bucket, "Key": source_key},
                    Key=normalized_key,
                )
                client.delete_object(Bucket=source_bucket, Key=source_key)
                return self.build_s3_storage_path(normalized_key, bucket=target_bucket)

            source = self.resolve_attachment_disk_path(raw_path)
            if not source or not source.exists() or not source.is_file():
                return None
            payload = source.read_bytes()
            stored_path = self.store_bytes_in_storage(normalized_key, payload)
            try:
                source.unlink()
            except OSError:
                pass
            return stored_path

        target = self.upload_dir / Path(normalized_key)
        target.parent.mkdir(parents=True, exist_ok=True)
        if s3_ref:
            payload_info = self.read_stored_file_bytes(raw_path)
            if not payload_info:
                return None
            payload, _ = payload_info
            try:
                with target.open("wb") as out:
                    out.write(payload)
            except Exception:
                if target.exists():
                    target.unlink()
                raise
            self.delete_stored_file(raw_path)
            return self.build_upload_url_from_disk_path(target)

        source = self.resolve_attachment_disk_path(raw_path)
        if not source or not source.exists() or not source.is_file():
            return None
        if source.resolve(strict=False) != target.resolve(strict=False):
            shutil.move(str(source), str(target))
        return self.build_upload_url_from_disk_path(target)

    def enrich_attachment_metadata(self, attachment: object, disk_path: Path | None = None) -> None:
        resolved = disk_path or self.resolve_attachment_disk_path(getattr(attachment, "file_path", None))
        if not resolved or not resolved.exists() or not resolved.is_file():
            return
        file_hash, file_size = self.compute_file_sha256_and_size(resolved)
        attachment.file_sha256 = file_hash
        attachment.file_size_bytes = file_size

    def normalize_uploaded_files(self, files: list) -> list:
        valid_files: list = []
        for upload in files:
            if upload and (getattr(upload, "filename", None) or "").strip():
                valid_files.append(upload)
        if not valid_files:
            raise self.http_exception_cls(400, "No files uploaded")
        return valid_files

    def normalize_optional_uploaded_files(self, files: list | None) -> list:
        valid_files: list = []
        for upload in files or []:
            if upload and (getattr(upload, "filename", None) or "").strip():
                valid_files.append(upload)
        return valid_files

    def choose_attachment_storage_name(self, attachment: object, ticket_id: int) -> str:
        preferred_name = (getattr(attachment, "original_name", None) or "").strip()
        if preferred_name:
            try:
                return self.make_safe_upload_name(preferred_name, ticket_id=ticket_id)
            except self.http_exception_cls:
                pass
        fallback_name = Path(getattr(attachment, "file_path", None) or "").name
        try:
            return self.make_safe_upload_name(fallback_name, ticket_id=ticket_id)
        except self.http_exception_cls:
            ext = Path(fallback_name).suffix.lower()[:10] or ".bin"
            return f"{ticket_id}_{uuid.uuid4().hex}{ext}"

    def choose_comment_media_storage_name(self, item: object, ticket_id: int) -> str:
        preferred_name = (getattr(item, "original_name", None) or "").strip()
        if preferred_name:
            try:
                return self.make_safe_upload_name(
                    preferred_name,
                    ticket_id=ticket_id,
                    allowed_extensions=self.comment_media_extensions,
                )
            except self.http_exception_cls:
                pass
        fallback_name = Path(getattr(item, "file_path", None) or "").name
        try:
            return self.make_safe_upload_name(
                fallback_name,
                ticket_id=ticket_id,
                allowed_extensions=self.comment_media_extensions,
            )
        except self.http_exception_cls:
            ext = self.get_upload_extension(fallback_name) or ".bin"
            return f"{ticket_id}_{uuid.uuid4().hex}{ext}"

    def move_attachment_to_archive(self, attachment: object, ticket_id: int, archived_at) -> None:
        archive_name = self.choose_attachment_storage_name(attachment, ticket_id)
        target_key = self.build_attachment_object_key(archive_name, archived_ticket_id=ticket_id)
        target_path = self.move_stored_file_to_key(getattr(attachment, "file_path", None), target_key)
        if not target_path:
            attachment.archived_at = archived_at
            return
        attachment.file_path = target_path
        attachment.archived_at = archived_at

    def move_attachment_to_active_storage(self, attachment: object, ticket_id: int) -> None:
        active_name = self.choose_attachment_storage_name(attachment, ticket_id)
        target_key = self.build_attachment_object_key(active_name)
        target_path = self.move_stored_file_to_key(getattr(attachment, "file_path", None), target_key)
        if not target_path:
            attachment.archived_at = None
            return
        attachment.file_path = target_path
        attachment.archived_at = None

    def move_comment_media_to_archive(self, item: object, ticket_id: int, archived_at) -> None:
        archive_name = self.choose_comment_media_storage_name(item, ticket_id)
        target_key = self.build_comment_media_object_key(archive_name, archived_ticket_id=ticket_id)
        target_path = self.move_stored_file_to_key(getattr(item, "file_path", None), target_key)
        if not target_path:
            item.archived_at = archived_at
            return
        item.file_path = target_path
        item.archived_at = archived_at

    def move_comment_media_to_active_storage(self, item: object, ticket_id: int) -> None:
        active_name = self.choose_comment_media_storage_name(item, ticket_id)
        target_key = self.build_comment_media_object_key(active_name)
        target_path = self.move_stored_file_to_key(getattr(item, "file_path", None), target_key)
        if not target_path:
            item.archived_at = None
            return
        item.file_path = target_path
        item.archived_at = None
