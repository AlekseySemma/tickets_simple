import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException, status
from fastapi.responses import FileResponse, RedirectResponse

from app_support.storage import StorageService


class _DummyUpload:
    def __init__(self, filename: str, payload: bytes, content_type: str = "application/octet-stream"):
        self.filename = filename
        self.content_type = content_type
        self._payload = payload
        self.file = self
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if self._offset >= len(self._payload):
            return b""
        if size is None or size < 0:
            size = len(self._payload) - self._offset
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class _AsyncDummyUpload:
    def __init__(self, filename: str, payload: bytes, content_type: str = "application/octet-stream"):
        self.filename = filename
        self.content_type = content_type
        self._payload = payload
        self._offset = 0
        self.closed = False

    async def read(self, size: int = -1) -> bytes:
        if self._offset >= len(self._payload):
            return b""
        if size is None or size < 0:
            size = len(self._payload) - self._offset
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    async def close(self) -> None:
        self.closed = True


class StorageServiceTests(unittest.TestCase):
    def build_service(self, upload_dir: Path) -> StorageService:
        return StorageService(
            upload_dir=upload_dir,
            archive_upload_subdir="_archive",
            storage_backend="local",
            s3_bucket="",
            s3_endpoint_url="",
            s3_access_key="",
            s3_secret_key="",
            s3_region="",
            s3_addressing_style="path",
            s3_presigned_ttl_seconds=3600,
            attachments_storage_prefix="attachments",
            comment_media_storage_prefix="comment-media",
            receipts_storage_prefix="receipts",
            allowed_upload_extensions={".png", ".jpg", ".pdf", ".txt", ".ogg"},
            comment_image_extensions={".png", ".jpg"},
            comment_audio_extensions={".ogg"},
            comment_media_extensions={".png", ".jpg", ".ogg", ".txt"},
            max_upload_size_bytes=1024 * 1024,
            http_exception_cls=HTTPException,
            redirect_response_cls=RedirectResponse,
            file_response_cls=FileResponse,
            status_module=status,
            boto3_available=False,
            boto3_module=None,
            boto_config_cls=None,
            boto_core_error_cls=Exception,
            client_error_cls=Exception,
        )

    def test_store_and_move_local_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            service = self.build_service(Path(tmpdir))
            upload = _DummyUpload("report.txt", b"hello storage")

            stored_path, file_hash, file_size = service.store_upload_file_to_storage(
                upload,
                service.build_attachment_object_key("report.txt"),
            )

            self.assertEqual(file_size, len(b"hello storage"))
            self.assertEqual(len(file_hash), 64)
            disk_path = service.resolve_attachment_disk_path(stored_path)
            self.assertIsNotNone(disk_path)
            self.assertTrue(disk_path.exists())
            self.assertEqual(disk_path.read_bytes(), b"hello storage")

            archived_path = service.move_stored_file_to_key(
                stored_path,
                service.build_attachment_object_key("report.txt", archived_ticket_id=42),
            )
            self.assertEqual(archived_path, "/uploads/attachments/_archive/42/report.txt")
            archived_disk_path = service.resolve_attachment_disk_path(archived_path)
            self.assertIsNotNone(archived_disk_path)
            self.assertTrue(archived_disk_path.exists())
            self.assertEqual(archived_disk_path.read_bytes(), b"hello storage")

    def test_media_kind_and_safe_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            service = self.build_service(Path(tmpdir))

            self.assertEqual(service.detect_comment_media_kind("photo.png"), "photo")
            self.assertEqual(service.detect_comment_media_kind("voice.ogg"), "voice")
            self.assertEqual(service.detect_comment_media_kind("note.txt"), "file")

            safe_name = service.make_safe_upload_name("photo.png", ticket_id=12)
            self.assertTrue(safe_name.startswith("12_"))
            self.assertTrue(safe_name.endswith(".png"))

            with self.assertRaises(HTTPException):
                service.make_safe_upload_name("script.exe", ticket_id=12)


class StorageServiceAsyncTests(unittest.IsolatedAsyncioTestCase):
    def build_service(self, upload_dir: Path) -> StorageService:
        return StorageServiceTests().build_service(upload_dir)

    async def test_async_store_closes_upload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            service = self.build_service(Path(tmpdir))
            upload = _AsyncDummyUpload("voice.ogg", b"OggSvoice", "audio/ogg")

            stored_path, file_hash, file_size = await service.store_upload_file_to_storage_async(
                upload,
                service.build_comment_media_object_key("voice.ogg"),
            )

            self.assertTrue(upload.closed)
            self.assertEqual(file_size, len(b"OggSvoice"))
            self.assertEqual(len(file_hash), 64)
            disk_path = service.resolve_attachment_disk_path(stored_path)
            self.assertIsNotNone(disk_path)
            self.assertTrue(disk_path.exists())


if __name__ == "__main__":
    unittest.main()
