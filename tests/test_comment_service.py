import asyncio
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.datastructures import UploadFile

os.environ.setdefault("JWT_SECRET", "x" * 40)
os.environ.setdefault("SKIP_MIGRATION_CHECK", "1")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import main  # noqa: E402

main.engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
main.SessionLocal = sessionmaker(bind=main.engine, autocommit=False, autoflush=False)
main.TEXT_REPAIR_ON_START = False
main.TEMPLATE_AUTOGEN_ENABLED = False
main.push_is_configured = lambda: False
main.run_archive_cleanup_forever = lambda: None


class CommentServiceTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()
        self.upload_dir_ctx = tempfile.TemporaryDirectory()
        main.STORAGE_BACKEND = "local"
        main.UPLOAD_DIR = Path(self.upload_dir_ctx.name)
        main.ARCHIVE_UPLOAD_DIR = main.UPLOAD_DIR / main.ARCHIVE_UPLOAD_SUBDIR
        main.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.upload_dir_ctx.cleanup()

    def seed_ticket_context(self) -> dict[str, int]:
        with main.SessionLocal() as db:
            company = main.Company(name="Comment Service Co")
            db.add(company)
            db.flush()

            user = main.User(
                email="comment-service@example.com",
                name="Comment Service User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()

            project = main.Project(name="Main Project", company_id=company.id)
            db.add(project)
            db.flush()

            ticket = main.Ticket(
                title="Service ticket",
                description="Comment flow",
                status=main.TicketStatus.in_progress,
                company_id=company.id,
                project_id=project.id,
                executor_id=user.id,
                created_by=user.id,
            )
            db.add(ticket)
            db.commit()
            return {"ticket_id": ticket.id, "user_id": user.id}

    def test_comment_service_creates_media_and_serializes_output(self):
        ids = self.seed_ticket_context()

        with main.SessionLocal() as db:
            comment, media_items, stored_paths = asyncio.run(
                main.create_comment_with_media_async(
                    db=db,
                    ticket_id=ids["ticket_id"],
                    author_id=ids["user_id"],
                    text="Service comment",
                    photos=[
                        UploadFile(
                            filename="photo.png",
                            file=BytesIO(b"\x89PNG\r\ncomment-photo"),
                            headers={"content-type": "image/png"},
                        )
                    ],
                    attachments=[
                        UploadFile(
                            filename="note.txt",
                            file=BytesIO(b"attached note"),
                            headers={"content-type": "text/plain"},
                        )
                    ],
                )
            )
            db.commit()
            db.refresh(comment)
            for item in media_items:
                db.refresh(item)

            payload = main.serialize_comment_out(comment, media_items)

        self.assertEqual(payload.text, "Service comment")
        self.assertEqual({item.media_kind for item in payload.media}, {"photo", "file"})
        self.assertEqual(len(stored_paths), 2)
        for stored_path in stored_paths:
            disk_path = main.resolve_attachment_disk_path(stored_path)
            self.assertIsNotNone(disk_path)
            self.assertTrue(disk_path.exists())

        self.assertEqual(main.summarize_comment_media(1, 0, 1, "Alex"), "Alex добавил фото и файл")


if __name__ == "__main__":
    unittest.main()
