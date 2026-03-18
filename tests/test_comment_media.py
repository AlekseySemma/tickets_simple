import asyncio
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
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


class CommentMediaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        cls.client_cm = TestClient(main.app)
        cls.client = cls.client_cm.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_cm.__exit__(None, None, None)

    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        self.upload_dir_ctx = tempfile.TemporaryDirectory()
        main.STORAGE_BACKEND = "local"
        main.UPLOAD_DIR = Path(self.upload_dir_ctx.name)
        main.ARCHIVE_UPLOAD_DIR = main.UPLOAD_DIR / main.ARCHIVE_UPLOAD_SUBDIR
        main.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        self.client.cookies.clear()

    def tearDown(self):
        self.upload_dir_ctx.cleanup()

    def seed_ticket_context(self) -> dict[str, int | str]:
        with main.SessionLocal() as db:
            company = main.Company(name="Acme")
            db.add(company)
            db.flush()

            project = main.Project(name="HQ", company_id=company.id)
            db.add(project)
            db.flush()

            user = main.User(
                email="admin@acme.local",
                name="Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()

            ticket = main.Ticket(
                title="Test ticket",
                description="Details",
                status=main.TicketStatus.in_progress,
                company_id=company.id,
                project_id=project.id,
                executor_id=user.id,
                created_by=user.id,
            )
            db.add(ticket)
            db.commit()

            return {
                "company_id": company.id,
                "project_id": project.id,
                "user_id": user.id,
                "ticket_id": ticket.id,
                "token": main.create_access_token(str(user.id), main.get_user_auth_token_version(user)),
            }

    def test_api_comment_accepts_photo_and_voice_and_stores_files(self):
        ids = self.seed_ticket_context()
        response = self.client.post(
            f"/tickets/{ids['ticket_id']}/comments",
            headers={"Authorization": f"Bearer {ids['token']}"},
            data={"text": "Комментарий с медиа"},
            files=[
                ("photos", ("photo.png", b"\x89PNG\r\nphoto", "image/png")),
                ("voice_messages", ("voice.ogg", b"OggSvoice", "audio/ogg")),
                ("attachments", ("report.pdf", b"%PDF-1.4 test", "application/pdf")),
            ],
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["text"], "Комментарий с медиа")
        self.assertEqual(len(payload["media"]), 3)
        self.assertEqual({item["media_kind"] for item in payload["media"]}, {"photo", "voice", "file"})

        with main.SessionLocal() as db:
            comment = db.query(main.Comment).filter(main.Comment.ticket_id == ids["ticket_id"]).one()
            media_items = db.query(main.CommentMedia).filter(main.CommentMedia.comment_id == comment.id).all()
            self.assertEqual(len(media_items), 3)
            for item in media_items:
                stored_path = main.resolve_attachment_disk_path(item.file_path)
                self.assertIsNotNone(stored_path)
                self.assertTrue(stored_path.exists())

            photo_item = next(item for item in media_items if item.media_kind == "photo")

        download = self.client.get(
            f"/comment-media/{photo_item.id}",
            headers={"Authorization": f"Bearer {ids['token']}"},
        )
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.content, b"\x89PNG\r\nphoto")

    def test_web_ticket_detail_renders_audio_player_for_voice_comment(self):
        ids = self.seed_ticket_context()
        login_response = self.client.post(
            "/web/login",
            data={"email": "admin@acme.local", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 303)

        response = self.client.post(
            f"/web/tickets/{ids['ticket_id']}/comments",
            data={"text": ""},
            files=[("voice_messages", ("voice.ogg", b"OggSvoice", "audio/ogg"))],
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

        detail = self.client.get(f"/web/tickets/{ids['ticket_id']}?tab=overview")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("<audio", detail.text)
        self.assertIn("/comment-media/", detail.text)

    def test_comment_media_moves_with_archive_and_restore(self):
        ids = self.seed_ticket_context()

        with main.SessionLocal() as db:
            comment, media_items, _ = asyncio.run(
                main.create_comment_with_media_async(
                    db=db,
                    ticket_id=int(ids["ticket_id"]),
                    author_id=int(ids["user_id"]),
                    text="",
                    photos=[
                        UploadFile(
                            filename="photo.png",
                            file=BytesIO(b"\x89PNG\r\narchive-photo"),
                            headers={"content-type": "image/png"},
                        )
                    ],
                )
            )
            db.commit()
            db.refresh(comment)
            for item in media_items:
                db.refresh(item)

            media_item = media_items[0]
            original_path = media_item.file_path
            original_disk_path = main.resolve_attachment_disk_path(original_path)
            self.assertIsNotNone(original_disk_path)
            self.assertTrue(original_disk_path.exists())

            ticket = db.get(main.Ticket, int(ids["ticket_id"]))
            company = db.get(main.Company, int(ids["company_id"]))
            ticket.status = main.TicketStatus.done
            main.archive_ticket(db, ticket, actor_id=int(ids["user_id"]), company=company)
            db.commit()
            db.refresh(media_item)

            archived_path = media_item.file_path
            archived_disk_path = main.resolve_attachment_disk_path(archived_path)
            self.assertIn("/_archive/", archived_path)
            self.assertIsNotNone(archived_disk_path)
            self.assertTrue(archived_disk_path.exists())
            self.assertFalse(original_disk_path.exists())

            main.restore_ticket_from_archive(db, ticket, actor_id=int(ids["user_id"]))
            db.commit()
            db.refresh(media_item)

            restored_path = media_item.file_path
            restored_disk_path = main.resolve_attachment_disk_path(restored_path)
            self.assertNotIn("/_archive/", restored_path)
            self.assertIsNotNone(restored_disk_path)
            self.assertTrue(restored_disk_path.exists())


if __name__ == "__main__":
    unittest.main()
