import os
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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


class CompanyCleanupTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        self.upload_dir_ctx = tempfile.TemporaryDirectory()
        main.STORAGE_BACKEND = "local"
        main.UPLOAD_DIR = Path(self.upload_dir_ctx.name)
        main.ARCHIVE_UPLOAD_DIR = main.UPLOAD_DIR / main.ARCHIVE_UPLOAD_SUBDIR
        main.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.upload_dir_ctx.cleanup()

    def test_delete_company_with_data_removes_company_records_and_files(self):
        attachment_path = main.UPLOAD_DIR / "attachments" / "cleanup.txt"
        attachment_path.parent.mkdir(parents=True, exist_ok=True)
        attachment_path.write_text("cleanup payload", encoding="utf-8")

        with main.SessionLocal() as db:
            company = main.Company(name="Cleanup Co")
            db.add(company)
            db.flush()

            user = main.User(
                email="cleanup@example.com",
                name="Cleanup User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()

            project = main.Project(name="Cleanup Project", company_id=company.id)
            db.add(project)
            db.flush()

            ticket = main.Ticket(
                title="Cleanup Ticket",
                description="Ticket to remove",
                status=main.TicketStatus.new,
                company_id=company.id,
                project_id=project.id,
                created_by=user.id,
            )
            db.add(ticket)
            db.flush()

            db.add(
                main.Attachment(
                    ticket_id=ticket.id,
                    uploader_id=user.id,
                    file_path="/uploads/attachments/cleanup.txt",
                    original_name="cleanup.txt",
                )
            )
            db.add(main.Notification(company_id=company.id, user_id=user.id, title="Cleanup", body="Body", url="/web"))
            db.commit()
            company_id = company.id

            main.delete_company_with_data(db, company_id)
            db.commit()

        self.assertFalse(attachment_path.exists())
        with main.SessionLocal() as db:
            self.assertEqual(db.query(main.Company).count(), 0)
            self.assertEqual(db.query(main.User).count(), 0)
            self.assertEqual(db.query(main.Ticket).count(), 0)
            self.assertEqual(db.query(main.Attachment).count(), 0)
            self.assertEqual(db.query(main.Notification).count(), 0)


if __name__ == "__main__":
    unittest.main()
