import io
import os
import unittest
import zipfile
from datetime import date
from decimal import Decimal
from pathlib import Path

from fastapi.testclient import TestClient
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


class ReceiptExportRoutesTests(unittest.TestCase):
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
        self.client.cookies.clear()
        self.created_files: list[Path] = []

    def tearDown(self):
        for path in self.created_files:
            try:
                if path.exists():
                    path.unlink()
            except OSError:
                pass

    def login_web(self, email: str = "exports@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def seed_receipt_with_file(self, email: str = "exports@example.com") -> dict[str, int]:
        filename = f"test_receipt_export_{email.replace('@', '_').replace('.', '_')}.txt"
        disk_path = main.UPLOAD_DIR / filename
        disk_path.parent.mkdir(parents=True, exist_ok=True)
        disk_path.write_text("receipt export payload", encoding="utf-8")
        self.created_files.append(disk_path)

        with main.SessionLocal() as db:
            company = main.Company(name=f"Receipt Exports {email}")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Export User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()
            project = main.Project(name="Project Export", company_id=company.id)
            card = main.PaymentCard(company_id=company.id, owner_user_id=user.id, name="BK 4444", is_active=True)
            db.add(project)
            db.add(card)
            db.flush()
            receipt = main.Receipt(
                company_id=company.id,
                project_id=project.id,
                card_id=card.id,
                created_by=user.id,
                status=main.ReceiptStatus.accepted,
                comment="Fuel check",
                amount=Decimal("321.00"),
                receipt_date=date(2026, 4, 2),
            )
            db.add(receipt)
            db.flush()
            receipt_file = main.ReceiptFile(
                receipt_id=receipt.id,
                uploader_id=user.id,
                file_path=f"/uploads/{filename}",
                original_name="receipt.txt",
            )
            db.add(receipt_file)
            db.commit()
            return {"receipt_id": receipt.id, "file_id": receipt_file.id}

    def test_receipt_file_download_returns_attachment(self):
        ids = self.seed_receipt_with_file()
        self.login_web()

        response = self.client.get(
            f"/web/receipt-files/{ids['file_id']}?download=1",
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers.get("content-disposition", ""))
        self.assertIn(b"receipt export payload", response.content)

    def test_receipts_export_xlsx_returns_attachment(self):
        self.seed_receipt_with_file()
        self.login_web()

        response = self.client.get("/web/receipts/export.xlsx", follow_redirects=False)

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment;", response.headers.get("content-disposition", ""))
        self.assertGreater(len(response.content), 0)

    def test_receipts_export_zip_contains_uploaded_file(self):
        self.seed_receipt_with_file()
        self.login_web()

        response = self.client.get("/web/receipts/export.zip", follow_redirects=False)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("content-type"), "application/zip")
        archive = zipfile.ZipFile(io.BytesIO(response.content))
        names = archive.namelist()
        self.assertEqual(len(names), 1)
        self.assertIn(b"receipt export payload", archive.read(names[0]))


if __name__ == "__main__":
    unittest.main()
