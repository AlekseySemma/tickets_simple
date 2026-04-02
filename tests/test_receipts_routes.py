import os
import unittest
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


class ReceiptsRoutesTests(unittest.TestCase):
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
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()
        self.client.cookies.clear()

    def tearDown(self):
        with main.SessionLocal() as db:
            file_paths = [row[0] for row in db.query(main.ReceiptFile.file_path).all()]
        for stored_path in file_paths:
            disk_path = main.resolve_attachment_disk_path(stored_path)
            if disk_path:
                Path(disk_path).unlink(missing_ok=True)

    def login_web(self, email: str = "receipts-list@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def seed_context(self, email: str = "receipts-list@example.com", *, accounting_mode: bool = True) -> dict[str, int]:
        with main.SessionLocal() as db:
            company = main.Company(name=f"Receipts View {email}")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Receipts User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
                show_receipts_accounting_mode=accounting_mode,
            )
            db.add(user)
            db.flush()
            project = main.Project(name="Receipt Project", company_id=company.id)
            card = main.PaymentCard(company_id=company.id, owner_user_id=user.id, name="BK 9000", is_active=True)
            db.add(project)
            db.add(card)
            db.commit()
            return {"user_id": user.id, "project_id": project.id, "card_id": card.id}

    def test_receipts_page_renders_for_logged_in_user(self):
        self.seed_context()
        self.login_web()

        response = self.client.get("/web/receipts?mode=field")

        self.assertEqual(response.status_code, 200)
        self.assertIn("receipts/create", response.text)
        self.assertIn("Receipt Project", response.text)

    def test_receipts_create_with_upload_redirects_and_saves(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            "/web/receipts/create",
            data={
                "project_id": str(ids["project_id"]),
                "card_id": str(ids["card_id"]),
                "comment": "Created from test",
                "amount": "99.50",
                "receipt_date": "2026-04-02",
                "category": "Fuel",
                "supplier": "Lukoil",
            },
            files={"files": ("receipt.jpg", b"binary-image-data", "image/jpeg")},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/receipts?ok=created&mode=field")
        with main.SessionLocal() as db:
            receipt = db.query(main.Receipt).filter(main.Receipt.comment == "Created from test").first()
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt.project_id, ids["project_id"])
            self.assertEqual(receipt.card_id, ids["card_id"])
            file_row = db.query(main.ReceiptFile).filter(main.ReceiptFile.receipt_id == receipt.id).first()
            self.assertIsNotNone(file_row)
            disk_path = main.resolve_attachment_disk_path(file_row.file_path)
            self.assertIsNotNone(disk_path)
            self.assertTrue(Path(disk_path).exists())


if __name__ == "__main__":
    unittest.main()
