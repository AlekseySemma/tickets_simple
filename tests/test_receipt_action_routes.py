import os
import unittest
from datetime import date
from decimal import Decimal

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


class ReceiptActionRoutesTests(unittest.TestCase):
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

    def login_web(self, email: str = "receipts@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def seed_receipt_context(self, email: str = "receipts@example.com") -> dict[str, int]:
        with main.SessionLocal() as db:
            company = main.Company(name=f"Receipts Co {email}")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Receipts User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()
            project = main.Project(name="Project A", company_id=company.id)
            card = main.PaymentCard(company_id=company.id, owner_user_id=user.id, name="BK 1111", is_active=True)
            db.add(project)
            db.add(card)
            db.flush()
            receipt = main.Receipt(
                company_id=company.id,
                project_id=project.id,
                card_id=card.id,
                created_by=user.id,
                status=main.ReceiptStatus.new,
                comment="Initial",
                amount=Decimal("123.45"),
                receipt_date=date(2026, 4, 1),
            )
            db.add(receipt)
            db.commit()
            return {
                "user_id": user.id,
                "company_id": company.id,
                "project_id": project.id,
                "card_id": card.id,
                "receipt_id": receipt.id,
            }

    def test_receipt_status_update_sets_processed_fields(self):
        ids = self.seed_receipt_context()
        self.login_web()

        response = self.client.post(
            f"/web/receipts/{ids['receipt_id']}/status",
            data={"status": main.ReceiptStatus.accepted.value, "next": "/web/receipts?mode=accounting"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/receipts?mode=accounting")
        with main.SessionLocal() as db:
            receipt = db.get(main.Receipt, ids["receipt_id"])
            self.assertEqual(receipt.status, main.ReceiptStatus.accepted)
            self.assertEqual(receipt.processed_by, ids["user_id"])
            self.assertIsNotNone(receipt.processed_at)

    def test_receipt_edit_updates_fields_and_redirects(self):
        ids = self.seed_receipt_context()
        self.login_web()
        with main.SessionLocal() as db:
            company_id = ids["company_id"]
            user_id = ids["user_id"]
            project = main.Project(name="Project B", company_id=company_id)
            card = main.PaymentCard(company_id=company_id, owner_user_id=user_id, name="BK 2222", is_active=True)
            db.add(project)
            db.add(card)
            db.commit()
            next_project_id = project.id
            next_card_id = card.id

        response = self.client.post(
            f"/web/receipts/{ids['receipt_id']}/edit",
            data={
                "next": "/web/receipts?mode=field",
                "project_id": str(next_project_id),
                "card_id": str(next_card_id),
                "comment": "Updated comment",
                "amount": "456.78",
                "receipt_date": "2026-04-02",
                "category": "Fuel",
                "supplier": "Shell",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/receipts?mode=field&ok=updated")
        with main.SessionLocal() as db:
            receipt = db.get(main.Receipt, ids["receipt_id"])
            self.assertEqual(receipt.project_id, next_project_id)
            self.assertEqual(receipt.card_id, next_card_id)
            self.assertEqual(receipt.comment, "Updated comment")
            self.assertEqual(receipt.amount, Decimal("456.78"))
            self.assertEqual(receipt.receipt_date, date(2026, 4, 2))
            self.assertEqual(receipt.category, "Fuel")
            self.assertEqual(receipt.supplier, "Shell")

    def test_receipt_delete_removes_receipt(self):
        ids = self.seed_receipt_context()
        self.login_web()

        response = self.client.post(
            f"/web/receipts/{ids['receipt_id']}/delete",
            data={"next": "/web/receipts?mode=field"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/receipts?mode=field&ok=deleted")
        with main.SessionLocal() as db:
            self.assertIsNone(db.get(main.Receipt, ids["receipt_id"]))

    def test_receipt_bulk_status_updates_multiple_items(self):
        ids = self.seed_receipt_context()
        self.login_web()
        with main.SessionLocal() as db:
            receipt2 = main.Receipt(
                company_id=ids["company_id"],
                project_id=ids["project_id"],
                card_id=ids["card_id"],
                created_by=ids["user_id"],
                status=main.ReceiptStatus.new,
                comment="Second",
            )
            db.add(receipt2)
            db.commit()
            receipt2_id = receipt2.id

        response = self.client.post(
            "/web/receipts/status/bulk",
            data={
                "status": main.ReceiptStatus.rejected.value,
                "next": "/web/receipts?mode=accounting",
                "receipt_ids": [str(ids["receipt_id"]), str(receipt2_id)],
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/receipts?mode=accounting")
        with main.SessionLocal() as db:
            first = db.get(main.Receipt, ids["receipt_id"])
            second = db.get(main.Receipt, receipt2_id)
            self.assertEqual(first.status, main.ReceiptStatus.rejected)
            self.assertEqual(second.status, main.ReceiptStatus.rejected)

    def test_receipt_bulk_delete_removes_selected_items(self):
        ids = self.seed_receipt_context()
        self.login_web()
        with main.SessionLocal() as db:
            receipt2 = main.Receipt(
                company_id=ids["company_id"],
                project_id=ids["project_id"],
                card_id=ids["card_id"],
                created_by=ids["user_id"],
                status=main.ReceiptStatus.new,
                comment="Second",
            )
            db.add(receipt2)
            db.commit()
            receipt2_id = receipt2.id

        response = self.client.post(
            "/web/receipts/delete/bulk",
            data={
                "next": "/web/receipts?mode=accounting",
                "receipt_ids": [str(ids["receipt_id"]), str(receipt2_id)],
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/receipts?mode=accounting&ok=deleted")
        with main.SessionLocal() as db:
            self.assertIsNone(db.get(main.Receipt, ids["receipt_id"]))
            self.assertIsNone(db.get(main.Receipt, receipt2_id))


if __name__ == "__main__":
    unittest.main()
