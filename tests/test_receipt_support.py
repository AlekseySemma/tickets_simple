import os
import tempfile
import unittest
from datetime import date
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


class ReceiptSupportTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def test_build_receipt_original_name_and_preferred_card(self):
        original_name = main.build_receipt_original_name(
            receipt_date_value=date(2026, 4, 5),
            card_name="Business Card 7788",
            project_name='North / Depot: "A"',
            source_filename="scan.JPG",
            fallback_card_id=12,
        )
        self.assertEqual(original_name, "2026-04-05_БК7788_North _ Depot_ _A.jpg")

        cards = [
            type("Card", (), {"id": 1, "name": "BK 1234", "is_active": True})(),
            type("Card", (), {"id": 2, "name": "Corporate 7788", "is_active": True})(),
        ]
        self.assertEqual(main.resolve_preferred_card_id(cards, "7788"), 2)

    def test_build_receipts_query_filters_for_executor(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Receipt Support Co")
            db.add(company)
            db.flush()
            executor = main.User(
                email="receipt-support@example.com",
                name="Receipt Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
            )
            other = main.User(
                email="other-receipt@example.com",
                name="Other User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(name="Receipt Project", company_id=company.id)
            db.add_all([executor, other, project])
            db.flush()
            card = main.PaymentCard(company_id=company.id, owner_user_id=executor.id, name="BK 1111", is_active=True)
            db.add(card)
            db.flush()
            own_receipt = main.Receipt(
                company_id=company.id,
                project_id=project.id,
                card_id=card.id,
                created_by=executor.id,
                status=main.ReceiptStatus.new,
                comment="Fuel",
            )
            foreign_receipt = main.Receipt(
                company_id=company.id,
                project_id=project.id,
                card_id=card.id,
                created_by=other.id,
                status=main.ReceiptStatus.accepted,
                comment="Hotel",
            )
            db.add_all([own_receipt, foreign_receipt])
            db.commit()

            results = main.build_receipts_query(db, executor, q="Fuel").all()

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].comment, "Fuel")


if __name__ == "__main__":
    unittest.main()
