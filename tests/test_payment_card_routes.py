import os
import unittest

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


class PaymentCardRoutesTests(unittest.TestCase):
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

    def seed_user(self, email: str = "cards@example.com") -> int:
        with main.SessionLocal() as db:
            company = main.Company(name=f"Cards Co {email}")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Cards User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()
            return user.id

    def login_web(self, email: str = "cards@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_create_card_redirects_to_selected_section(self):
        self.seed_user()
        self.login_web()

        response = self.client.post(
            "/web/payment-cards/create",
            data={"name": "Alpha 1234", "section": "receipts"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/settings?section=receipts&card_created=1")

    def test_delete_card_redirects_to_selected_section(self):
        user_id = self.seed_user()
        self.login_web()
        with main.SessionLocal() as db:
            user = db.get(main.User, user_id)
            card = main.PaymentCard(company_id=user.company_id, owner_user_id=user.id, name="Delete Me", is_active=True)
            db.add(card)
            db.commit()
            card_id = card.id

        response = self.client.post(
            f"/web/payment-cards/{card_id}/delete",
            data={"section": "receipts"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/settings?section=receipts&card_deleted=1")
        with main.SessionLocal() as db:
            self.assertIsNone(db.get(main.PaymentCard, card_id))

    def test_delete_used_card_is_blocked(self):
        user_id = self.seed_user()
        self.login_web()
        with main.SessionLocal() as db:
            user = db.get(main.User, user_id)
            card = main.PaymentCard(company_id=user.company_id, owner_user_id=user.id, name="Primary", is_active=True)
            db.add(card)
            db.flush()
            user.preferred_payment_card_id = card.id
            db.commit()
            card_id = card.id

        response = self.client.post(
            f"/web/payment-cards/{card_id}/delete",
            data={"section": "receipts"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/settings?section=receipts&card_delete_error=in_use")
        with main.SessionLocal() as db:
            self.assertIsNotNone(db.get(main.PaymentCard, card_id))


if __name__ == "__main__":
    unittest.main()
