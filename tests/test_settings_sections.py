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


class SettingsSectionsTests(unittest.TestCase):
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

    def seed_user(self, email: str = "settings@example.com", role=main.Role.admin) -> int:
        with main.SessionLocal() as db:
            company = main.Company(name="Settings Co")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Settings User",
                password_hash=main.hash_password("secret123"),
                role=role,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()
            db.add(main.PaymentCard(company_id=company.id, owner_user_id=user.id, name="BK 1234", is_active=True))
            db.commit()
            return user.id

    def login_web(self, email: str = "settings@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_settings_root_shows_section_list_without_forms(self):
        self.seed_user()
        self.login_web()

        response = self.client.get("/web/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn("/web/settings?section=general", response.text)
        self.assertIn("/web/settings?section=notifications", response.text)
        self.assertIn("/web/settings?section=receipts", response.text)
        self.assertIn("/web/settings?section=archive", response.text)
        self.assertIn("/web/settings?section=system", response.text)
        self.assertIn("/web/settings?section=directories", response.text)
        self.assertNotIn('action="/web/settings/deadline-warning"', response.text)
        self.assertNotIn('action="/web/settings/archive-retention"', response.text)

    def test_selected_section_renders_only_its_forms(self):
        self.seed_user()
        self.login_web()

        response = self.client.get("/web/settings?section=notifications")

        self.assertEqual(response.status_code, 200)
        self.assertIn('action="/web/settings/watcher-comments"', response.text)
        self.assertIn('action="/web/settings/receipt-notifications"', response.text)
        self.assertIn('id="enable-push-btn"', response.text)
        self.assertNotIn('action="/web/settings/archive-retention"', response.text)
        self.assertNotIn('action="/web/settings/preferred-card"', response.text)

    def test_archive_update_redirects_back_to_archive_section(self):
        self.seed_user()
        self.login_web()

        response = self.client.post(
            "/web/settings/archive-retention",
            data={"archive_retention_days_default": "30", "section": "archive"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/settings?section=archive&archive_retention_saved=1")

    def test_card_create_redirects_back_to_receipts_section(self):
        self.seed_user()
        self.login_web()

        response = self.client.post(
            "/web/payment-cards/create",
            data={"name": "Tinkoff 5678", "section": "receipts"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/settings?section=receipts&card_created=1")


if __name__ == "__main__":
    unittest.main()
