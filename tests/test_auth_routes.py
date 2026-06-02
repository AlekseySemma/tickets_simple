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


class AuthRoutesTests(unittest.TestCase):
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
        os.environ["PUBLIC_COMPANY_REGISTRATION_ENABLED"] = "0"

    def test_auth_bootstrap_creates_platform_admin(self):
        response = self.client.post(
            "/auth/bootstrap",
            json={
                "company_name": "Platform Root",
                "admin_name": "Root",
                "admin_email": "root@example.com",
                "admin_password": "secret123",
            },
        )

        self.assertEqual(response.status_code, 200)
        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "root@example.com").first()
            self.assertIsNotNone(user)
            self.assertEqual(user.role, main.Role.platform_admin)
            self.assertTrue(user.email_verified)

    def test_auth_register_company_creates_unverified_owner(self):
        os.environ["PUBLIC_COMPANY_REGISTRATION_ENABLED"] = "1"
        response = self.client.post(
            "/auth/register-company",
            json={
                "company_name": "API Company",
                "admin_name": "Owner",
                "admin_email": "owner@example.com",
                "admin_password": "secret123",
            },
        )

        self.assertEqual(response.status_code, 200)
        with main.SessionLocal() as db:
            company = db.query(main.Company).filter(main.Company.name == "API Company").first()
            user = db.query(main.User).filter(main.User.email == "owner@example.com").first()
            self.assertIsNotNone(company)
            self.assertIsNotNone(user)
            self.assertEqual(user.company_id, company.id)
            self.assertEqual(user.role, main.Role.admin)
            self.assertFalse(user.email_verified)
            self.assertIsNotNone(user.email_verification_token)

    def test_auth_register_company_returns_404_when_public_signup_disabled(self):
        response = self.client.post(
            "/auth/register-company",
            json={
                "company_name": "Blocked Co",
                "admin_name": "Owner",
                "admin_email": "blocked@example.com",
                "admin_password": "secret123",
            },
        )

        self.assertEqual(response.status_code, 404)
        with main.SessionLocal() as db:
            self.assertIsNone(db.query(main.Company).filter(main.Company.name == "Blocked Co").first())
            self.assertIsNone(db.query(main.User).filter(main.User.email == "blocked@example.com").first())


if __name__ == "__main__":
    unittest.main()
