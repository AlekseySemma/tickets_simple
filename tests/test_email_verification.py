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


class EmailVerificationTests(unittest.TestCase):
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

    def seed_invite(self) -> str:
        with main.SessionLocal() as db:
            company = main.Company(name="Acme")
            db.add(company)
            db.flush()
            admin = main.User(
                email="admin@acme.local",
                name="Admin",
                password_hash=main.hash_password("pass"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(admin)
            db.flush()
            invite = main.RegistrationInvite(
                token="invite-token",
                role=main.Role.executor,
                company_id=company.id,
                created_by=admin.id,
            )
            db.add(invite)
            db.commit()
            return invite.token

    def test_invite_registration_blocks_login_until_email_verified(self):
        invite_token = self.seed_invite()

        response = self.client.post(
            "/web/register",
            data={
                "token": invite_token,
                "name": "Ivan",
                "email": "ivan@example.com",
                "password": "secret123",
            },
        )
        self.assertEqual(response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "ivan@example.com").first()
            self.assertIsNotNone(user)
            self.assertFalse(user.email_verified)
            self.assertIsNotNone(user.email_verification_token)

        web_login = self.client.post(
            "/web/login",
            data={"email": "ivan@example.com", "password": "secret123"},
        )
        self.assertEqual(web_login.status_code, 403)

        api_login = self.client.post(
            "/auth/login",
            data={"username": "ivan@example.com", "password": "secret123"},
        )
        self.assertEqual(api_login.status_code, 403)

    def test_email_verification_allows_login(self):
        invite_token = self.seed_invite()
        self.client.post(
            "/web/register",
            data={
                "token": invite_token,
                "name": "Olga",
                "email": "olga@example.com",
                "password": "secret123",
            },
        )

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "olga@example.com").first()
            self.assertIsNotNone(user)
            verify_token = user.email_verification_token

        verify_response = self.client.get(f"/web/verify-email?token={verify_token}")
        self.assertEqual(verify_response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "olga@example.com").first()
            self.assertTrue(user.email_verified)
            self.assertIsNone(user.email_verification_token)

        api_login = self.client.post(
            "/auth/login",
            data={"username": "olga@example.com", "password": "secret123"},
        )
        self.assertEqual(api_login.status_code, 200)
        self.assertIn("access_token", api_login.json())

    def test_resend_verification_rotates_token(self):
        invite_token = self.seed_invite()
        self.client.post(
            "/web/register",
            data={
                "token": invite_token,
                "name": "Petr",
                "email": "petr@example.com",
                "password": "secret123",
            },
        )

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "petr@example.com").first()
            self.assertIsNotNone(user)
            old_token = user.email_verification_token

        resend_response = self.client.post(
            "/web/verify-email/resend",
            data={"email": "petr@example.com"},
        )
        self.assertEqual(resend_response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "petr@example.com").first()
            self.assertFalse(user.email_verified)
            self.assertNotEqual(old_token, user.email_verification_token)
            self.assertIsNotNone(user.email_verification_sent_at)

    def test_company_registration_creates_unverified_owner(self):
        response = self.client.post(
            "/web/register-company",
            data={
                "company_name": "New Co",
                "admin_name": "Founder",
                "admin_email": "founder@example.com",
                "admin_password": "secret123",
            },
        )
        self.assertEqual(response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "founder@example.com").first()
            self.assertIsNotNone(user)
            self.assertFalse(user.email_verified)
            self.assertEqual(user.role, main.Role.admin)
            self.assertIsNotNone(user.email_verification_token)


if __name__ == "__main__":
    unittest.main()
