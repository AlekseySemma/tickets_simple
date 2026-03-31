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


class WebAuthRoutesTests(unittest.TestCase):
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

    def seed_verified_user(self, email: str = "web@example.com", password: str = "secret123") -> None:
        with main.SessionLocal() as db:
            company = main.Company(name="Web Auth Co")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Web User",
                password_hash=main.hash_password(password),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()

    def seed_invite(self) -> str:
        with main.SessionLocal() as db:
            company = main.Company(name="Invite Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="admin@invite.local",
                name="Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(admin)
            db.flush()
            invite = main.RegistrationInvite(
                token="web-auth-invite-token",
                role=main.Role.executor,
                company_id=company.id,
                created_by=admin.id,
            )
            db.add(invite)
            db.commit()
            return invite.token

    def test_login_page_renders_logout_message(self):
        response = self.client.get("/web/login?info=logged_out_all")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Сессии на всех устройствах завершены", response.text)

    def test_web_login_sets_cookie_and_redirects(self):
        self.seed_verified_user()

        response = self.client.post(
            "/web/login",
            data={"email": "web@example.com", "password": "secret123"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web")
        self.assertIn("access_token=", response.headers.get("set-cookie", ""))

    def test_register_submit_creates_unverified_user_from_invite(self):
        invite_token = self.seed_invite()

        response = self.client.post(
            "/web/register",
            data={
                "token": invite_token,
                "name": "Worker",
                "email": "worker@example.com",
                "password": "secret123",
            },
        )

        self.assertEqual(response.status_code, 200)
        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "worker@example.com").first()
            self.assertIsNotNone(user)
            self.assertFalse(user.email_verified)
            self.assertEqual(user.role, main.Role.executor)

    def test_web_logout_clears_cookie_and_redirects(self):
        response = self.client.get("/web/logout", follow_redirects=False)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/login")
        self.assertIn("access_token=", response.headers.get("set-cookie", ""))


if __name__ == "__main__":
    unittest.main()
