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


class UserRoutesTests(unittest.TestCase):
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

    def seed_admin(self, email: str = "users@example.com") -> int:
        with main.SessionLocal() as db:
            company = main.Company(name="Users Co")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Users Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()
            return user.id

    def login_web(self, email: str = "users@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_users_page_renders_for_manager(self):
        self.seed_admin()
        self.login_web()

        response = self.client.get("/web/users")

        self.assertEqual(response.status_code, 200)
        self.assertIn("users/templates/create", response.text)
        self.assertIn("invite", response.text.lower())

    def test_invite_create_redirects_and_persists(self):
        user_id = self.seed_admin()
        self.login_web()

        response = self.client.post(
            "/web/users/invites/create",
            data={"role": "EXECUTOR", "expires_days": "5"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/users?ok=invite_created")
        with main.SessionLocal() as db:
            invite = db.query(main.RegistrationInvite).filter(main.RegistrationInvite.created_by == user_id).first()
            self.assertIsNotNone(invite)
            self.assertEqual(invite.role, main.Role.executor)


if __name__ == "__main__":
    unittest.main()
