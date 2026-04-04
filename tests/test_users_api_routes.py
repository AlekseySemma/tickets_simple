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


class UsersApiRoutesTests(unittest.TestCase):
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

    def seed_admin(self, email: str = "api-admin@example.com") -> dict[str, int | str]:
        with main.SessionLocal() as db:
            company = main.Company(name="Users API Co")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="API Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            token = main.create_access_token(str(user.id), main.get_user_auth_token_version(user))
            return {"company_id": company.id, "user_id": user.id, "token": token}

    def auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def test_users_me_returns_current_user(self):
        user = self.seed_admin()

        response = self.client.get(
            "/users/me",
            headers=self.auth_headers(user["token"]),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], user["user_id"])
        self.assertEqual(response.json()["role"], main.Role.admin.value)

    def test_users_create_creates_executor(self):
        admin = self.seed_admin()

        response = self.client.post(
            "/users",
            headers=self.auth_headers(admin["token"]),
            json={
                "email": "executor-api@example.com",
                "name": "Executor API",
                "password": "secret123",
                "role": main.Role.executor.value,
                "bk_last4": "1234",
                "notify_receipt_created": False,
                "is_assignable_executor": True,
                "can_view_all_tickets": False,
                "can_create_tickets": True,
                "can_close_tickets": True,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["email"], "executor-api@example.com")
        self.assertEqual(response.json()["role"], main.Role.executor.value)
        self.assertEqual(response.json()["bk_last4"], "1234")
        self.assertFalse(response.json()["notify_receipt_created"])
        self.assertTrue(response.json()["is_assignable_executor"])
        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "executor-api@example.com").one()
            self.assertEqual(user.company_id, admin["company_id"])
            self.assertEqual(user.role, main.Role.executor)


if __name__ == "__main__":
    unittest.main()
