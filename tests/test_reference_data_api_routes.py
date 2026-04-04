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


class ReferenceDataApiRoutesTests(unittest.TestCase):
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

    def seed_user(self, *, role=main.Role.admin, email="ref@example.com") -> dict[str, int | str]:
        with main.SessionLocal() as db:
            company = main.Company(name="Reference Co")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Reference Admin",
                password_hash=main.hash_password("secret123"),
                role=role,
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

    def test_projects_create_and_list_roundtrip(self):
        user = self.seed_user()

        created = self.client.post(
            "/projects",
            headers=self.auth_headers(user["token"]),
            json={"name": "HQ", "description": "Main project"},
        )

        self.assertEqual(created.status_code, 200)
        self.assertEqual(created.json()["name"], "HQ")

        listed = self.client.get(
            "/projects",
            headers=self.auth_headers(user["token"]),
        )

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()), 1)
        self.assertEqual(listed.json()[0]["name"], "HQ")

    def test_departments_create_update_delete_roundtrip(self):
        user = self.seed_user()

        created = self.client.post(
            "/departments",
            headers=self.auth_headers(user["token"]),
            json={"name": " Support ", "is_active": True},
        )
        self.assertEqual(created.status_code, 200)
        department_id = created.json()["id"]
        self.assertEqual(created.json()["name"], "Support")

        updated = self.client.patch(
            f"/departments/{department_id}",
            headers=self.auth_headers(user["token"]),
            json={"name": "Field Support", "is_active": False},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["name"], "Field Support")
        self.assertFalse(updated.json()["is_active"])

        deleted = self.client.delete(
            f"/departments/{department_id}",
            headers=self.auth_headers(user["token"]),
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json(), {"ok": True})

    def test_unit_types_create_update_delete_roundtrip(self):
        user = self.seed_user()

        created = self.client.post(
            "/unit-types",
            headers=self.auth_headers(user["token"]),
            json={"name": "Shop", "code": "SHOP", "is_active": True},
        )
        self.assertEqual(created.status_code, 200)
        unit_type_id = created.json()["id"]
        self.assertEqual(created.json()["code"], "SHOP")

        updated = self.client.patch(
            f"/unit-types/{unit_type_id}",
            headers=self.auth_headers(user["token"]),
            json={"name": "Store", "code": "STORE", "is_active": False},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["name"], "Store")
        self.assertEqual(updated.json()["code"], "STORE")
        self.assertFalse(updated.json()["is_active"])

        deleted = self.client.delete(
            f"/unit-types/{unit_type_id}",
            headers=self.auth_headers(user["token"]),
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
