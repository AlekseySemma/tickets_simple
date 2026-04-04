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


class TicketCatalogApiRoutesTests(unittest.TestCase):
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

    def seed_admin(self, email: str = "catalog-admin@example.com") -> dict[str, int | str]:
        with main.SessionLocal() as db:
            company = main.Company(name="Catalog API Co")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Catalog Admin",
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

    def test_ticket_types_create_update_delete_roundtrip(self):
        admin = self.seed_admin()

        created = self.client.post(
            "/ticket-types",
            headers=self.auth_headers(admin["token"]),
            json={
                "name": "Repair",
                "description": "Repair tasks",
                "archive_retention_days": 12,
                "is_active": True,
            },
        )
        self.assertEqual(created.status_code, 200)
        ticket_type_id = created.json()["id"]
        self.assertEqual(created.json()["name"], "Repair")

        updated = self.client.patch(
            f"/ticket-types/{ticket_type_id}",
            headers=self.auth_headers(admin["token"]),
            json={"name": "Maintenance", "description": "Updated", "is_active": False},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["name"], "Maintenance")
        self.assertFalse(updated.json()["is_active"])

        deleted = self.client.delete(
            f"/ticket-types/{ticket_type_id}",
            headers=self.auth_headers(admin["token"]),
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json(), {"ok": True})

    def test_ticket_templates_create_update_clear_and_delete_roundtrip(self):
        admin = self.seed_admin()

        type_response = self.client.post(
            "/ticket-types",
            headers=self.auth_headers(admin["token"]),
            json={"name": "Inspection", "description": "Checks", "is_active": True},
        )
        self.assertEqual(type_response.status_code, 200)
        ticket_type_id = type_response.json()["id"]

        created = self.client.post(
            "/ticket-templates",
            headers=self.auth_headers(admin["token"]),
            json={
                "ticket_type_id": ticket_type_id,
                "name": "Monthly inspection",
                "title_template": "Inspect site",
                "description_template": "Run inspection",
                "default_deadline_rule": "in_3_days",
                "is_active": True,
            },
        )
        self.assertEqual(created.status_code, 200)
        template_id = created.json()["id"]
        self.assertEqual(created.json()["name"], "Monthly inspection")

        updated = self.client.patch(
            f"/ticket-templates/{template_id}",
            headers=self.auth_headers(admin["token"]),
            json={"name": "Weekly inspection", "is_active": False},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["name"], "Weekly inspection")
        self.assertFalse(updated.json()["is_active"])

        cleared = self.client.post(
            f"/ticket-templates/{template_id}/clear-keys",
            headers=self.auth_headers(admin["token"]),
            json={},
        )
        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(cleared.json()["deleted_count"], 0)
        self.assertEqual(cleared.json()["period_key"], main.month_period_key())

        deleted = self.client.delete(
            f"/ticket-templates/{template_id}",
            headers=self.auth_headers(admin["token"]),
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
