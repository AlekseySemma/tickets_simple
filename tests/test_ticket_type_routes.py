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


class TicketTypeRoutesTests(unittest.TestCase):
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

    def seed_context(self) -> dict[str, int]:
        with main.SessionLocal() as db:
            company = main.Company(name="Type Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="types@example.com",
                name="Types Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            department = main.Department(company_id=company.id, name="Operations", is_active=True)
            db.add_all([admin, department])
            db.commit()
            return {"company_id": company.id, "department_id": department.id}

    def login_web(self) -> None:
        response = self.client.post(
            "/web/login",
            data={"email": "types@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_ticket_types_page_renders(self):
        self.seed_context()
        self.login_web()

        response = self.client.get("/web/ticket-types")

        self.assertEqual(response.status_code, 200)
        self.assertIn("/web/ticket-types/create", response.text)
        self.assertIn("Operations", response.text)

    def test_ticket_types_create_persists(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            "/web/ticket-types/create",
            data={
                "name": "Repair",
                "description": "Repair task",
                "department_id": str(ids["department_id"]),
                "archive_retention_days": "30",
                "is_active": "1",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/ticket-types")
        with main.SessionLocal() as db:
            item = db.query(main.TicketType).filter(main.TicketType.name == "Repair").first()
            self.assertIsNotNone(item)
            self.assertEqual(item.department_id, ids["department_id"])
            self.assertEqual(item.archive_retention_days, 30)

    def test_ticket_types_update_changes_fields(self):
        ids = self.seed_context()
        with main.SessionLocal() as db:
            item = main.TicketType(company_id=ids["company_id"], name="Repair", description=None, is_active=True)
            db.add(item)
            db.commit()
            item_id = item.id
        self.login_web()

        response = self.client.post(
            f"/web/ticket-types/{item_id}/update",
            data={
                "name": "Repair Updated",
                "description": "Updated",
                "department_id": str(ids["department_id"]),
                "archive_retention_days": "45",
                "is_active": "1",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/ticket-types")
        with main.SessionLocal() as db:
            item = db.get(main.TicketType, item_id)
            self.assertEqual(item.name, "Repair Updated")
            self.assertEqual(item.archive_retention_days, 45)
            self.assertEqual(item.department_id, ids["department_id"])

    def test_ticket_types_delete_removes_unused_type(self):
        ids = self.seed_context()
        with main.SessionLocal() as db:
            item = main.TicketType(company_id=ids["company_id"], name="Repair", description=None, is_active=True)
            db.add(item)
            db.commit()
            item_id = item.id
        self.login_web()

        response = self.client.post(
            f"/web/ticket-types/{item_id}/delete",
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/ticket-types")
        with main.SessionLocal() as db:
            self.assertIsNone(db.get(main.TicketType, item_id))


if __name__ == "__main__":
    unittest.main()
