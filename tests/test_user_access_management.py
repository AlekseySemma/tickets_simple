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


class UserAccessManagementTests(unittest.TestCase):
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

    def seed_admin(self) -> dict[str, int]:
        with main.SessionLocal() as db:
            company = main.Company(name="Access Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="owner@example.com",
                name="Owner",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=False,
            )
            db.add(admin)
            db.commit()
            return {"company_id": company.id, "admin_id": admin.id}

    def login_web(self, email: str = "owner@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_admin_can_enable_self_as_assignable_executor(self):
        ids = self.seed_admin()
        self.login_web()

        response = self.client.post(
            f"/web/users/{ids['admin_id']}/update",
            data={
                "name": "Owner",
                "email": "owner@example.com",
                "role": "ADMIN",
                "role_label": "Частный мастер",
                "is_assignable_executor": "1",
                "show_receipts_accounting_mode": "1",
                "can_view_all_tickets": "1",
                "can_create_tickets": "1",
                "can_close_tickets": "1",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/users?ok=updated")
        with main.SessionLocal() as db:
            admin = db.get(main.User, ids["admin_id"])
            self.assertTrue(admin.is_assignable_executor)
            self.assertEqual(admin.role_label, "Частный мастер")

        page = self.client.get("/web/ticket-templates")
        self.assertEqual(page.status_code, 200)
        self.assertIn(f'<option value="{ids["admin_id"]}">Owner</option>', page.text)

    def test_role_template_applies_to_new_user(self):
        self.seed_admin()
        self.login_web()

        create_template_response = self.client.post(
            "/web/users/templates/create",
            data={
                "name": "Старший мастер",
                "access_level": "EXECUTOR",
                "role_label": "",
                "is_assignable_executor": "1",
                "show_receipts_accounting_mode": "1",
                "can_view_all_tickets": "1",
                "can_create_tickets": "1",
                "can_close_tickets": "1",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )
        self.assertEqual(create_template_response.status_code, 303)
        self.assertEqual(create_template_response.headers["location"], "/web/users?ok=template_created")

        with main.SessionLocal() as db:
            template = db.query(main.RoleTemplate).filter(main.RoleTemplate.name == "Старший мастер").first()
            self.assertIsNotNone(template)
            template_id = template.id

        create_user_response = self.client.post(
            "/web/users/create",
            data={
                "name": "Tech User",
                "email": "tech@example.com",
                "password": "secret123",
                "role": "EXECUTOR",
                "role_template_id": str(template_id),
                "role_label": "",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )
        self.assertEqual(create_user_response.status_code, 303)
        self.assertEqual(create_user_response.headers["location"], "/web/users?ok=created")

        with main.SessionLocal() as db:
            created = db.query(main.User).filter(main.User.email == "tech@example.com").first()
            self.assertIsNotNone(created)
            self.assertEqual(created.role, main.Role.executor)
            self.assertEqual(created.role_label, "Старший мастер")
            self.assertTrue(created.is_assignable_executor)
            self.assertTrue(created.show_receipts_accounting_mode)
            self.assertTrue(created.can_view_all_tickets)
            self.assertTrue(created.can_create_tickets)
            self.assertTrue(created.can_close_tickets)


if __name__ == "__main__":
    unittest.main()
