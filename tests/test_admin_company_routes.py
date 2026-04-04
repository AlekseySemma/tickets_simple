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


class AdminCompanyRoutesTests(unittest.TestCase):
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

    def seed_platform_admin(self, email: str = "platform@example.com", password: str = "secret123") -> int:
        with main.SessionLocal() as db:
            admin = main.User(
                email=email,
                name="Platform Admin",
                password_hash=main.hash_password(password),
                role=main.Role.platform_admin,
                email_verified=True,
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            return admin.id

    def login_web(self, email: str = "platform@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_admin_companies_page_renders_counts(self):
        self.seed_platform_admin()
        with main.SessionLocal() as db:
            company = main.Company(name="Admin Co")
            db.add(company)
            db.flush()
            company_user = main.User(
                email="worker@example.com",
                name="Worker",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(company_user)
            db.flush()
            unit_type = main.UnitType(company_id=company.id, name="Узел")
            db.add(unit_type)
            db.flush()
            org_unit = main.OrgUnit(
                company_id=company.id,
                name="HQ",
                unit_type_id=unit_type.id,
            )
            db.add(org_unit)
            db.flush()
            project = main.Project(name="Admin Project", company_id=company.id)
            db.add(project)
            db.flush()
            ticket = main.Ticket(
                company_id=company.id,
                title="Admin ticket",
                project_id=project.id,
                created_by=company_user.id,
                status=main.TicketStatus.new,
            )
            db.add(ticket)
            db.commit()

        self.login_web()
        response = self.client.get("/web/admin/companies")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Admin Co", response.text)
        self.assertIn(">1<", response.text)

    def test_admin_company_update_persists(self):
        self.seed_platform_admin()
        with main.SessionLocal() as db:
            company = main.Company(name="Old Name")
            db.add(company)
            db.commit()
            company_id = company.id

        self.login_web()
        response = self.client.post(
            f"/web/admin/companies/{company_id}/update",
            data={
                "name": "New Name",
                "deadline_soon_warning_minutes": "45",
                "archive_retention_days_default": "14",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            f"/web/admin/companies/{company_id}/settings?ok=company_updated",
        )
        with main.SessionLocal() as db:
            company = db.get(main.Company, company_id)
            self.assertEqual(company.name, "New Name")
            self.assertEqual(company.deadline_soon_warning_minutes, 45)
            self.assertEqual(company.archive_retention_days_default, 14)

    def test_admin_company_user_create_persists(self):
        self.seed_platform_admin()
        with main.SessionLocal() as db:
            company = main.Company(name="Create User Co")
            db.add(company)
            db.commit()
            company_id = company.id

        self.login_web()
        response = self.client.post(
            f"/web/admin/companies/{company_id}/users/create",
            data={
                "name": "Executor User",
                "email": "executor@example.com",
                "password": "secret123",
                "role": "EXECUTOR",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            f"/web/admin/companies/{company_id}/settings?ok=user_created",
        )
        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "executor@example.com").one()
            self.assertEqual(user.company_id, company_id)
            self.assertEqual(user.role, main.Role.executor)

    def test_admin_company_user_delete_removes_safe_user(self):
        self.seed_platform_admin()
        with main.SessionLocal() as db:
            company = main.Company(name="Delete User Co")
            db.add(company)
            db.flush()
            user = main.User(
                email="delete-me@example.com",
                name="Delete Me",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()
            company_id = company.id
            user_id = user.id

        self.login_web()
        response = self.client.post(
            f"/web/admin/companies/{company_id}/users/{user_id}/delete",
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            f"/web/admin/companies/{company_id}/settings?ok=user_deleted",
        )
        with main.SessionLocal() as db:
            self.assertIsNone(db.get(main.User, user_id))


if __name__ == "__main__":
    unittest.main()
