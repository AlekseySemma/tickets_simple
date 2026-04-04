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


class OrgStructureRoutesTests(unittest.TestCase):
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
            company = main.Company(name="Org Routes Co")
            db.add(company)
            db.flush()

            admin = main.User(
                email="org-routes-admin@example.com",
                name="Org Routes Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            executor = main.User(
                email="org-routes-executor@example.com",
                name="Org Routes Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=True,
            )
            unit_type = main.UnitType(company_id=company.id, name="Branch", code="branch", is_active=True)
            department = main.Department(company_id=company.id, name="Ops", is_active=True)
            db.add_all([admin, executor, unit_type, department])
            db.flush()

            unit = main.OrgUnit(
                company_id=company.id,
                name="HQ",
                unit_type_id=unit_type.id,
                parent_id=None,
                is_active=True,
            )
            db.add(unit)
            db.commit()
            return {
                "company_id": company.id,
                "admin_id": admin.id,
                "executor_id": executor.id,
                "unit_id": unit.id,
                "department_id": department.id,
            }

    def login_web(self) -> None:
        response = self.client.post(
            "/web/login",
            data={"email": "org-routes-admin@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_projects_redirects_to_org_structure(self):
        self.seed_context()
        self.login_web()

        response = self.client.get("/web/projects", follow_redirects=False)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/org-structure")

    def test_org_structure_create_creates_child_unit(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            "/web/org-structure/create",
            data={
                "section": "nodes",
                "name": "Branch 1",
                "parent_id": str(ids["unit_id"]),
                "unit_type_name": "Branch",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/org-structure?section=nodes")
        with main.SessionLocal() as db:
            created = (
                db.query(main.OrgUnit)
                .filter(main.OrgUnit.company_id == ids["company_id"], main.OrgUnit.name == "Branch 1")
                .one()
            )
            self.assertEqual(created.parent_id, ids["unit_id"])

    def test_department_create_creates_department(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            "/web/departments/create",
            data={"section": "departments", "name": "Support", "is_active": "1"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/org-structure?section=nodes")
        with main.SessionLocal() as db:
            created = (
                db.query(main.Department)
                .filter(main.Department.company_id == ids["company_id"], main.Department.name == "Support")
                .one()
            )
            self.assertTrue(created.is_active)

    def test_org_structure_toggle_flips_active_flag(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            f"/web/org-structure/{ids['unit_id']}/toggle",
            data={"section": "nodes"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/org-structure?section=nodes")
        with main.SessionLocal() as db:
            unit = db.get(main.OrgUnit, ids["unit_id"])
            self.assertFalse(unit.is_active)


if __name__ == "__main__":
    unittest.main()
