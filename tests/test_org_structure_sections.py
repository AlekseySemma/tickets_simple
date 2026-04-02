import io
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


class OrgStructureSectionsTests(unittest.TestCase):
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

    def seed_company_data(self) -> None:
        with main.SessionLocal() as db:
            company = main.Company(name="Org Co")
            db.add(company)
            db.flush()

            admin = main.User(
                email="org-admin@example.com",
                name="Org Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            executor = main.User(
                email="executor@example.com",
                name="Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
            )
            db.add_all([admin, executor])
            db.flush()

            department = main.Department(company_id=company.id, name="Service", is_active=True)
            unit_type = main.UnitType(company_id=company.id, name="Филиал", code="branch", is_active=True)
            db.add_all([department, unit_type])
            db.flush()

            unit = main.OrgUnit(
                company_id=company.id,
                name="Москва",
                unit_type_id=unit_type.id,
                parent_id=None,
                is_active=True,
            )
            db.add(unit)
            db.commit()

    def login_web(self) -> None:
        response = self.client.post(
            "/web/login",
            data={"email": "org-admin@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_org_structure_defaults_to_nodes_tab(self):
        self.seed_company_data()
        self.login_web()

        response = self.client.get("/web/org-structure")

        self.assertEqual(response.status_code, 200)
        self.assertIn("/web/org-structure?section=nodes", response.text)
        self.assertIn('action="/web/org-structure/create"', response.text)
        self.assertIn("Список узлов", response.text)
        self.assertNotIn('action="/web/org-structure/assign"', response.text)
        self.assertNotIn('action="/web/org-structure/import-csv"', response.text)

    def test_org_structure_executors_tab_shows_assignment_tools(self):
        self.seed_company_data()
        self.login_web()

        response = self.client.get("/web/org-structure?section=executors")

        self.assertEqual(response.status_code, 200)
        self.assertIn('action="/web/org-structure/assign"', response.text)
        self.assertIn('name="section" value="executors"', response.text)
        self.assertNotIn('action="/web/org-structure/create"', response.text)
        self.assertNotIn('action="/web/org-structure/import-csv"', response.text)

    def test_org_structure_import_error_returns_to_import_tab(self):
        self.seed_company_data()
        self.login_web()

        response = self.client.post(
            "/web/org-structure/import-csv?section=import",
            files={"file": ("org.csv", io.BytesIO(b""), "text/csv")},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/org-structure?section=import&error=import_empty")


if __name__ == "__main__":
    unittest.main()
