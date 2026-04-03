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


class TicketTemplateRoutesTests(unittest.TestCase):
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
            company = main.Company(name="Templates Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="templates@example.com",
                name="Templates Admin",
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
                is_assignable_executor=True,
            )
            db.add_all([admin, executor])
            db.flush()
            unit_type = main.UnitType(company_id=company.id, name="Node", code="node", is_active=True)
            ticket_type = main.TicketType(company_id=company.id, name="TO", description=None, is_active=True)
            db.add_all([unit_type, ticket_type])
            db.flush()
            root = main.OrgUnit(company_id=company.id, name="Branch", unit_type_id=unit_type.id, parent_id=None, is_active=True)
            leaf = main.OrgUnit(company_id=company.id, name="Store 1", unit_type_id=unit_type.id, parent_id=None, is_active=True)
            db.add_all([root, leaf])
            db.flush()
            leaf.parent_id = root.id
            db.commit()
            return {
                "company_id": company.id,
                "admin_id": admin.id,
                "executor_id": executor.id,
                "ticket_type_id": ticket_type.id,
                "root_unit_id": root.id,
                "leaf_unit_id": leaf.id,
            }

    def login_web(self) -> None:
        response = self.client.post(
            "/web/login",
            data={"email": "templates@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_ticket_templates_page_renders(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.get("/web/ticket-templates")

        self.assertEqual(response.status_code, 200)
        self.assertIn("/web/ticket-templates/create", response.text)
        self.assertIn(f'<option value="{ids["executor_id"]}">Executor</option>', response.text)

    def test_ticket_templates_create_persists(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            "/web/ticket-templates/create",
            data={
                "name": "Monthly TO",
                "ticket_type_id": str(ids["ticket_type_id"]),
                "title_template": "TO {period}",
                "description_template": "Plan",
                "deadline_mode": "date",
                "deadline_date": "2026-04-30",
                "scope_unit_id": str(ids["root_unit_id"]),
                "default_executor_id": str(ids["executor_id"]),
                "is_active": "1",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/ticket-templates")
        with main.SessionLocal() as db:
            template = db.query(main.TicketTemplate).filter(main.TicketTemplate.name == "Monthly TO").first()
            self.assertIsNotNone(template)
            self.assertEqual(template.default_executor_id, ids["executor_id"])
            self.assertEqual(template.scope_unit_id, ids["root_unit_id"])

    def test_ticket_templates_run_creates_ticket(self):
        ids = self.seed_context()
        with main.SessionLocal() as db:
            template = main.TicketTemplate(
                company_id=ids["company_id"],
                ticket_type_id=ids["ticket_type_id"],
                name="Run Template",
                title_template="Run {period}",
                description_template="Plan {unit_name}",
                default_deadline_rule="2026-04-30",
                default_executor_id=ids["executor_id"],
                scope_unit_id=ids["root_unit_id"],
                is_active=True,
            )
            db.add(template)
            db.commit()
            template_id = template.id
        self.login_web()

        response = self.client.post(
            f"/web/ticket-templates/{template_id}/run",
            data={"period_key": "2026-04"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            "/web/ticket-templates?run_ok=1&run_created=1&run_skipped=0&run_period=2026-04",
        )
        with main.SessionLocal() as db:
            ticket = db.query(main.Ticket).filter(main.Ticket.ticket_template_id == template_id).first()
            self.assertIsNotNone(ticket)
            self.assertEqual(ticket.target_unit_id, ids["leaf_unit_id"])

    def test_ticket_templates_clear_keys_removes_period_entries(self):
        ids = self.seed_context()
        with main.SessionLocal() as db:
            template = main.TicketTemplate(
                company_id=ids["company_id"],
                ticket_type_id=ids["ticket_type_id"],
                name="Keys Template",
                title_template="Keys {period}",
                description_template=None,
                default_deadline_rule=None,
                default_executor_id=ids["executor_id"],
                scope_unit_id=ids["root_unit_id"],
                is_active=True,
            )
            db.add(template)
            db.flush()
            db.add(
                main.TicketGenerationKey(
                    company_id=ids["company_id"],
                    ticket_template_id=template.id,
                    target_unit_id=ids["leaf_unit_id"],
                    period_key="2026-04",
                    ticket_id=None,
                )
            )
            db.commit()
            template_id = template.id
        self.login_web()

        response = self.client.post(
            f"/web/ticket-templates/{template_id}/clear-keys",
            data={"period_key": "2026-04"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            "/web/ticket-templates?keys_cleared=1&keys_period=2026-04&keys_deleted=1",
        )
        with main.SessionLocal() as db:
            count = (
                db.query(main.TicketGenerationKey)
                .filter(main.TicketGenerationKey.ticket_template_id == template_id)
                .count()
            )
            self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
