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


class TicketCreateRoutesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        cls.client_cm = TestClient(main.app)
        cls.client = cls.client_cm.__enter__()
        cls.original_org_v2 = main.ORG_STRUCTURE_V2_ENABLED

    @classmethod
    def tearDownClass(cls):
        main.ORG_STRUCTURE_V2_ENABLED = cls.original_org_v2
        cls.client_cm.__exit__(None, None, None)

    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()
        self.client.cookies.clear()
        main.ORG_STRUCTURE_V2_ENABLED = False

    def tearDown(self):
        main.ORG_STRUCTURE_V2_ENABLED = self.original_org_v2

    def seed_context(self) -> dict[str, int]:
        with main.SessionLocal() as db:
            company = main.Company(name="Create Co")
            db.add(company)
            db.flush()

            admin = main.User(
                email="create-admin@example.com",
                name="Create Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            executor = main.User(
                email="create-executor@example.com",
                name="Create Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                can_view_all_tickets=True,
                is_assignable_executor=True,
            )
            watcher = main.User(
                email="create-watcher@example.com",
                name="Create Watcher",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=True,
            )
            repair_type = main.TicketType(company_id=company.id, name="Ремонт", is_active=True)
            project = main.Project(name="Create Project", company_id=company.id)
            db.add_all([admin, executor, watcher, repair_type, project])
            db.commit()
            return {
                "company_id": company.id,
                "admin_id": admin.id,
                "executor_id": executor.id,
                "watcher_id": watcher.id,
                "repair_type_id": repair_type.id,
                "project_id": project.id,
            }

    def login_web(self, email: str = "create-admin@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_create_ticket_creates_ticket_and_watcher(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            "/web/tickets/create",
            data={
                "title": "Created from web",
                "description": "Created description",
                "project_id": str(ids["project_id"]),
                "executor_id": str(ids["executor_id"]),
                "ticket_type_id": "",
                "department_id": "",
                "deadline_date": "",
                "deadline_time4": "",
                "watcher_user_ids": [str(ids["watcher_id"])],
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web")
        with main.SessionLocal() as db:
            ticket = db.query(main.Ticket).filter(main.Ticket.title == "Created from web").one()
            self.assertEqual(ticket.description, "Created description")
            self.assertEqual(ticket.project_id, ids["project_id"])
            self.assertEqual(ticket.executor_id, ids["executor_id"])
            self.assertEqual(ticket.created_by, ids["admin_id"])
            self.assertEqual(ticket.status, main.TicketStatus.new)
            watcher = (
                db.query(main.TicketWatcher)
                .filter(
                    main.TicketWatcher.ticket_id == ticket.id,
                    main.TicketWatcher.user_id == ids["watcher_id"],
                )
                .first()
            )
            self.assertIsNotNone(watcher)
            log_item = (
                db.query(main.TicketLog)
                .filter(main.TicketLog.ticket_id == ticket.id, main.TicketLog.action == main.LOG_ACTION_CREATED)
                .first()
            )
            self.assertIsNotNone(log_item)

    def test_create_ticket_redirects_on_too_long_title(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            "/web/tickets/create",
            data={
                "title": "X" * (main.MAX_TICKET_TITLE_LEN + 1),
                "project_id": str(ids["project_id"]),
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web?open_create=1&create_error=title_too_long")

    def test_executor_create_form_defaults_to_self_and_repair_type(self):
        ids = self.seed_context()
        self.login_web("create-executor@example.com")

        response = self.client.get("/web?open_create=1")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            f'<option value="{ids["executor_id"]}" selected>Create Executor (create-executor@example.com)</option>',
            response.text,
        )
        self.assertIn(
            f'<option value="{ids["repair_type_id"]}" data-department-id="" selected>Ремонт</option>',
            response.text,
        )


if __name__ == "__main__":
    unittest.main()
