import os
import unittest
from datetime import timedelta

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


class TicketBulkActionsTests(unittest.TestCase):
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
        self.client.cookies.clear()

    def seed_company_with_users(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Bulk Co")
            db.add(company)
            db.flush()

            admin = main.User(
                email="admin@example.com",
                name="Admin",
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
            other_executor = main.User(
                email="other@example.com",
                name="Other",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
            )
            db.add_all([admin, executor, other_executor])
            db.flush()

            project = main.Project(name="Main Project", company_id=company.id)
            db.add(project)
            db.flush()

            done_ticket = main.Ticket(
                title="Done ticket",
                description="ready for archive",
                status=main.TicketStatus.done,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
            )
            new_ticket = main.Ticket(
                title="New ticket",
                description="still active",
                status=main.TicketStatus.new,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
            )
            own_ticket = main.Ticket(
                title="Own ticket",
                description="executor owned",
                status=main.TicketStatus.new,
                company_id=company.id,
                project_id=project.id,
                created_by=executor.id,
            )
            foreign_ticket = main.Ticket(
                title="Foreign ticket",
                description="other executor owned",
                status=main.TicketStatus.new,
                company_id=company.id,
                project_id=project.id,
                created_by=other_executor.id,
            )
            archived_ticket = main.Ticket(
                title="Archived ticket",
                description="in archive",
                status=main.TicketStatus.archived,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
                archived_by=admin.id,
                archived_at=main.local_now(),
                retention_days=30,
                delete_at=main.local_now() + timedelta(days=30),
            )
            db.add_all([done_ticket, new_ticket, own_ticket, foreign_ticket, archived_ticket])
            db.commit()
            return {
                "admin_id": admin.id,
                "executor_id": executor.id,
                "other_executor_id": other_executor.id,
                "project_id": project.id,
                "done_ticket_id": done_ticket.id,
                "new_ticket_id": new_ticket.id,
                "own_ticket_id": own_ticket.id,
                "foreign_ticket_id": foreign_ticket.id,
                "archived_ticket_id": archived_ticket.id,
            }

    def login_web(self, email: str, password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_table_view_renders_bulk_actions_form(self):
        self.seed_company_with_users()
        self.login_web("admin@example.com")

        response = self.client.get("/web?view_mode=table")

        self.assertEqual(response.status_code, 200)
        self.assertIn('id="bulk-ticket-actions-form"', response.text)
        self.assertIn('data-ticket-select-all', response.text)
        self.assertIn('name="ticket_ids"', response.text)

    def test_bulk_archive_archives_only_eligible_tickets(self):
        ids = self.seed_company_with_users()
        self.login_web("admin@example.com")

        response = self.client.post(
            "/web/tickets/bulk-action",
            data={
                "action": "archive",
                "ticket_ids": [str(ids["done_ticket_id"]), str(ids["new_ticket_id"])],
                "next": "/web?view_mode=table",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            "/web?view_mode=table&bulk_ok=1&bulk_action=archive&bulk_done=1&bulk_skipped=1",
        )
        with main.SessionLocal() as db:
            done_ticket = db.get(main.Ticket, ids["done_ticket_id"])
            new_ticket = db.get(main.Ticket, ids["new_ticket_id"])
            self.assertEqual(done_ticket.status, main.TicketStatus.archived)
            self.assertEqual(new_ticket.status, main.TicketStatus.new)

    def test_executor_bulk_delete_skips_unavailable_ticket_ids(self):
        ids = self.seed_company_with_users()
        self.login_web("executor@example.com")

        response = self.client.post(
            "/web/tickets/bulk-action",
            data={
                "action": "delete",
                "ticket_ids": [str(ids["own_ticket_id"]), str(ids["foreign_ticket_id"])],
                "next": "/web?view_mode=table",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            "/web?view_mode=table&bulk_ok=1&bulk_action=delete&bulk_done=1&bulk_skipped=1",
        )
        with main.SessionLocal() as db:
            self.assertIsNone(db.get(main.Ticket, ids["own_ticket_id"]))
            self.assertIsNotNone(db.get(main.Ticket, ids["foreign_ticket_id"]))


if __name__ == "__main__":
    unittest.main()
