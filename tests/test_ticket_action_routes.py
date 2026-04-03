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


class TicketActionRoutesTests(unittest.TestCase):
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
            company = main.Company(name="Action Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="actions@example.com",
                name="Action Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(name="Action Project", company_id=company.id)
            db.add_all([admin, project])
            db.flush()
            new_ticket = main.Ticket(
                title="New ticket",
                description="for status",
                status=main.TicketStatus.new,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
            )
            done_ticket = main.Ticket(
                title="Done ticket",
                description="for archive",
                status=main.TicketStatus.done,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
            )
            archived_ticket = main.Ticket(
                title="Archived ticket",
                description="for restore",
                status=main.TicketStatus.archived,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
                archived_by=admin.id,
                archived_at=main.local_now(),
                retention_days=30,
                delete_at=main.local_now() + timedelta(days=30),
            )
            deletable_ticket = main.Ticket(
                title="Delete me",
                description="for delete",
                status=main.TicketStatus.new,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
            )
            db.add_all([new_ticket, done_ticket, archived_ticket, deletable_ticket])
            db.commit()
            return {
                "new_ticket_id": new_ticket.id,
                "done_ticket_id": done_ticket.id,
                "archived_ticket_id": archived_ticket.id,
                "deletable_ticket_id": deletable_ticket.id,
            }

    def login_web(self) -> None:
        response = self.client.post(
            "/web/login",
            data={"email": "actions@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_status_update_returns_json(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            f"/web/tickets/{ids['new_ticket_id']}/status",
            data={"status": "IN_PROGRESS"},
            headers={"accept": "application/json", "origin": "http://testserver"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "IN_PROGRESS")
        with main.SessionLocal() as db:
            ticket = db.get(main.Ticket, ids["new_ticket_id"])
            self.assertEqual(ticket.status, main.TicketStatus.in_progress)

    def test_archive_action_archives_done_ticket(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            f"/web/tickets/{ids['done_ticket_id']}/archive",
            data={"next": "/web"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web")
        with main.SessionLocal() as db:
            ticket = db.get(main.Ticket, ids["done_ticket_id"])
            self.assertEqual(ticket.status, main.TicketStatus.archived)

    def test_restore_action_restores_archived_ticket_to_done(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            f"/web/tickets/{ids['archived_ticket_id']}/restore",
            data={"next": "/web/archive"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/archive")
        with main.SessionLocal() as db:
            ticket = db.get(main.Ticket, ids["archived_ticket_id"])
            self.assertEqual(ticket.status, main.TicketStatus.done)
            self.assertFalse(ticket.is_legal_hold)

    def test_legal_hold_action_updates_archived_ticket(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            f"/web/tickets/{ids['archived_ticket_id']}/legal-hold",
            data={"is_legal_hold": "1", "next": "/web/archive"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/archive")
        with main.SessionLocal() as db:
            ticket = db.get(main.Ticket, ids["archived_ticket_id"])
            self.assertTrue(ticket.is_legal_hold)

    def test_delete_action_removes_ticket(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            f"/web/tickets/{ids['deletable_ticket_id']}/delete",
            data={"next": "/web"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web")
        with main.SessionLocal() as db:
            self.assertIsNone(db.get(main.Ticket, ids["deletable_ticket_id"]))


if __name__ == "__main__":
    unittest.main()
