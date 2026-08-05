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


class TicketDetailRoutesTests(unittest.TestCase):
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
            company = main.Company(name="Detail Co")
            db.add(company)
            db.flush()

            admin = main.User(
                email="detail-admin@example.com",
                name="Detail Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            executor = main.User(
                email="detail-executor@example.com",
                name="Detail Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                can_view_all_tickets=True,
                is_assignable_executor=True,
            )
            project = main.Project(name="Detail Project", company_id=company.id)
            db.add_all([admin, executor, project])
            db.flush()

            ticket = main.Ticket(
                title="Detail ticket",
                description="Original description",
                status=main.TicketStatus.in_progress,
                company_id=company.id,
                project_id=project.id,
                created_by=executor.id,
                executor_id=executor.id,
            )
            db.add(ticket)
            db.commit()
            return {
                "admin_id": admin.id,
                "executor_id": executor.id,
                "project_id": project.id,
                "ticket_id": ticket.id,
            }

    def login_web(self, email: str = "detail-admin@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_ticket_detail_renders(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.get(f"/web/tickets/{ids['ticket_id']}")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Detail ticket", response.text)
        self.assertIn('class="comment-composer"', response.text)

    def test_add_self_watcher_adds_current_user(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            f"/web/tickets/{ids['ticket_id']}/watchers/self",
            data={"next": f"/web/tickets/{ids['ticket_id']}"},
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], f"/web/tickets/{ids['ticket_id']}")
        with main.SessionLocal() as db:
            watcher = (
                db.query(main.TicketWatcher)
                .filter(
                    main.TicketWatcher.ticket_id == ids["ticket_id"],
                    main.TicketWatcher.user_id == ids["admin_id"],
                )
                .first()
            )
            self.assertIsNotNone(watcher)

    def test_ticket_edit_page_renders(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.get(f"/web/tickets/{ids['ticket_id']}/edit")

        self.assertEqual(response.status_code, 200)
        self.assertIn(f'action="/web/tickets/{ids["ticket_id"]}/edit"', response.text)
        self.assertIn('value="Detail ticket"', response.text)

    def test_ticket_edit_save_updates_ticket(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.post(
            f"/web/tickets/{ids['ticket_id']}/edit",
            data={
                "title": "Updated detail ticket",
                "description": "Updated description",
                "status": main.TicketStatus.done.value,
                "project_id": str(ids["project_id"]),
                "executor_id": str(ids["executor_id"]),
                "ticket_type_id": "",
                "department_id": "",
                "deadline_date": "",
                "deadline_time4": "",
                "next": f"/web/tickets/{ids['ticket_id']}",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], f"/web/tickets/{ids['ticket_id']}")
        with main.SessionLocal() as db:
            ticket = db.get(main.Ticket, ids["ticket_id"])
            self.assertEqual(ticket.title, "Updated detail ticket")
            self.assertEqual(ticket.description, "Updated description")
            self.assertEqual(ticket.status, main.TicketStatus.done)

    def test_executor_with_view_all_sees_delete_action_for_foreign_ticket(self):
        ids = self.seed_context()
        with main.SessionLocal() as db:
            ticket = db.get(main.Ticket, ids["ticket_id"])
            ticket.created_by = ids["admin_id"]
            db.commit()

        self.login_web("detail-executor@example.com")
        response = self.client.get(f"/web/tickets/{ids['ticket_id']}")

        self.assertEqual(response.status_code, 200)
        self.assertIn(">Удалить</button>", response.text)


if __name__ == "__main__":
    unittest.main()
