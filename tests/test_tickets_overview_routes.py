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


class TicketsOverviewRoutesTests(unittest.TestCase):
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
            company = main.Company(name="Overview Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="overview@example.com",
                name="Overview Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(name="Overview Project", company_id=company.id)
            db.add_all([admin, project])
            db.flush()
            active_ticket = main.Ticket(
                title="Active ticket",
                description="visible on /web",
                status=main.TicketStatus.new,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
            )
            archived_ticket = main.Ticket(
                title="Archived ticket",
                description="visible on /web/archive",
                status=main.TicketStatus.archived,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
                archived_by=admin.id,
                archived_at=main.local_now(),
                retention_days=30,
                delete_at=main.local_now(),
            )
            db.add_all([active_ticket, archived_ticket])
            db.commit()
            return {"active_ticket_id": active_ticket.id, "archived_ticket_id": archived_ticket.id}

    def login_web(self) -> None:
        response = self.client.post(
            "/web/login",
            data={"email": "overview@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_web_ticket_list_renders(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.get("/web")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Active ticket", response.text)
        self.assertIn(f'/web/tickets/{ids["active_ticket_id"]}', response.text)

    def test_web_archive_ticket_list_renders(self):
        ids = self.seed_context()
        self.login_web()

        response = self.client.get("/web/archive")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Archived ticket", response.text)
        self.assertIn(f'/web/tickets/{ids["archived_ticket_id"]}', response.text)


if __name__ == "__main__":
    unittest.main()
