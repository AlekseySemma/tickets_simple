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


class TicketsApiRoutesTests(unittest.TestCase):
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

    def seed_admin_with_project(self, email: str = "tickets-api@example.com") -> dict[str, int | str]:
        with main.SessionLocal() as db:
            company = main.Company(name="Tickets API Co")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="Tickets Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()
            project = main.Project(name="Main Project", company_id=company.id)
            db.add(project)
            db.commit()
            db.refresh(user)
            db.refresh(project)
            token = main.create_access_token(str(user.id), main.get_user_auth_token_version(user))
            return {
                "company_id": company.id,
                "user_id": user.id,
                "project_id": project.id,
                "token": token,
            }

    def auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def test_tickets_create_and_list_roundtrip(self):
        admin = self.seed_admin_with_project()

        created = self.client.post(
            "/tickets",
            headers=self.auth_headers(admin["token"]),
            json={
                "title": "API ticket",
                "description": "Created by API",
                "project_id": admin["project_id"],
            },
        )

        self.assertEqual(created.status_code, 200)
        self.assertEqual(created.json()["title"], "API ticket")
        ticket_id = created.json()["id"]

        listed = self.client.get(
            "/tickets",
            headers=self.auth_headers(admin["token"]),
        )

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()), 1)
        self.assertEqual(listed.json()[0]["id"], ticket_id)

    def test_tickets_update_changes_title_description_and_status(self):
        admin = self.seed_admin_with_project()

        created = self.client.post(
            "/tickets",
            headers=self.auth_headers(admin["token"]),
            json={
                "title": "Old title",
                "description": "Old desc",
                "project_id": admin["project_id"],
            },
        )
        self.assertEqual(created.status_code, 200)
        ticket_id = created.json()["id"]

        updated = self.client.patch(
            f"/tickets/{ticket_id}",
            headers=self.auth_headers(admin["token"]),
            json={
                "title": "New title",
                "description": "New desc",
                "status": main.TicketStatus.in_progress.value,
            },
        )

        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["title"], "New title")
        self.assertEqual(updated.json()["description"], "New desc")
        self.assertEqual(updated.json()["status"], main.TicketStatus.in_progress.value)


if __name__ == "__main__":
    unittest.main()
