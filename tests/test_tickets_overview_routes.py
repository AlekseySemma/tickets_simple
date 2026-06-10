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
            executor = main.User(
                email="overview-executor@example.com",
                name="Overview Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=True,
            )
            project = main.Project(name="Overview Project", company_id=company.id)
            department = main.Department(company_id=company.id, name="Overview Department", is_active=True)
            db.add_all([admin, executor, project, department])
            db.flush()
            active_ticket = main.Ticket(
                title="Active ticket",
                description="visible on /web",
                status=main.TicketStatus.new,
                company_id=company.id,
                project_id=project.id,
                executor_id=executor.id,
                department_id=department.id,
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
            return {
                "admin_id": admin.id,
                "active_ticket_id": active_ticket.id,
                "archived_ticket_id": archived_ticket.id,
            }

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

    def test_web_ticket_list_can_filter_by_type_then_sort_by_deadline(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Sort Overview Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="sort-overview@example.com",
                name="Sort Overview Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(name="Sort Overview Project", company_id=company.id)
            repair_type = main.TicketType(company_id=company.id, name="Repair", is_active=True)
            monthly_type = main.TicketType(company_id=company.id, name="Monthly", is_active=True)
            db.add_all([admin, project, repair_type, monthly_type])
            db.flush()
            repair_type_id = repair_type.id

            base_deadline = main.local_now().replace(microsecond=0, second=0)
            db.add_all(
                [
                    main.Ticket(
                        title="Repair later ticket",
                        description="",
                        status=main.TicketStatus.new,
                        company_id=company.id,
                        project_id=project.id,
                        ticket_type_id=repair_type.id,
                        deadline=base_deadline + timedelta(days=3),
                        created_by=admin.id,
                    ),
                    main.Ticket(
                        title="Repair nearest ticket",
                        description="",
                        status=main.TicketStatus.new,
                        company_id=company.id,
                        project_id=project.id,
                        ticket_type_id=repair_type.id,
                        deadline=base_deadline + timedelta(days=1),
                        created_by=admin.id,
                    ),
                    main.Ticket(
                        title="Monthly nearest ticket",
                        description="",
                        status=main.TicketStatus.new,
                        company_id=company.id,
                        project_id=project.id,
                        ticket_type_id=monthly_type.id,
                        deadline=base_deadline + timedelta(days=1),
                        created_by=admin.id,
                    ),
                    main.Ticket(
                        title="Monthly later ticket",
                        description="",
                        status=main.TicketStatus.new,
                        company_id=company.id,
                        project_id=project.id,
                        ticket_type_id=monthly_type.id,
                        deadline=base_deadline + timedelta(days=2),
                        created_by=admin.id,
                    ),
                ]
            )
            db.commit()

        response = self.client.post(
            "/web/login",
            data={"email": "sort-overview@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

        response = self.client.get(f"/web?ticket_type_id={repair_type_id}&sort=deadline_asc&view_mode=table")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Monthly nearest ticket", response.text)
        self.assertNotIn("Monthly later ticket", response.text)
        repair_nearest_pos = response.text.find("Repair nearest ticket")
        repair_later_pos = response.text.find("Repair later ticket")
        self.assertGreaterEqual(repair_nearest_pos, 0)
        self.assertGreaterEqual(repair_later_pos, 0)
        self.assertLess(repair_nearest_pos, repair_later_pos)

    def test_web_ticket_list_can_sort_by_title(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Title Sort Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="title-sort@example.com",
                name="Title Sort Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(name="Title Sort Project", company_id=company.id)
            db.add_all([admin, project])
            db.flush()
            db.add_all(
                [
                    main.Ticket(
                        title="Zulu task",
                        description="",
                        status=main.TicketStatus.new,
                        company_id=company.id,
                        project_id=project.id,
                        created_by=admin.id,
                    ),
                    main.Ticket(
                        title="Alpha task",
                        description="",
                        status=main.TicketStatus.new,
                        company_id=company.id,
                        project_id=project.id,
                        created_by=admin.id,
                    ),
                    main.Ticket(
                        title="Bravo task",
                        description="",
                        status=main.TicketStatus.new,
                        company_id=company.id,
                        project_id=project.id,
                        created_by=admin.id,
                    ),
                ]
            )
            db.commit()

        response = self.client.post(
            "/web/login",
            data={"email": "title-sort@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

        response = self.client.get("/web?sort=title_asc&view_mode=table")

        self.assertEqual(response.status_code, 200)
        alpha_pos = response.text.find("Alpha task")
        bravo_pos = response.text.find("Bravo task")
        zulu_pos = response.text.find("Zulu task")
        self.assertGreaterEqual(alpha_pos, 0)
        self.assertGreaterEqual(bravo_pos, 0)
        self.assertGreaterEqual(zulu_pos, 0)
        self.assertLess(alpha_pos, bravo_pos)
        self.assertLess(bravo_pos, zulu_pos)

    def test_ticket_card_fields_can_be_hidden_in_card_list_only(self):
        ids = self.seed_context()
        with main.SessionLocal() as db:
            user = db.get(main.User, ids["admin_id"])
            user.ticket_card_show_department = False
            user.ticket_card_show_executor = False
            user.ticket_card_show_creator = False
            db.commit()
        self.login_web()

        response = self.client.get("/web?view_mode=cards")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Active ticket", response.text)
        self.assertNotIn('data-ticket-card-field="department"', response.text)
        self.assertNotIn('data-ticket-card-field="executor"', response.text)
        self.assertNotIn('data-ticket-card-field="creator"', response.text)

        detail_response = self.client.get(f'/web/tickets/{ids["active_ticket_id"]}')
        self.assertEqual(detail_response.status_code, 200)
        self.assertIn("Overview Department", detail_response.text)
        self.assertIn("Overview Executor", detail_response.text)


if __name__ == "__main__":
    unittest.main()
