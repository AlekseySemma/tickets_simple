import os
import unittest

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


class TicketTextSupportTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def test_name_and_notification_helpers(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Text Support Co")
            db.add(company)
            db.flush()
            user = main.User(
                email="text-support@example.com",
                name="Text User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(company_id=company.id, name="Alpha", description=None)
            department = main.Department(company_id=company.id, name="Ops", is_active=True)
            ticket_type = main.TicketType(company_id=company.id, name="Incident", is_active=True)
            db.add_all([user, project, department, ticket_type])
            db.commit()

            self.assertEqual(main._ticket_user_name(db, user.id), "Text User")
            self.assertEqual(main._ticket_project_name(db, project.id), "Alpha")
            self.assertEqual(main._ticket_type_name(db, ticket_type.id), "Incident")
            self.assertEqual(main._department_name(db, department.id), "Ops")

        self.assertEqual(
            main.ticket_field_change_log_action("исполнителя", "Иван", "Петр"),
            "Изменение исполнителя: Иван -> Петр",
        )
        self.assertEqual(
            main.ticket_notification_title("Новая заявка", "Очень длинный заголовок заявки для preview", ticket_id=7),
            "Новая заявка: Очень длинный заголовок зая...",
        )

    def test_normalize_and_add_ticket_log(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Log Co")
            db.add(company)
            db.flush()
            user = main.User(
                email="log-support@example.com",
                name="Logger",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(company_id=company.id, name="Alpha", description=None)
            ticket = main.Ticket(
                title="Logged ticket",
                company_id=company.id,
                created_by=1,
                project_id=1,
            )
            db.add_all([user, project, ticket])
            db.flush()

            main.add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action="???? ?????")
            db.commit()

            row = db.query(main.TicketLog).filter(main.TicketLog.ticket_id == ticket.id).one()

        self.assertEqual(row.action, main.LOG_ACTION_CHANGED)
        self.assertEqual(main.normalize_log_action(main.LOG_ACTION_CREATED), main.LOG_ACTION_CREATED)
        self.assertEqual(main.ticket_title_notification_preview("", ticket_id=42), "заявка #42")


if __name__ == "__main__":
    unittest.main()
