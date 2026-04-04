import os
import unittest
from datetime import timedelta

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


class DeadlineReminderServiceTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()
        self.sent_pushes = []
        self.original_send_push = main.send_push_to_user
        main.send_push_to_user = lambda **kwargs: self.sent_pushes.append(kwargs)

    def tearDown(self):
        main.send_push_to_user = self.original_send_push

    def test_run_deadline_reminders_once_creates_log_and_sends_single_push(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Reminders Co")
            db.add(company)
            db.flush()

            executor = main.User(
                email="reminder-executor@example.com",
                name="Reminder Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=True,
            )
            project = main.Project(name="Reminder Project", company_id=company.id)
            db.add_all([executor, project])
            db.flush()

            ticket = main.Ticket(
                title="Reminder ticket",
                description="Soon due",
                status=main.TicketStatus.in_progress,
                company_id=company.id,
                project_id=project.id,
                executor_id=executor.id,
                created_by=executor.id,
                deadline=main.local_now() + timedelta(minutes=main.PUSH_REMINDER_MINUTES, seconds=10),
            )
            db.add(ticket)
            db.commit()
            ticket_id = ticket.id
            executor_id = executor.id

        main.run_deadline_reminders_once()
        main.run_deadline_reminders_once()

        self.assertEqual(len(self.sent_pushes), 1)
        self.assertEqual(self.sent_pushes[0]["user_id"], executor_id)
        self.assertIn("Срок заявки скоро истечет", self.sent_pushes[0]["title"])

        with main.SessionLocal() as db:
            logs = db.query(main.DeadlineReminderLog).all()
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].ticket_id, ticket_id)
            self.assertEqual(
                logs[0].reminder_key,
                main.build_deadline_reminder_key(
                    ticket_id,
                    executor_id,
                    int((db.get(main.Ticket, ticket_id).deadline).timestamp()),
                    main.PUSH_REMINDER_MINUTES,
                ),
            )


if __name__ == "__main__":
    unittest.main()
