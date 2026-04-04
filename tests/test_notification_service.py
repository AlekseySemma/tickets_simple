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
main.TEXT_REPAIR_ON_START = False
main.TEMPLATE_AUTOGEN_ENABLED = False
main.push_is_configured = lambda: False
main.mobile_push_is_configured = lambda: False
main.run_archive_cleanup_forever = lambda: None


class NotificationServiceTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()

    def test_notify_comment_added_creates_notifications_for_executor_and_curator(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Notify Co")
            db.add(company)
            db.flush()

            author = main.User(
                email="author@example.com",
                name="Author",
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
            curator = main.User(
                email="curator@example.com",
                name="Curator",
                password_hash=main.hash_password("secret123"),
                role=main.Role.curator,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(name="HQ", company_id=company.id)
            db.add_all([author, executor, curator, project])
            db.flush()

            ticket = main.Ticket(
                title="Need comment alert",
                description="Check notification fanout",
                status=main.TicketStatus.in_progress,
                company_id=company.id,
                project_id=project.id,
                executor_id=executor.id,
                created_by=author.id,
            )
            db.add(ticket)
            db.flush()

            db.add(
                main.TicketWatcher(
                    ticket_id=ticket.id,
                    user_id=curator.id,
                    added_by=author.id,
                )
            )
            db.commit()

            main.notify_comment_added(
                db=db,
                ticket=ticket,
                author=author,
                comment_text="Status update from field",
            )
            db.commit()

            notifications = (
                db.query(main.Notification)
                .filter(main.Notification.company_id == company.id)
                .order_by(main.Notification.user_id.asc())
                .all()
            )
            recipient_ids = [item.user_id for item in notifications]
            self.assertEqual(recipient_ids, [executor.id, curator.id])
            self.assertTrue(all("/web/tickets/" in (item.url or "") for item in notifications))


if __name__ == "__main__":
    unittest.main()
