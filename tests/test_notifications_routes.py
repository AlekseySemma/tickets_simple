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


class NotificationRoutesTests(unittest.TestCase):
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

    def seed_user_with_notification(self) -> dict[str, int]:
        with main.SessionLocal() as db:
            company = main.Company(name="Notify Co")
            db.add(company)
            db.flush()
            user = main.User(
                email="notify@example.com",
                name="Notify User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()
            notification = main.Notification(
                company_id=company.id,
                user_id=user.id,
                title="Изменен статус заявки",
                body="Тестовое уведомление",
                url="/web/tickets/123",
                is_read=False,
            )
            db.add(notification)
            db.commit()
            return {"user_id": user.id, "notification_id": notification.id}

    def login_web(self, email: str = "notify@example.com", password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_notifications_page_and_unread_counter_render(self):
        self.seed_user_with_notification()
        self.login_web()

        page = self.client.get("/web/notifications")
        counter = self.client.get("/web/notifications/unread-count")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Тестовое уведомление", page.text)
        self.assertEqual(counter.status_code, 200)
        self.assertEqual(counter.json()["unread"], 1)

    def test_open_notification_marks_it_read_and_redirects(self):
        ids = self.seed_user_with_notification()
        self.login_web()

        response = self.client.get(
            f"/web/notifications/{ids['notification_id']}/open",
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/tickets/123")
        with main.SessionLocal() as db:
            item = db.get(main.Notification, ids["notification_id"])
            self.assertTrue(item.is_read)


if __name__ == "__main__":
    unittest.main()
