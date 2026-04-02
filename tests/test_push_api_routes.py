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
main.run_archive_cleanup_forever = lambda: None


class PushApiRoutesTests(unittest.TestCase):
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
        main.push_is_configured = lambda: False
        main.VAPID_PUBLIC_KEY = "test-public-key"

    def seed_user(self, email: str) -> dict[str, object]:
        with main.SessionLocal() as db:
            company = main.Company(name="Push Co")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name=email.split("@", 1)[0],
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()
            token = main.create_access_token(str(user.id), main.get_user_auth_token_version(user))
            return {"id": user.id, "token": token}

    def test_push_public_key_returns_current_configuration(self):
        user = self.seed_user("push-public@example.com")
        main.push_is_configured = lambda: True
        main.VAPID_PUBLIC_KEY = "browser-push-key"

        response = self.client.get(
            "/api/push/public-key",
            headers={"Authorization": f"Bearer {user['token']}"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"publicKey": "browser-push-key", "enabled": True, "user_id": user["id"]},
        )

    def test_push_subscribe_and_unsubscribe_roundtrip(self):
        user = self.seed_user("push-subscribe@example.com")
        endpoint = "https://push.example.test/subscriptions/123"

        subscribe = self.client.post(
            "/api/push/subscribe",
            headers={"Authorization": f"Bearer {user['token']}"},
            json={
                "endpoint": endpoint,
                "keys": {
                    "p256dh": "p256dh-key-123456",
                    "auth": "auth-key-654321",
                },
            },
        )

        self.assertEqual(subscribe.status_code, 200)
        with main.SessionLocal() as db:
            items = db.query(main.PushSubscription).all()
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].user_id, user["id"])
            self.assertEqual(items[0].endpoint, endpoint)

        unsubscribe = self.client.post(
            "/api/push/unsubscribe",
            headers={"Authorization": f"Bearer {user['token']}"},
            json={"endpoint": endpoint},
        )

        self.assertEqual(unsubscribe.status_code, 200)
        with main.SessionLocal() as db:
            self.assertEqual(db.query(main.PushSubscription).count(), 0)


if __name__ == "__main__":
    unittest.main()
