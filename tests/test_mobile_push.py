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
main.mobile_push_is_configured = lambda: False
main.run_archive_cleanup_forever = lambda: None


class MobilePushTests(unittest.TestCase):
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

    def seed_user(self, email: str, company_name: str = "Acme") -> dict[str, object]:
        with main.SessionLocal() as db:
            company = db.query(main.Company).filter(main.Company.name == company_name).first()
            if not company:
                company = main.Company(name=company_name)
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
            return {"id": user.id, "token": token, "email": email}

    def login_web(self, email: str, password: str = "secret123") -> None:
        response = self.client.post(
            "/web/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_mobile_device_register_reassigns_same_device_to_new_user(self):
        user1 = self.seed_user("first@example.com")
        user2 = self.seed_user("second@example.com")

        response1 = self.client.post(
            "/api/mobile/devices/register",
            headers={"Authorization": f"Bearer {user1['token']}"},
            json={"token": "token-1111111111111111", "device_id": "device-aaaa-1111", "platform": "android"},
        )
        self.assertEqual(response1.status_code, 200)

        response2 = self.client.post(
            "/api/mobile/devices/register",
            headers={"Authorization": f"Bearer {user2['token']}"},
            json={"token": "token-2222222222222222", "device_id": "device-aaaa-1111", "platform": "android"},
        )
        self.assertEqual(response2.status_code, 200)

        with main.SessionLocal() as db:
            devices = db.query(main.MobileDevice).all()
            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].user_id, user2["id"])
            self.assertEqual(devices[0].token, "token-2222222222222222")

    def test_mobile_device_unregister_by_device_id(self):
        user = self.seed_user("mobile@example.com")
        with main.SessionLocal() as db:
            db.add(
                main.MobileDevice(
                    user_id=int(user["id"]),
                    platform="android",
                    device_id="device-remove-1",
                    token="token-remove-1234567890",
                )
            )
            db.commit()

        response = self.client.post(
            "/api/mobile/devices/unregister",
            headers={"Authorization": f"Bearer {user['token']}"},
            json={"device_id": "device-remove-1", "platform": "android"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["deleted"], 1)

        with main.SessionLocal() as db:
            self.assertEqual(db.query(main.MobileDevice).count(), 0)

    def test_android_user_agent_hides_browser_push_controls(self):
        user = self.seed_user("settings-mobile@example.com")
        self.login_web(str(user["email"]))

        response = self.client.get(
            "/web/settings?section=notifications",
            headers={"User-Agent": "Mozilla/5.0 ServoraAndroidApp/1.0"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Firebase", response.text)
        self.assertNotIn('id="enable-push-btn"', response.text)


if __name__ == "__main__":
    unittest.main()
