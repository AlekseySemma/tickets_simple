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


class EmailVerificationTests(unittest.TestCase):
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

    def seed_invite(self) -> str:
        with main.SessionLocal() as db:
            company = main.Company(name="Acme")
            db.add(company)
            db.flush()
            admin = main.User(
                email="admin@acme.local",
                name="Admin",
                password_hash=main.hash_password("pass"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(admin)
            db.flush()
            invite = main.RegistrationInvite(
                token="invite-token",
                role=main.Role.executor,
                company_id=company.id,
                created_by=admin.id,
            )
            db.add(invite)
            db.commit()
            return invite.token

    def seed_verified_user(self, email: str = "user@example.com", password: str = "secret123") -> int:
        with main.SessionLocal() as db:
            company = main.Company(name=f"Company-{email}")
            db.add(company)
            db.flush()
            user = main.User(
                email=email,
                name="User",
                password_hash=main.hash_password(password),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()
            return user.id

    def test_invite_registration_blocks_login_until_email_verified(self):
        invite_token = self.seed_invite()

        response = self.client.post(
            "/web/register",
            data={
                "token": invite_token,
                "name": "Ivan",
                "email": "ivan@example.com",
                "password": "secret123",
            },
        )
        self.assertEqual(response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "ivan@example.com").first()
            self.assertIsNotNone(user)
            self.assertFalse(user.email_verified)
            self.assertIsNotNone(user.email_verification_token)

        web_login = self.client.post(
            "/web/login",
            data={"email": "ivan@example.com", "password": "secret123"},
        )
        self.assertEqual(web_login.status_code, 403)

        api_login = self.client.post(
            "/auth/login",
            data={"username": "ivan@example.com", "password": "secret123"},
        )
        self.assertEqual(api_login.status_code, 403)

    def test_email_verification_allows_login(self):
        invite_token = self.seed_invite()
        self.client.post(
            "/web/register",
            data={
                "token": invite_token,
                "name": "Olga",
                "email": "olga@example.com",
                "password": "secret123",
            },
        )

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "olga@example.com").first()
            self.assertIsNotNone(user)
            verify_token = user.email_verification_token

        verify_response = self.client.get(f"/web/verify-email?token={verify_token}")
        self.assertEqual(verify_response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "olga@example.com").first()
            self.assertTrue(user.email_verified)
            self.assertIsNone(user.email_verification_token)

        api_login = self.client.post(
            "/auth/login",
            data={"username": "olga@example.com", "password": "secret123"},
        )
        self.assertEqual(api_login.status_code, 200)
        self.assertIn("access_token", api_login.json())

    def test_resend_verification_rotates_token(self):
        invite_token = self.seed_invite()
        self.client.post(
            "/web/register",
            data={
                "token": invite_token,
                "name": "Petr",
                "email": "petr@example.com",
                "password": "secret123",
            },
        )

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "petr@example.com").first()
            self.assertIsNotNone(user)
            old_token = user.email_verification_token

        resend_response = self.client.post(
            "/web/verify-email/resend",
            data={"email": "petr@example.com"},
        )
        self.assertEqual(resend_response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "petr@example.com").first()
            self.assertFalse(user.email_verified)
            self.assertNotEqual(old_token, user.email_verification_token)
            self.assertIsNotNone(user.email_verification_sent_at)

    def test_company_registration_creates_unverified_owner(self):
        response = self.client.post(
            "/web/register-company",
            data={
                "company_name": "New Co",
                "admin_name": "Founder",
                "admin_email": "founder@example.com",
                "admin_password": "secret123",
            },
        )
        self.assertEqual(response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "founder@example.com").first()
            self.assertIsNotNone(user)
            self.assertFalse(user.email_verified)
            self.assertEqual(user.role, main.Role.admin)
            self.assertIsNotNone(user.email_verification_token)

    def test_password_reset_request_creates_token(self):
        self.seed_verified_user(email="reset1@example.com")

        response = self.client.post(
            "/web/password-reset",
            data={"email": "reset1@example.com"},
        )
        self.assertEqual(response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "reset1@example.com").first()
            self.assertIsNotNone(user)
            self.assertIsNotNone(user.password_reset_token)
            self.assertIsNotNone(user.password_reset_expires_at)
            self.assertIsNotNone(user.password_reset_sent_at)

    def test_password_reset_changes_password_and_allows_login(self):
        self.seed_verified_user(email="reset2@example.com", password="oldpassword")

        old_login = self.client.post(
            "/auth/login",
            data={"username": "reset2@example.com", "password": "oldpassword"},
        )
        self.assertEqual(old_login.status_code, 200)
        old_token = old_login.json()["access_token"]

        self.client.post(
            "/web/password-reset",
            data={"email": "reset2@example.com"},
        )

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "reset2@example.com").first()
            self.assertIsNotNone(user)
            token = user.password_reset_token
            self.assertTrue(main.verify_password("oldpassword", user.password_hash))

        confirm_response = self.client.post(
            "/web/password-reset/confirm",
            data={
                "token": token,
                "password": "newpassword",
                "password_confirm": "newpassword",
            },
        )
        self.assertEqual(confirm_response.status_code, 200)

        with main.SessionLocal() as db:
            user = db.query(main.User).filter(main.User.email == "reset2@example.com").first()
            self.assertIsNotNone(user)
            self.assertTrue(main.verify_password("newpassword", user.password_hash))
            self.assertFalse(main.verify_password("oldpassword", user.password_hash))
            self.assertIsNone(user.password_reset_token)
            self.assertIsNone(user.password_reset_expires_at)
            self.assertIsNone(user.password_reset_sent_at)
            self.assertEqual(user.auth_token_version, 1)

        old_token_me = self.client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        self.assertEqual(old_token_me.status_code, 401)

        api_login = self.client.post(
            "/auth/login",
            data={"username": "reset2@example.com", "password": "newpassword"},
        )
        self.assertEqual(api_login.status_code, 200)

    def test_logout_all_devices_revokes_old_tokens_and_current_cookie(self):
        self.seed_verified_user(email="logoutall@example.com", password="secret123")

        api_login = self.client.post(
            "/auth/login",
            data={"username": "logoutall@example.com", "password": "secret123"},
        )
        self.assertEqual(api_login.status_code, 200)
        old_token = api_login.json()["access_token"]

        web_login = self.client.post(
            "/web/login",
            data={"email": "logoutall@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(web_login.status_code, 303)

        logout_all = self.client.post(
            "/web/settings/logout-all",
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )
        self.assertEqual(logout_all.status_code, 303)
        self.assertIn("/web/login?info=logged_out_all", logout_all.headers["location"])

        old_token_me = self.client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        self.assertEqual(old_token_me.status_code, 401)

        settings_after = self.client.get("/web/settings", follow_redirects=False)
        self.assertEqual(settings_after.status_code, 303)
        self.assertEqual(settings_after.headers["location"], "/web/login")

    def test_settings_change_password_revokes_sessions_and_updates_password(self):
        self.seed_verified_user(email="changepw@example.com", password="oldpassword")

        api_login = self.client.post(
            "/auth/login",
            data={"username": "changepw@example.com", "password": "oldpassword"},
        )
        self.assertEqual(api_login.status_code, 200)
        old_token = api_login.json()["access_token"]

        web_login = self.client.post(
            "/web/login",
            data={"email": "changepw@example.com", "password": "oldpassword"},
            follow_redirects=False,
        )
        self.assertEqual(web_login.status_code, 303)

        change_password = self.client.post(
            "/web/settings/change-password",
            data={
                "current_password": "oldpassword",
                "new_password": "newpassword",
                "new_password_confirm": "newpassword",
            },
            headers={"origin": "http://testserver"},
            follow_redirects=False,
        )
        self.assertEqual(change_password.status_code, 303)
        self.assertIn("/web/login?info=password_changed", change_password.headers["location"])

        old_token_me = self.client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        self.assertEqual(old_token_me.status_code, 401)

        old_password_login = self.client.post(
            "/auth/login",
            data={"username": "changepw@example.com", "password": "oldpassword"},
        )
        self.assertEqual(old_password_login.status_code, 401)

        new_password_login = self.client.post(
            "/auth/login",
            data={"username": "changepw@example.com", "password": "newpassword"},
        )
        self.assertEqual(new_password_login.status_code, 200)

        settings_after = self.client.get("/web/settings", follow_redirects=False)
        self.assertEqual(settings_after.status_code, 303)
        self.assertEqual(settings_after.headers["location"], "/web/login")


if __name__ == "__main__":
    unittest.main()
