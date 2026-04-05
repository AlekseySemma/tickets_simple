import os
import unittest

from fastapi import Request
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


class EmailAuthSupportTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def _request(self, path: str) -> Request:
        return Request(
            {
                "type": "http",
                "scheme": "http",
                "server": ("testserver", 80),
                "client": ("127.0.0.1", 12345),
                "method": "GET",
                "path": path,
                "raw_path": path.encode("utf-8"),
                "query_string": b"",
                "headers": [],
            }
        )

    def test_send_user_verification_email_sets_timestamp_and_returns_url(self):
        request = self._request("/web/register")
        with main.SessionLocal() as db:
            company = main.Company(name="Email Auth Co")
            db.add(company)
            db.flush()
            user = main.User(
                email="verify-support@example.com",
                name="Verify User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=False,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

            verification_url = main.send_user_verification_email(request, db, user)

            self.assertIn("/web/verify-email?token=", verification_url)
            self.assertIsNotNone(user.email_verification_sent_at)

    def test_send_user_password_reset_email_sets_timestamp_and_returns_url(self):
        request = self._request("/web/password-reset")
        with main.SessionLocal() as db:
            company = main.Company(name="Reset Auth Co")
            db.add(company)
            db.flush()
            user = main.User(
                email="reset-support@example.com",
                name="Reset User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

            reset_url = main.send_user_password_reset_email(request, db, user)

            self.assertIn("/web/password-reset/confirm?token=", reset_url)
            self.assertIsNotNone(user.password_reset_sent_at)


if __name__ == "__main__":
    unittest.main()
