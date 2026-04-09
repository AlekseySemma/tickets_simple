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
main.run_archive_cleanup_forever = lambda: None


class SecuritySupportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()

    def test_normalizers_and_rate_limit(self):
        self.assertEqual(main.normalize_email("  USER@Example.COM "), "user@example.com")
        self.assertEqual(main.normalize_department_name("  Support   Team "), "Support Team")

        limited, retry_after = main.hit_rate_limit("bucket-1", 1, 60)
        self.assertEqual((limited, retry_after), (False, 0))

        limited, retry_after = main.hit_rate_limit("bucket-1", 1, 60)
        self.assertTrue(limited)
        self.assertGreaterEqual(retry_after, 1)

    def test_audit_security_event_persists_row(self):
        main.audit_security_event(
            "auth_login",
            None,
            success=False,
            email=" TEST@example.com ",
            detail="invalid_credentials",
        )

        with main.SessionLocal() as db:
            row = db.query(main.SecurityEvent).one()
            self.assertEqual(row.event_type, "auth_login")
            self.assertIsNone(row.endpoint)
            self.assertEqual(row.email, "test@example.com")
            self.assertFalse(row.success)
            self.assertEqual(row.detail, "invalid_credentials")


if __name__ == "__main__":
    unittest.main()
