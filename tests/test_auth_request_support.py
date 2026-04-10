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


class AuthRequestSupportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def test_get_active_invite_uses_registration_invite_model(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Invite Co")
            db.add(company)
            db.flush()
            creator = main.User(
                email="creator@example.com",
                name="Creator",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(creator)
            db.flush()
            invite = main.RegistrationInvite(
                company_id=company.id,
                created_by=creator.id,
                role=main.Role.executor,
                token="invite-token-1",
            )
            db.add(invite)
            db.commit()

            loaded = main.get_active_invite(db, "invite-token-1")

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.token, "invite-token-1")


if __name__ == "__main__":
    unittest.main()
