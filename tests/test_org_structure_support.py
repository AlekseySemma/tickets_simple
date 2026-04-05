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


class OrgStructureSupportTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def test_parse_helpers(self):
        self.assertTrue(main.parse_bool_text("yes", default=False))
        self.assertFalse(main.parse_bool_text("0", default=True))
        self.assertIsNone(main.parse_optional_int(" "))
        self.assertEqual(main.parse_optional_int("42"), 42)

    def test_get_or_create_unit_type_reactivates_existing(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Org Support Co")
            db.add(company)
            db.flush()
            original = main.UnitType(
                company_id=company.id,
                name="Branch",
                code="branch",
                is_active=False,
            )
            db.add(original)
            db.commit()

            restored = main.get_or_create_unit_type(db, company.id, "branch")
            db.commit()

            again = db.get(main.UnitType, original.id)

        self.assertEqual(restored.id, original.id)
        self.assertTrue(again.is_active)

    def test_query_assignable_users_and_cycle_detection(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Org Graph Co")
            db.add(company)
            db.flush()

            executor = main.User(
                email="assignable@example.com",
                name="Assignable",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=True,
            )
            spectator = main.User(
                email="spectator@example.com",
                name="Spectator",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=False,
            )
            platform_admin = main.User(
                email="platform@example.com",
                name="Platform",
                password_hash=main.hash_password("secret123"),
                role=main.Role.platform_admin,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=True,
            )
            unit_type = main.UnitType(company_id=company.id, name="Branch", code="branch", is_active=True)
            db.add_all([executor, spectator, platform_admin, unit_type])
            db.flush()

            root = main.OrgUnit(
                company_id=company.id,
                name="Root",
                unit_type_id=unit_type.id,
                parent_id=None,
                is_active=True,
            )
            db.add(root)
            db.flush()
            child = main.OrgUnit(
                company_id=company.id,
                name="Child",
                unit_type_id=unit_type.id,
                parent_id=root.id,
                is_active=True,
            )
            db.add(child)
            db.commit()

            executor_id = executor.id
            root_id = root.id
            child_id = child.id
            assignable_ids = main.get_assignable_company_user_ids(db, company.id)
            parent_map = main.build_unit_parent_map(db, company.id)

        self.assertEqual(assignable_ids, {executor_id})
        self.assertFalse(main.would_create_unit_cycle(parent_map, unit_id=root_id, new_parent_id=None))
        self.assertTrue(main.would_create_unit_cycle(parent_map, unit_id=root_id, new_parent_id=child_id))


if __name__ == "__main__":
    unittest.main()
