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


class RoleTemplateSupportTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def test_ensure_default_role_templates_creates_allowed_presets_once(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Roles Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="roles-admin@example.com",
                name="Roles Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(admin)
            db.commit()

            allowed = main.manageable_template_access_levels_for_actor(admin)
            main.ensure_default_role_templates(db, company.id, allowed)
            main.ensure_default_role_templates(db, company.id, allowed)

            rows = db.query(main.RoleTemplate).filter(main.RoleTemplate.company_id == company.id).all()

        self.assertTrue(rows)
        self.assertTrue(all(row.access_level in allowed for row in rows))
        self.assertEqual(len(rows), len({row.name.casefold() for row in rows}))

    def test_get_manageable_role_template_respects_actor_access(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Manageable Co")
            db.add(company)
            db.flush()
            admin = main.User(
                email="manage-admin@example.com",
                name="Manage Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            curator = main.User(
                email="manage-curator@example.com",
                name="Manage Curator",
                password_hash=main.hash_password("secret123"),
                role=main.Role.curator,
                company_id=company.id,
                email_verified=True,
            )
            db.add_all([admin, curator])
            db.flush()

            executor_template = main.RoleTemplate(
                company_id=company.id,
                name="Executor template",
                access_level=main.Role.executor,
                **main.normalize_capability_flags(main.Role.executor),
            )
            curator_template = main.RoleTemplate(
                company_id=company.id,
                name="Curator template",
                access_level=main.Role.curator,
                **main.normalize_capability_flags(main.Role.curator),
            )
            db.add_all([executor_template, curator_template])
            db.commit()

            allowed_for_curator = main.manageable_template_access_levels_for_actor(curator)
            visible_for_admin = main.get_manageable_role_template(db, admin, executor_template.id)
            visible_for_curator = main.get_manageable_role_template(
                db,
                curator,
                executor_template.id,
                allowed_access_levels=allowed_for_curator,
            )
            hidden_for_curator = main.get_manageable_role_template(
                db,
                curator,
                curator_template.id,
                allowed_access_levels=allowed_for_curator,
            )

        self.assertIsNotNone(visible_for_admin)
        self.assertIsNotNone(visible_for_curator)
        self.assertIsNone(hidden_for_curator)


if __name__ == "__main__":
    unittest.main()
