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


class TicketRuntimeServiceTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()

    def test_run_template_autogen_once_creates_ticket(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Runtime Templates Co")
            db.add(company)
            db.flush()

            admin = main.User(
                email="runtime-admin@example.com",
                name="Runtime Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            executor = main.User(
                email="runtime-executor@example.com",
                name="Runtime Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=True,
            )
            db.add_all([admin, executor])
            db.flush()

            unit_type = main.UnitType(company_id=company.id, name="Node", code="node", is_active=True)
            ticket_type = main.TicketType(company_id=company.id, name="Runtime TO", is_active=True)
            db.add_all([unit_type, ticket_type])
            db.flush()

            root = main.OrgUnit(company_id=company.id, name="Branch", unit_type_id=unit_type.id, is_active=True)
            leaf = main.OrgUnit(company_id=company.id, name="Store 7", unit_type_id=unit_type.id, is_active=True)
            db.add_all([root, leaf])
            db.flush()
            leaf.parent_id = root.id

            template = main.TicketTemplate(
                company_id=company.id,
                ticket_type_id=ticket_type.id,
                name="Autogen Runtime",
                title_template="Auto {period}",
                description_template="Work for {unit_name}",
                default_deadline_rule="2026-04-30",
                default_executor_id=executor.id,
                scope_unit_id=root.id,
                is_active=True,
            )
            db.add(template)
            db.commit()
            template_id = template.id
            leaf_id = leaf.id

        main.run_template_autogen_once()

        with main.SessionLocal() as db:
            tickets = db.query(main.Ticket).all()
            self.assertEqual(len(tickets), 1)
            self.assertEqual(tickets[0].ticket_template_id, template_id)
            self.assertEqual(tickets[0].target_unit_id, leaf_id)
            self.assertEqual(
                db.query(main.TicketGenerationKey).filter(main.TicketGenerationKey.ticket_id == tickets[0].id).count(),
                1,
            )

    def test_run_archive_cleanup_once_deletes_due_archived_ticket(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Archive Runtime Co")
            db.add(company)
            db.flush()

            admin = main.User(
                email="archive-admin@example.com",
                name="Archive Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            project = main.Project(name="Archive Project", company_id=company.id)
            db.add_all([admin, project])
            db.flush()

            ticket = main.Ticket(
                title="Delete me",
                description="Archived runtime ticket",
                status=main.TicketStatus.archived,
                company_id=company.id,
                project_id=project.id,
                created_by=admin.id,
                archived_by=admin.id,
                archived_at=main.local_now(),
                retention_days=1,
                delete_at=main.local_now(),
                is_legal_hold=False,
            )
            db.add(ticket)
            db.commit()

        main.run_archive_cleanup_once()

        with main.SessionLocal() as db:
            self.assertEqual(db.query(main.Ticket).count(), 0)
            self.assertEqual(db.query(main.ArchiveCleanupLog).count(), 1)


if __name__ == "__main__":
    unittest.main()
