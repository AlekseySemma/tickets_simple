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


class TicketSupportTests(unittest.TestCase):
    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def _seed_company_graph(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Ticket Support Co")
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
            executor = main.User(
                email="executor@example.com",
                name="Executor",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=True,
            )
            outsider = main.User(
                email="outsider@example.com",
                name="Outsider",
                password_hash=main.hash_password("secret123"),
                role=main.Role.executor,
                company_id=company.id,
                email_verified=True,
                is_assignable_executor=False,
            )
            department = main.Department(company_id=company.id, name="Ops", is_active=True)
            unit_type = main.UnitType(company_id=company.id, name="Branch", code="branch", is_active=True)
            db.add_all([creator, executor, outsider, department, unit_type])
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
            db.flush()
            leaf = main.OrgUnit(
                company_id=company.id,
                name="Leaf",
                unit_type_id=unit_type.id,
                parent_id=child.id,
                is_active=True,
            )
            db.add(leaf)
            db.flush()

            ticket_type = main.TicketType(
                company_id=company.id,
                name="Incident",
                is_active=True,
                department_id=department.id,
            )
            db.add(ticket_type)
            db.flush()

            project = main.Project(company_id=company.id, name="Root / Child / Leaf", description=None)
            template = main.TicketTemplate(
                company_id=company.id,
                name="Template",
                title_template="Task {period}",
                scope_unit_id=leaf.id,
                ticket_type_id=ticket_type.id,
                department_id=department.id,
                default_executor_id=executor.id,
            )
            db.add_all([project, template])
            db.flush()

            assignment = main.UnitAssignment(
                company_id=company.id,
                unit_id=leaf.id,
                user_id=executor.id,
                department_id=department.id,
                role_code="EXECUTOR",
                is_primary=True,
            )
            db.add(assignment)
            db.flush()

            ticket = main.Ticket(
                title="Support ticket",
                company_id=company.id,
                created_by=creator.id,
                executor_id=executor.id,
                project_id=project.id,
            )
            db.add(ticket)
            db.commit()

            return {
                "company_id": company.id,
                "creator_id": creator.id,
                "executor_id": executor.id,
                "outsider_id": outsider.id,
                "department_id": department.id,
                "root_id": root.id,
                "child_id": child.id,
                "leaf_id": leaf.id,
                "ticket_type_id": ticket_type.id,
                "project_id": project.id,
                "template_id": template.id,
                "ticket_id": ticket.id,
            }

    def test_watchers_and_scope_helpers(self):
        ids = self._seed_company_graph()
        with main.SessionLocal() as db:
            ticket = db.get(main.Ticket, ids["ticket_id"])

            changed_first = main.ensure_default_ticket_watchers(db, ticket)
            db.flush()
            changed_second = main.ensure_default_ticket_watchers(db, ticket)
            db.commit()

            watcher_ids = {
                row.user_id
                for row in db.query(main.TicketWatcher).filter(main.TicketWatcher.ticket_id == ticket.id).all()
            }
            leaves = sorted(main.resolve_scope_leaf_units(db, ids["company_id"], ids["root_id"]))
            descendants = sorted(main.resolve_scope_descendant_units(db, ids["company_id"], ids["root_id"]))

        self.assertTrue(changed_first)
        self.assertFalse(changed_second)
        self.assertEqual(watcher_ids, {ids["creator_id"], ids["executor_id"]})
        self.assertEqual(leaves, [ids["leaf_id"]])
        self.assertEqual(descendants, [ids["root_id"], ids["child_id"], ids["leaf_id"]])

    def test_form_resolution_and_preferred_executor(self):
        ids = self._seed_company_graph()
        with main.SessionLocal() as db:
            self.assertEqual(
                main.resolve_target_unit_id_from_form_input(db, ids["company_id"], f"Leaf (#{ids['leaf_id']})"),
                ids["leaf_id"],
            )
            self.assertEqual(
                main.resolve_target_unit_id_from_form_input(db, ids["company_id"], "Leaf"),
                ids["leaf_id"],
            )
            self.assertEqual(
                main.resolve_executor_id_from_form_input(db, ids["company_id"], "executor@example.com"),
                ids["executor_id"],
            )
            self.assertEqual(
                main.resolve_executor_id_from_form_input(db, ids["company_id"], f"Executor (#{ids['executor_id']})"),
                ids["executor_id"],
            )
            self.assertEqual(
                main.get_preferred_executor_for_unit(
                    db,
                    ids["company_id"],
                    ids["leaf_id"],
                    department_id=ids["department_id"],
                ),
                ids["executor_id"],
            )

    def test_validation_project_and_deadline_helpers(self):
        ids = self._seed_company_graph()
        with main.SessionLocal() as db:
            main.validate_ticket_links(
                db,
                ids["company_id"],
                ids["project_id"],
                ids["executor_id"],
                ids["ticket_type_id"],
                ids["leaf_id"],
                ids["template_id"],
                ids["department_id"],
            )
            main.validate_template_links(
                db,
                ids["company_id"],
                ids["ticket_type_id"],
                ids["department_id"],
                ids["executor_id"],
                ids["leaf_id"],
            )
            resolved_department_id = main.resolve_ticket_department_id(
                db,
                company_id=ids["company_id"],
                ticket_type_id=ids["ticket_type_id"],
                department_id=ids["department_id"],
            )
            project_id = main.get_or_create_project_for_org_unit(db, ids["company_id"], ids["leaf_id"])

        self.assertEqual(resolved_department_id, ids["department_id"])
        self.assertEqual(project_id, ids["project_id"])
        self.assertEqual(main.normalize_period_key("2026-05"), "2026-05")
        self.assertEqual(main.template_deadline_mode("dom:15"), "dom")
        self.assertEqual(
            main.parse_template_deadline_rule_from_form({"deadline_mode": "dom", "deadline_dom": "7"}),
            "dom:7",
        )


if __name__ == "__main__":
    unittest.main()
