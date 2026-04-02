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


class Stage6PlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()

    def seed_companies_users(self):
        with main.SessionLocal() as db:
            c1 = main.Company(name="Comp A")
            c2 = main.Company(name="Comp B")
            db.add_all([c1, c2])
            db.flush()

            admin1 = main.User(
                email="admin1@test.local",
                name="Admin1",
                password_hash=main.hash_password("pass"),
                role=main.Role.admin,
                company_id=c1.id,
            )
            curator1 = main.User(
                email="curator1@test.local",
                name="Curator1",
                password_hash=main.hash_password("pass"),
                role=main.Role.curator,
                company_id=c1.id,
            )
            exec1 = main.User(
                email="exec1@test.local",
                name="Exec1",
                password_hash=main.hash_password("pass"),
                role=main.Role.executor,
                company_id=c1.id,
            )
            exec2 = main.User(
                email="exec2@test.local",
                name="Exec2",
                password_hash=main.hash_password("pass"),
                role=main.Role.executor,
                company_id=c1.id,
            )
            admin2 = main.User(
                email="admin2@test.local",
                name="Admin2",
                password_hash=main.hash_password("pass"),
                role=main.Role.admin,
                company_id=c2.id,
            )
            db.add_all([admin1, curator1, exec1, exec2, admin2])
            db.commit()
            return {
                "company1": c1.id,
                "company2": c2.id,
                "admin1": admin1.id,
                "curator1": curator1.id,
                "exec1": exec1.id,
                "exec2": exec2.id,
                "admin2": admin2.id,
            }

    def test_scope_tree_leaf_and_descendants(self):
        ids = self.seed_companies_users()
        with main.SessionLocal() as db:
            ut = main.UnitType(company_id=ids["company1"], name="Node", code="node", is_active=True)
            db.add(ut)
            db.flush()

            root = main.OrgUnit(company_id=ids["company1"], name="Root", unit_type_id=ut.id, parent_id=None, is_active=True)
            child_a = main.OrgUnit(company_id=ids["company1"], name="A", unit_type_id=ut.id, parent_id=None, is_active=True)
            db.add_all([root, child_a])
            db.flush()
            child_a.parent_id = root.id
            leaf1 = main.OrgUnit(company_id=ids["company1"], name="L1", unit_type_id=ut.id, parent_id=child_a.id, is_active=True)
            leaf2 = main.OrgUnit(company_id=ids["company1"], name="L2", unit_type_id=ut.id, parent_id=child_a.id, is_active=True)
            db.add_all([leaf1, leaf2])
            db.commit()

            leaves = sorted(main.resolve_scope_leaf_units(db, ids["company1"], root.id))
            descendants = sorted(main.resolve_scope_descendant_units(db, ids["company1"], root.id))

            self.assertEqual(leaves, sorted([leaf1.id, leaf2.id]))
            self.assertEqual(descendants, sorted([root.id, child_a.id, leaf1.id, leaf2.id]))

    def test_template_dedupe_by_period_template_target_unit(self):
        ids = self.seed_companies_users()
        with main.SessionLocal() as db:
            tt = main.TicketType(company_id=ids["company1"], name="TO", description=None, is_active=True)
            ut = main.UnitType(company_id=ids["company1"], name="Node", code="node", is_active=True)
            db.add_all([tt, ut])
            db.flush()

            root = main.OrgUnit(company_id=ids["company1"], name="Branch", unit_type_id=ut.id, parent_id=None, is_active=True)
            store1 = main.OrgUnit(company_id=ids["company1"], name="Store 1", unit_type_id=ut.id, parent_id=None, is_active=True)
            store2 = main.OrgUnit(company_id=ids["company1"], name="Store 2", unit_type_id=ut.id, parent_id=None, is_active=True)
            db.add_all([root, store1, store2])
            db.flush()
            store1.parent_id = root.id
            store2.parent_id = root.id

            tmpl = main.TicketTemplate(
                company_id=ids["company1"],
                ticket_type_id=tt.id,
                name="Monthly TO",
                title_template="TO {unit_name} {period}",
                description_template="Plan for {period}",
                default_deadline_rule="2026-02-28",
                default_executor_id=ids["exec1"],
                scope_unit_id=root.id,
                is_active=True,
            )
            db.add(tmpl)
            db.commit()

            created_1, skipped_1, period_1 = main.create_tickets_from_template(
                db=db,
                template=tmpl,
                actor_id=ids["admin1"],
                period_key="2026-02",
            )
            db.commit()
            created_2, skipped_2, period_2 = main.create_tickets_from_template(
                db=db,
                template=tmpl,
                actor_id=ids["admin1"],
                period_key="2026-02",
            )
            db.commit()

            total = (
                db.query(main.Ticket)
                .filter(main.Ticket.company_id == ids["company1"], main.Ticket.ticket_template_id == tmpl.id)
                .count()
            )

            self.assertEqual(period_1, "2026-02")
            self.assertEqual(period_2, "2026-02")
            self.assertEqual(created_1, 2)
            self.assertEqual(skipped_1, 0)
            self.assertEqual(created_2, 0)
            self.assertEqual(skipped_2, 2)
            self.assertEqual(total, 2)

    def test_template_dedupe_survives_ticket_delete(self):
        ids = self.seed_companies_users()
        with main.SessionLocal() as db:
            tt = main.TicketType(company_id=ids["company1"], name="Plan", description=None, is_active=True)
            ut = main.UnitType(company_id=ids["company1"], name="Node", code="node", is_active=True)
            db.add_all([tt, ut])
            db.flush()

            root = main.OrgUnit(company_id=ids["company1"], name="Branch", unit_type_id=ut.id, parent_id=None, is_active=True)
            store = main.OrgUnit(company_id=ids["company1"], name="Store 1", unit_type_id=ut.id, parent_id=None, is_active=True)
            db.add_all([root, store])
            db.flush()
            store.parent_id = root.id

            tmpl = main.TicketTemplate(
                company_id=ids["company1"],
                ticket_type_id=tt.id,
                name="Monthly Plan",
                title_template="Plan {period}",
                description_template=None,
                default_deadline_rule="2026-02-28",
                default_executor_id=ids["exec1"],
                scope_unit_id=root.id,
                is_active=True,
            )
            db.add(tmpl)
            db.commit()

            created_1, skipped_1, _ = main.create_tickets_from_template(
                db=db,
                template=tmpl,
                actor_id=ids["admin1"],
                period_key="2026-02",
            )
            db.commit()
            self.assertEqual(created_1, 1)
            self.assertEqual(skipped_1, 0)

            created_ticket = (
                db.query(main.Ticket)
                .filter(main.Ticket.company_id == ids["company1"], main.Ticket.ticket_template_id == tmpl.id)
                .first()
            )
            self.assertIsNotNone(created_ticket)
            db.delete(created_ticket)
            db.commit()

            created_2, skipped_2, _ = main.create_tickets_from_template(
                db=db,
                template=tmpl,
                actor_id=ids["admin1"],
                period_key="2026-02",
            )
            db.commit()
            self.assertEqual(created_2, 0)
            self.assertEqual(skipped_2, 1)

    def test_template_generation_truncates_long_ticket_title(self):
        ids = self.seed_companies_users()
        with main.SessionLocal() as db:
            tt = main.TicketType(company_id=ids["company1"], name="Plan", description=None, is_active=True)
            ut = main.UnitType(company_id=ids["company1"], name="Node", code="node", is_active=True)
            db.add_all([tt, ut])
            db.flush()

            root = main.OrgUnit(company_id=ids["company1"], name="Branch", unit_type_id=ut.id, parent_id=None, is_active=True)
            store = main.OrgUnit(company_id=ids["company1"], name="Store 1", unit_type_id=ut.id, parent_id=None, is_active=True)
            db.add_all([root, store])
            db.flush()
            store.parent_id = root.id

            long_title_template = "TO " + ("X" * 400) + " {period} {unit_name}"
            tmpl = main.TicketTemplate(
                company_id=ids["company1"],
                ticket_type_id=tt.id,
                name="Long Title Plan",
                title_template=long_title_template,
                description_template="Plan for {period}",
                default_deadline_rule="2026-02-28",
                default_executor_id=ids["exec1"],
                scope_unit_id=root.id,
                is_active=True,
            )
            db.add(tmpl)
            db.commit()

            created, skipped, _ = main.create_tickets_from_template(
                db=db,
                template=tmpl,
                actor_id=ids["admin1"],
                period_key="2026-02",
            )
            db.commit()

            created_ticket = (
                db.query(main.Ticket)
                .filter(main.Ticket.company_id == ids["company1"], main.Ticket.ticket_template_id == tmpl.id)
                .first()
            )

            self.assertEqual(created, 1)
            self.assertEqual(skipped, 0)
            self.assertIsNotNone(created_ticket)
            self.assertEqual(len(created_ticket.title), main.MAX_TICKET_TITLE_LEN)

    def test_ticket_visibility_company_and_executor_rules(self):
        ids = self.seed_companies_users()
        with main.SessionLocal() as db:
            p1 = main.Project(company_id=ids["company1"], name="P1", description=None)
            p2 = main.Project(company_id=ids["company2"], name="P2", description=None)
            db.add_all([p1, p2])
            db.flush()

            t1 = main.Ticket(
                title="A1",
                description=None,
                deadline=None,
                status=main.TicketStatus.new,
                company_id=ids["company1"],
                project_id=p1.id,
                executor_id=ids["exec1"],
                created_by=ids["admin1"],
            )
            t2 = main.Ticket(
                title="A2",
                description=None,
                deadline=None,
                status=main.TicketStatus.new,
                company_id=ids["company1"],
                project_id=p1.id,
                executor_id=ids["exec2"],
                created_by=ids["exec1"],
            )
            t3 = main.Ticket(
                title="B1",
                description=None,
                deadline=None,
                status=main.TicketStatus.new,
                company_id=ids["company2"],
                project_id=p2.id,
                executor_id=None,
                created_by=ids["admin2"],
            )
            db.add_all([t1, t2, t3])
            db.commit()

            curator1 = db.get(main.User, ids["curator1"])
            exec1 = db.get(main.User, ids["exec1"])
            admin2 = db.get(main.User, ids["admin2"])

            curator_titles = sorted([t.title for t in main.list_tickets(db=db, user=curator1)])
            exec1_titles = sorted([t.title for t in main.list_tickets(db=db, user=exec1)])
            admin2_titles = sorted([t.title for t in main.list_tickets(db=db, user=admin2)])

            self.assertEqual(curator_titles, ["A1", "A2"])
            self.assertEqual(exec1_titles, ["A1", "A2"])
            self.assertEqual(admin2_titles, ["B1"])


if __name__ == "__main__":
    unittest.main()
