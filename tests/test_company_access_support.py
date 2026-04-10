import os
import unittest

from fastapi import HTTPException
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


class CompanyAccessSupportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def _seed_company_user_and_ticket(self):
        with main.SessionLocal() as db:
            company = main.Company(name="Access Co")
            other_company = main.Company(name="Other Co")
            db.add_all([company, other_company])
            db.flush()

            user = main.User(
                email="admin@example.com",
                name="Admin",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            other_user = main.User(
                email="other@example.com",
                name="Other",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=other_company.id,
                email_verified=True,
            )
            db.add_all([user, other_user])
            db.flush()

            project = main.Project(company_id=company.id, name="Project A")
            card = main.PaymentCard(company_id=company.id, owner_user_id=user.id, name="Card A")
            db.add_all([project, card])
            db.flush()

            ticket = main.Ticket(
                company_id=company.id,
                project_id=project.id,
                created_by=user.id,
                title="Ticket A",
                status=main.TicketStatus.new,
            )
            receipt = main.Receipt(
                company_id=company.id,
                project_id=project.id,
                card_id=card.id,
                created_by=user.id,
                status=main.ReceiptStatus.new,
                comment="Receipt A",
            )
            foreign_project = main.Project(company_id=other_company.id, name="Foreign Project")
            db.add(foreign_project)
            db.flush()
            foreign_ticket = main.Ticket(
                company_id=other_company.id,
                project_id=foreign_project.id,
                created_by=other_user.id,
                title="Foreign",
                status=main.TicketStatus.new,
            )
            db.add_all([ticket, receipt, foreign_ticket])
            db.commit()
            return user.id, ticket.id, receipt.id, foreign_ticket.id

    def test_company_ticket_and_receipt_lookup(self):
        user_id, ticket_id, receipt_id, foreign_ticket_id = self._seed_company_user_and_ticket()
        with main.SessionLocal() as db:
            user = db.get(main.User, user_id)
            self.assertEqual(main.get_company_ticket_or_404(db, user, ticket_id).id, ticket_id)
            self.assertEqual(main.get_company_receipt_or_404(db, user, receipt_id).id, receipt_id)
            with self.assertRaises(HTTPException) as exc:
                main.get_company_ticket_or_404(db, user, foreign_ticket_id)
            self.assertEqual(exc.exception.status_code, 403)

    def test_require_role_checker_forbids_wrong_role(self):
        checker = main.require_role(main.Role.admin)

        allowed_user = type("UserObj", (), {"role": main.Role.admin})()
        denied_user = type("UserObj", (), {"role": main.Role.executor})()

        self.assertIs(checker(allowed_user), allowed_user)
        with self.assertRaises(HTTPException) as exc:
            checker(denied_user)
        self.assertEqual(exc.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
