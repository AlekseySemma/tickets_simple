"""Make payment cards user-owned.

Revision ID: 0016_payment_cards_owner_user
Revises: 0015_user_preferred_payment_card
Create Date: 2026-03-05
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0016_payment_cards_owner_user"
down_revision = "0015_user_preferred_payment_card"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("payment_cards"):
        return

    cols = {col["name"] for col in insp.get_columns("payment_cards")}
    if "owner_user_id" not in cols:
        op.add_column("payment_cards", sa.Column("owner_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True))

    # Backfill existing cards with the first user of the same company.
    bind.execute(
        sa.text(
            """
            UPDATE payment_cards
            SET owner_user_id = (
                SELECT u.id
                FROM users u
                WHERE u.company_id = payment_cards.company_id
                ORDER BY u.id ASC
                LIMIT 1
            )
            WHERE owner_user_id IS NULL
            """
        )
    )

    indexes = {idx["name"] for idx in insp.get_indexes("payment_cards")}
    if "ix_payment_cards_owner_user_id" not in indexes:
        op.create_index("ix_payment_cards_owner_user_id", "payment_cards", ["owner_user_id"], unique=False)

    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute("ALTER TABLE payment_cards DROP CONSTRAINT IF EXISTS uq_payment_cards_company_name")
        op.execute("DROP INDEX IF EXISTS uq_payment_cards_company_owner_name")
        op.execute(
            "CREATE UNIQUE INDEX uq_payment_cards_company_owner_name ON payment_cards (company_id, owner_user_id, name)"
        )
    else:
        # SQLite may still keep old table-level unique constraint; create a new index where possible.
        try:
            op.create_index(
                "uq_payment_cards_company_owner_name",
                "payment_cards",
                ["company_id", "owner_user_id", "name"],
                unique=True,
            )
        except Exception:
            pass


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("payment_cards"):
        return

    indexes = {idx["name"] for idx in insp.get_indexes("payment_cards")}
    if "uq_payment_cards_company_owner_name" in indexes:
        op.drop_index("uq_payment_cards_company_owner_name", table_name="payment_cards")
    if "ix_payment_cards_owner_user_id" in indexes:
        op.drop_index("ix_payment_cards_owner_user_id", table_name="payment_cards")

    cols = {col["name"] for col in insp.get_columns("payment_cards")}
    if "owner_user_id" in cols:
        op.drop_column("payment_cards", "owner_user_id")
