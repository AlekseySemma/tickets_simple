"""Add per-user flag for receipts accounting mode visibility.

Revision ID: 0017_user_receipts_mode
Revises: 0016_payment_cards_owner_user
Create Date: 2026-03-06
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0017_user_receipts_mode"
down_revision = "0016_payment_cards_owner_user"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    cols = {col["name"] for col in insp.get_columns("users")}
    if "show_receipts_accounting_mode" not in cols:
        op.add_column(
            "users",
            sa.Column(
                "show_receipts_accounting_mode",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("true"),
            ),
        )

    # Keep prior UX: executors have field mode only by default.
    role_expr = "LOWER(role::text)" if bind.dialect.name == "postgresql" else "LOWER(CAST(role AS TEXT))"
    bind.execute(
        sa.text(
            f"""
            UPDATE users
            SET show_receipts_accounting_mode = CASE
                WHEN {role_expr} = 'executor' THEN false
                ELSE true
            END
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return
    cols = {col["name"] for col in insp.get_columns("users")}
    if "show_receipts_accounting_mode" in cols:
        op.drop_column("users", "show_receipts_accounting_mode")
