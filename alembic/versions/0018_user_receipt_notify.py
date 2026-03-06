"""Add per-user receipt notifications toggle.

Revision ID: 0018_user_receipt_notify
Revises: 0017_user_receipts_mode
Create Date: 2026-03-06
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0018_user_receipt_notify"
down_revision = "0017_user_receipts_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    cols = {col["name"] for col in insp.get_columns("users")}
    if "notify_receipt_created" not in cols:
        op.add_column(
            "users",
            sa.Column(
                "notify_receipt_created",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("true"),
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return
    cols = {col["name"] for col in insp.get_columns("users")}
    if "notify_receipt_created" in cols:
        op.drop_column("users", "notify_receipt_created")
