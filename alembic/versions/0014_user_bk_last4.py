"""Add bk_last4 to users.

Revision ID: 0014_user_bk_last4
Revises: 0013_receipts_mvp
Create Date: 2026-03-05
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0014_user_bk_last4"
down_revision = "0013_receipts_mvp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return
    user_cols = {col["name"] for col in insp.get_columns("users")}
    if "bk_last4" not in user_cols:
        op.add_column("users", sa.Column("bk_last4", sa.String(length=4), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return
    user_cols = {col["name"] for col in insp.get_columns("users")}
    if "bk_last4" in user_cols:
        op.drop_column("users", "bk_last4")
