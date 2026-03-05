"""Add preferred payment card to users.

Revision ID: 0015_user_preferred_payment_card
Revises: 0014_user_bk_last4
Create Date: 2026-03-05
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0015_user_preferred_payment_card"
down_revision = "0014_user_bk_last4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return
    user_cols = {col["name"] for col in insp.get_columns("users")}
    if "preferred_payment_card_id" not in user_cols:
        op.add_column(
            "users",
            sa.Column("preferred_payment_card_id", sa.Integer(), sa.ForeignKey("payment_cards.id"), nullable=True),
        )
    user_indexes = {idx["name"] for idx in insp.get_indexes("users")}
    if "ix_users_preferred_payment_card_id" not in user_indexes:
        op.create_index("ix_users_preferred_payment_card_id", "users", ["preferred_payment_card_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return
    user_indexes = {idx["name"] for idx in insp.get_indexes("users")}
    if "ix_users_preferred_payment_card_id" in user_indexes:
        op.drop_index("ix_users_preferred_payment_card_id", table_name="users")
    user_cols = {col["name"] for col in insp.get_columns("users")}
    if "preferred_payment_card_id" in user_cols:
        op.drop_column("users", "preferred_payment_card_id")
