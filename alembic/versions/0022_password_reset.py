"""Add user password reset fields.

Revision ID: 0022_password_reset
Revises: 0021_merge_email_template
Create Date: 2026-03-17
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0022_password_reset"
down_revision = "0021_merge_email_template"
branch_labels = None
depends_on = None


def _index_names(insp: sa.Inspector, table_name: str) -> set[str]:
    return {idx["name"] for idx in insp.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    cols = {col["name"] for col in insp.get_columns("users")}
    if "password_reset_token" not in cols:
        op.add_column("users", sa.Column("password_reset_token", sa.String(length=255), nullable=True))
    if "password_reset_expires_at" not in cols:
        op.add_column("users", sa.Column("password_reset_expires_at", sa.DateTime(), nullable=True))
    if "password_reset_sent_at" not in cols:
        op.add_column("users", sa.Column("password_reset_sent_at", sa.DateTime(), nullable=True))

    insp = sa.inspect(bind)
    indexes = _index_names(insp, "users")
    if "ix_users_password_reset_token" not in indexes:
        op.create_index("ix_users_password_reset_token", "users", ["password_reset_token"], unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    indexes = _index_names(insp, "users")
    if "ix_users_password_reset_token" in indexes:
        op.drop_index("ix_users_password_reset_token", table_name="users")

    cols = {col["name"] for col in insp.get_columns("users")}
    if "password_reset_sent_at" in cols:
        op.drop_column("users", "password_reset_sent_at")
    if "password_reset_expires_at" in cols:
        op.drop_column("users", "password_reset_expires_at")
    if "password_reset_token" in cols:
        op.drop_column("users", "password_reset_token")
