"""Add auth token version to users.

Revision ID: 0023_auth_token_version
Revises: 0022_password_reset
Create Date: 2026-03-17
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0023_auth_token_version"
down_revision = "0022_password_reset"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    cols = {col["name"] for col in insp.get_columns("users")}
    if "auth_token_version" not in cols:
        op.add_column(
            "users",
            sa.Column("auth_token_version", sa.Integer(), nullable=False, server_default=sa.text("0")),
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    cols = {col["name"] for col in insp.get_columns("users")}
    if "auth_token_version" in cols:
        op.drop_column("users", "auth_token_version")
