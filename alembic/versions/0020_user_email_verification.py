"""Add user email verification fields.

Revision ID: 0020_user_email_verification
Revises: 0019_departments_permissions
Create Date: 2026-03-17
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0020_user_email_verification"
down_revision = "0019_departments_permissions"
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
    if "email_verified" not in cols:
        op.add_column(
            "users",
            sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
    if "email_verified_at" not in cols:
        op.add_column("users", sa.Column("email_verified_at", sa.DateTime(), nullable=True))
    if "email_verification_token" not in cols:
        op.add_column("users", sa.Column("email_verification_token", sa.String(length=255), nullable=True))
    if "email_verification_expires_at" not in cols:
        op.add_column("users", sa.Column("email_verification_expires_at", sa.DateTime(), nullable=True))
    if "email_verification_sent_at" not in cols:
        op.add_column("users", sa.Column("email_verification_sent_at", sa.DateTime(), nullable=True))

    insp = sa.inspect(bind)
    indexes = _index_names(insp, "users")
    if "ix_users_email_verification_token" not in indexes:
        op.create_index("ix_users_email_verification_token", "users", ["email_verification_token"], unique=True)

    bind.execute(
        sa.text(
            """
            UPDATE users
            SET email_verified = true
            WHERE email_verified = false OR email_verified IS NULL
            """
        )
    )
    bind.execute(
        sa.text(
            """
            UPDATE users
            SET email_verified_at = CURRENT_TIMESTAMP
            WHERE email_verified = 1 AND email_verified_at IS NULL
            """
        )
    )
    bind.execute(
        sa.text(
            """
            UPDATE users
            SET email_verification_token = NULL,
                email_verification_expires_at = NULL,
                email_verification_sent_at = NULL
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    indexes = _index_names(insp, "users")
    if "ix_users_email_verification_token" in indexes:
        op.drop_index("ix_users_email_verification_token", table_name="users")

    cols = {col["name"] for col in insp.get_columns("users")}
    if "email_verification_sent_at" in cols:
        op.drop_column("users", "email_verification_sent_at")
    if "email_verification_expires_at" in cols:
        op.drop_column("users", "email_verification_expires_at")
    if "email_verification_token" in cols:
        op.drop_column("users", "email_verification_token")
    if "email_verified_at" in cols:
        op.drop_column("users", "email_verified_at")
    if "email_verified" in cols:
        op.drop_column("users", "email_verified")
