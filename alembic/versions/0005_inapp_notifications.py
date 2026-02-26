"""Add in-app notifications.

Revision ID: 0005_inapp_notifications
Revises: 0004_org_structure_ticket_types
Create Date: 2026-02-26
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0005_inapp_notifications"
down_revision = "0004_org_structure_ticket_types"
branch_labels = None
depends_on = None


def _index_names(insp: sa.Inspector, table_name: str) -> set[str]:
    return {idx["name"] for idx in insp.get_indexes(table_name)}


def _create_if_missing(
    insp: sa.Inspector,
    table_name: str,
    index_name: str,
    columns: list[str],
) -> None:
    if index_name not in _index_names(insp, table_name):
        op.create_index(index_name, table_name, columns, unique=False)


def _drop_if_exists(insp: sa.Inspector, table_name: str, index_name: str) -> None:
    if index_name in _index_names(insp, table_name):
        op.drop_index(index_name, table_name=table_name)


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("notifications"):
        op.create_table(
            "notifications",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("body", sa.Text(), nullable=True),
            sa.Column("url", sa.String(length=500), nullable=True),
            sa.Column("is_read", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("read_at", sa.DateTime(), nullable=True),
        )

    insp = sa.inspect(bind)
    if insp.has_table("notifications"):
        _create_if_missing(insp, "notifications", "ix_notifications_user_id", ["user_id"])
        _create_if_missing(insp, "notifications", "ix_notifications_user_is_read", ["user_id", "is_read"])
        _create_if_missing(insp, "notifications", "ix_notifications_user_created_at", ["user_id", "created_at"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if insp.has_table("notifications"):
        _drop_if_exists(insp, "notifications", "ix_notifications_user_created_at")
        _drop_if_exists(insp, "notifications", "ix_notifications_user_is_read")
        _drop_if_exists(insp, "notifications", "ix_notifications_user_id")
        op.drop_table("notifications")
