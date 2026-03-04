"""Add ticket watchers.

Revision ID: 0011_ticket_watchers
Revises: 0010_ticketstatus_archived_lower
Create Date: 2026-03-04
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError


revision = "0011_ticket_watchers"
down_revision = "0010_ticketstatus_archived_lower"
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

    if not insp.has_table("ticket_watchers"):
        op.create_table(
            "ticket_watchers",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("tickets.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("added_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("ticket_id", "user_id", name="uq_ticket_watchers_ticket_user"),
        )

    insp = sa.inspect(bind)
    if insp.has_table("ticket_watchers"):
        _create_if_missing(insp, "ticket_watchers", "ix_ticket_watchers_ticket_id", ["ticket_id"])
        _create_if_missing(insp, "ticket_watchers", "ix_ticket_watchers_user_id", ["user_id"])
        _create_if_missing(insp, "ticket_watchers", "ix_ticket_watchers_added_by", ["added_by"])
        _create_if_missing(insp, "ticket_watchers", "ix_ticket_watchers_created_at", ["created_at"])

    if not insp.has_table("tickets"):
        return

    rows = bind.execute(sa.text("SELECT id, created_by, executor_id FROM tickets")).fetchall()
    for row in rows:
        ticket_id = int(row[0])
        user_ids = {int(row[1])}
        if row[2] is not None:
            user_ids.add(int(row[2]))
        for user_id in user_ids:
            try:
                bind.execute(
                    sa.text(
                        """
                        INSERT INTO ticket_watchers (ticket_id, user_id, added_by)
                        VALUES (:ticket_id, :user_id, :added_by)
                        """
                    ),
                    {"ticket_id": ticket_id, "user_id": user_id, "added_by": row[1]},
                )
            except IntegrityError:
                pass


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if insp.has_table("ticket_watchers"):
        _drop_if_exists(insp, "ticket_watchers", "ix_ticket_watchers_created_at")
        _drop_if_exists(insp, "ticket_watchers", "ix_ticket_watchers_added_by")
        _drop_if_exists(insp, "ticket_watchers", "ix_ticket_watchers_user_id")
        _drop_if_exists(insp, "ticket_watchers", "ix_ticket_watchers_ticket_id")
        op.drop_table("ticket_watchers")
