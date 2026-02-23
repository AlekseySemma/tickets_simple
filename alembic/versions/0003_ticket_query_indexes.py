"""Add indexes for web tickets list query patterns.

Revision ID: 0003_ticket_query_indexes
Revises: 0002_dedupe_projects_company
Create Date: 2026-02-23
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0003_ticket_query_indexes"
down_revision = "0002_dedupe_projects_company"
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


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("tickets"):
        return

    # Main list: company scope + id ordering.
    _create_if_missing(insp, "tickets", "ix_tickets_company_id_id", ["company_id", "id"])
    # Filters used in /web list.
    _create_if_missing(insp, "tickets", "ix_tickets_company_status_id", ["company_id", "status", "id"])
    _create_if_missing(insp, "tickets", "ix_tickets_company_project_id", ["company_id", "project_id", "id"])
    _create_if_missing(insp, "tickets", "ix_tickets_company_executor_id", ["company_id", "executor_id", "id"])
    # Executor visibility: (executor_id == user.id) OR (created_by == user.id)
    _create_if_missing(insp, "tickets", "ix_tickets_company_created_by_id", ["company_id", "created_by", "id"])
    # Overdue and deadline sorting paths.
    _create_if_missing(insp, "tickets", "ix_tickets_company_deadline_status", ["company_id", "deadline", "status"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("tickets"):
        return

    existing = _index_names(insp, "tickets")
    for idx_name in (
        "ix_tickets_company_deadline_status",
        "ix_tickets_company_created_by_id",
        "ix_tickets_company_executor_id",
        "ix_tickets_company_project_id",
        "ix_tickets_company_status_id",
        "ix_tickets_company_id_id",
    ):
        if idx_name in existing:
            op.drop_index(idx_name, table_name="tickets")
