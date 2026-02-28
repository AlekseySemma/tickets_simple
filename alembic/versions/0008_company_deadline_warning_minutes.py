"""Add per-company yellow deadline warning threshold.

Revision ID: 0008_company_deadline_warning_minutes
Revises: 0007_ticket_generation_keys
Create Date: 2026-02-28
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0008_company_deadline_warning_minutes"
down_revision = "0007_ticket_generation_keys"
branch_labels = None
depends_on = None


DEFAULT_WARNING_MINUTES = 1440


def _column_names(insp: sa.Inspector, table_name: str) -> set[str]:
    return {col["name"] for col in insp.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("companies"):
        return

    columns = _column_names(insp, "companies")
    if "deadline_soon_warning_minutes" not in columns:
        with op.batch_alter_table("companies") as batch_op:
            batch_op.add_column(
                sa.Column(
                    "deadline_soon_warning_minutes",
                    sa.Integer(),
                    nullable=False,
                    server_default=str(DEFAULT_WARNING_MINUTES),
                )
            )

    op.execute(
        sa.text(
            "UPDATE companies "
            "SET deadline_soon_warning_minutes = :default_value "
            "WHERE deadline_soon_warning_minutes IS NULL"
        ),
        {"default_value": DEFAULT_WARNING_MINUTES},
    )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("companies"):
        return

    columns = _column_names(insp, "companies")
    if "deadline_soon_warning_minutes" in columns:
        with op.batch_alter_table("companies") as batch_op:
            batch_op.drop_column("deadline_soon_warning_minutes")
