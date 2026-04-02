"""Expand ticket template title storage to text.

Revision ID: 0027_ticket_template_title_text
Revises: 0026_user_role_templates
Create Date: 2026-04-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0027_ticket_template_title_text"
down_revision = "0026_user_role_templates"
branch_labels = None
depends_on = None


def _column_by_name(insp: sa.Inspector, table_name: str, column_name: str) -> dict[str, object] | None:
    for column in insp.get_columns(table_name):
        if column.get("name") == column_name:
            return column
    return None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("ticket_templates"):
        return

    title_column = _column_by_name(insp, "ticket_templates", "title_template")
    if not title_column:
        return

    title_type = title_column.get("type")
    if isinstance(title_type, sa.Text):
        return

    with op.batch_alter_table("ticket_templates") as batch_op:
        batch_op.alter_column(
            "title_template",
            existing_type=sa.String(length=255),
            type_=sa.Text(),
            existing_nullable=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("ticket_templates"):
        return

    title_column = _column_by_name(insp, "ticket_templates", "title_template")
    if not title_column:
        return

    title_type = title_column.get("type")
    if isinstance(title_type, sa.String) and getattr(title_type, "length", None) == 255:
        return

    with op.batch_alter_table("ticket_templates") as batch_op:
        batch_op.alter_column(
            "title_template",
            existing_type=sa.Text(),
            type_=sa.String(length=255),
            existing_nullable=True,
        )
