"""Add department to ticket templates.

Revision ID: 0020_template_department
Revises: 0019_departments_permissions
Create Date: 2026-03-16
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0020_template_department"
down_revision = "0019_departments_permissions"
branch_labels = None
depends_on = None


def _index_names(insp: sa.Inspector, table_name: str) -> set[str]:
    return {idx["name"] for idx in insp.get_indexes(table_name)}


def _column_names(insp: sa.Inspector, table_name: str) -> set[str]:
    return {col["name"] for col in insp.get_columns(table_name)}


def _fk_names(insp: sa.Inspector, table_name: str) -> set[str]:
    names: set[str] = set()
    for fk in insp.get_foreign_keys(table_name):
        name = fk.get("name")
        if name:
            names.add(str(name))
    return names


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("ticket_templates"):
        cols = _column_names(insp, "ticket_templates")
        with op.batch_alter_table("ticket_templates") as batch_op:
            if "department_id" not in cols:
                batch_op.add_column(sa.Column("department_id", sa.Integer(), nullable=True))

        insp = sa.inspect(bind)
        fk_names = _fk_names(insp, "ticket_templates")
        with op.batch_alter_table("ticket_templates") as batch_op:
            if "fk_ticket_templates_department_id_departments" not in fk_names:
                batch_op.create_foreign_key(
                    "fk_ticket_templates_department_id_departments",
                    "departments",
                    ["department_id"],
                    ["id"],
                )

        insp = sa.inspect(bind)
        if "ix_ticket_templates_department_id" not in _index_names(insp, "ticket_templates"):
            op.create_index("ix_ticket_templates_department_id", "ticket_templates", ["department_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("ticket_templates"):
        if "ix_ticket_templates_department_id" in _index_names(insp, "ticket_templates"):
            op.drop_index("ix_ticket_templates_department_id", table_name="ticket_templates")

        fk_names = _fk_names(insp, "ticket_templates")
        with op.batch_alter_table("ticket_templates") as batch_op:
            if "fk_ticket_templates_department_id_departments" in fk_names:
                batch_op.drop_constraint("fk_ticket_templates_department_id_departments", type_="foreignkey")

        cols = _column_names(sa.inspect(bind), "ticket_templates")
        with op.batch_alter_table("ticket_templates") as batch_op:
            if "department_id" in cols:
                batch_op.drop_column("department_id")
