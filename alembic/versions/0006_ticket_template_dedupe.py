"""Add ticket template dedupe columns.

Revision ID: 0006_ticket_template_dedupe
Revises: 0005_inapp_notifications
Create Date: 2026-02-27
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0006_ticket_template_dedupe"
down_revision = "0005_inapp_notifications"
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

    if not insp.has_table("tickets"):
        return

    columns = _column_names(insp, "tickets")
    with op.batch_alter_table("tickets") as batch_op:
        if "ticket_template_id" not in columns:
            batch_op.add_column(sa.Column("ticket_template_id", sa.Integer(), nullable=True))
        if "period_key" not in columns:
            batch_op.add_column(sa.Column("period_key", sa.String(length=16), nullable=True))

    insp = sa.inspect(bind)
    fk_names = _fk_names(insp, "tickets")
    with op.batch_alter_table("tickets") as batch_op:
        if "fk_tickets_ticket_template_id_ticket_templates" not in fk_names:
            batch_op.create_foreign_key(
                "fk_tickets_ticket_template_id_ticket_templates",
                "ticket_templates",
                ["ticket_template_id"],
                ["id"],
            )

    insp = sa.inspect(bind)
    index_names = _index_names(insp, "tickets")
    if "ix_tickets_ticket_template_id" not in index_names:
        op.create_index("ix_tickets_ticket_template_id", "tickets", ["ticket_template_id"], unique=False)
    if "ix_tickets_period_key" not in index_names:
        op.create_index("ix_tickets_period_key", "tickets", ["period_key"], unique=False)
    if "uq_tickets_company_template_unit_period" not in index_names:
        op.create_index(
            "uq_tickets_company_template_unit_period",
            "tickets",
            ["company_id", "ticket_template_id", "target_unit_id", "period_key"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("tickets"):
        return

    index_names = _index_names(insp, "tickets")
    if "uq_tickets_company_template_unit_period" in index_names:
        op.drop_index("uq_tickets_company_template_unit_period", table_name="tickets")
    if "ix_tickets_period_key" in index_names:
        op.drop_index("ix_tickets_period_key", table_name="tickets")
    if "ix_tickets_ticket_template_id" in index_names:
        op.drop_index("ix_tickets_ticket_template_id", table_name="tickets")

    fk_names = _fk_names(sa.inspect(bind), "tickets")
    with op.batch_alter_table("tickets") as batch_op:
        if "fk_tickets_ticket_template_id_ticket_templates" in fk_names:
            batch_op.drop_constraint("fk_tickets_ticket_template_id_ticket_templates", type_="foreignkey")

    columns = _column_names(sa.inspect(bind), "tickets")
    with op.batch_alter_table("tickets") as batch_op:
        if "period_key" in columns:
            batch_op.drop_column("period_key")
        if "ticket_template_id" in columns:
            batch_op.drop_column("ticket_template_id")
