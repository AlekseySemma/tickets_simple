"""Add org structure and ticket type foundation.

Revision ID: 0004_org_structure_ticket_types
Revises: 0003_ticket_query_indexes
Create Date: 2026-02-25
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0004_org_structure_ticket_types"
down_revision = "0003_ticket_query_indexes"
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

    if not insp.has_table("unit_types"):
        op.create_table(
            "unit_types",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("code", sa.String(length=80), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("company_id", "name", name="uq_unit_types_company_name"),
            sa.UniqueConstraint("company_id", "code", name="uq_unit_types_company_code"),
        )
    insp = sa.inspect(bind)
    if insp.has_table("unit_types"):
        _create_if_missing(insp, "unit_types", "ix_unit_types_company_name", ["company_id", "name"])
        _create_if_missing(insp, "unit_types", "ix_unit_types_company_code", ["company_id", "code"])

    if not insp.has_table("org_units"):
        op.create_table(
            "org_units",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("unit_type_id", sa.Integer(), sa.ForeignKey("unit_types.id"), nullable=False),
            sa.Column("parent_id", sa.Integer(), sa.ForeignKey("org_units.id"), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("company_id", "parent_id", "name", name="uq_org_units_company_parent_name"),
        )
    insp = sa.inspect(bind)
    if insp.has_table("org_units"):
        _create_if_missing(insp, "org_units", "ix_org_units_company_parent", ["company_id", "parent_id"])
        _create_if_missing(insp, "org_units", "ix_org_units_company_unit_type", ["company_id", "unit_type_id"])
        _create_if_missing(insp, "org_units", "ix_org_units_company_active", ["company_id", "is_active"])

    if not insp.has_table("unit_assignments"):
        op.create_table(
            "unit_assignments",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("unit_id", sa.Integer(), sa.ForeignKey("org_units.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("role_code", sa.String(length=64), nullable=False),
            sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint(
                "company_id",
                "unit_id",
                "user_id",
                "role_code",
                name="uq_unit_assignments_company_unit_user_role",
            ),
        )
    insp = sa.inspect(bind)
    if insp.has_table("unit_assignments"):
        _create_if_missing(insp, "unit_assignments", "ix_unit_assignments_company_unit", ["company_id", "unit_id"])
        _create_if_missing(insp, "unit_assignments", "ix_unit_assignments_company_user", ["company_id", "user_id"])

    if not insp.has_table("ticket_types"):
        op.create_table(
            "ticket_types",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("company_id", "name", name="uq_ticket_types_company_name"),
        )
    insp = sa.inspect(bind)
    if insp.has_table("ticket_types"):
        _create_if_missing(insp, "ticket_types", "ix_ticket_types_company_name", ["company_id", "name"])

    if not insp.has_table("ticket_templates"):
        op.create_table(
            "ticket_templates",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("ticket_type_id", sa.Integer(), sa.ForeignKey("ticket_types.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("title_template", sa.String(length=255), nullable=True),
            sa.Column("description_template", sa.Text(), nullable=True),
            sa.Column("default_deadline_rule", sa.String(length=64), nullable=True),
            sa.Column("default_executor_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("scope_unit_id", sa.Integer(), sa.ForeignKey("org_units.id"), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("company_id", "name", name="uq_ticket_templates_company_name"),
        )
    insp = sa.inspect(bind)
    if insp.has_table("ticket_templates"):
        _create_if_missing(
            insp, "ticket_templates", "ix_ticket_templates_company_ticket_type", ["company_id", "ticket_type_id"]
        )
        _create_if_missing(insp, "ticket_templates", "ix_ticket_templates_company_scope", ["company_id", "scope_unit_id"])

    if insp.has_table("tickets"):
        columns = _column_names(insp, "tickets")
        with op.batch_alter_table("tickets") as batch_op:
            if "ticket_type_id" not in columns:
                batch_op.add_column(sa.Column("ticket_type_id", sa.Integer(), nullable=True))
            if "target_unit_id" not in columns:
                batch_op.add_column(sa.Column("target_unit_id", sa.Integer(), nullable=True))
            if "batch_id" not in columns:
                batch_op.add_column(sa.Column("batch_id", sa.String(length=64), nullable=True))

        insp = sa.inspect(bind)
        fk_names = _fk_names(insp, "tickets")
        with op.batch_alter_table("tickets") as batch_op:
            if "fk_tickets_ticket_type_id_ticket_types" not in fk_names:
                batch_op.create_foreign_key(
                    "fk_tickets_ticket_type_id_ticket_types",
                    "ticket_types",
                    ["ticket_type_id"],
                    ["id"],
                )
            if "fk_tickets_target_unit_id_org_units" not in fk_names:
                batch_op.create_foreign_key(
                    "fk_tickets_target_unit_id_org_units",
                    "org_units",
                    ["target_unit_id"],
                    ["id"],
                )

        insp = sa.inspect(bind)
        _create_if_missing(insp, "tickets", "ix_tickets_company_ticket_type_id", ["company_id", "ticket_type_id", "id"])
        _create_if_missing(insp, "tickets", "ix_tickets_company_target_unit_id", ["company_id", "target_unit_id", "id"])
        _create_if_missing(insp, "tickets", "ix_tickets_batch_id", ["batch_id"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("tickets"):
        _drop_if_exists(insp, "tickets", "ix_tickets_batch_id")
        _drop_if_exists(insp, "tickets", "ix_tickets_company_target_unit_id")
        _drop_if_exists(insp, "tickets", "ix_tickets_company_ticket_type_id")

        fk_names = _fk_names(insp, "tickets")
        with op.batch_alter_table("tickets") as batch_op:
            if "fk_tickets_target_unit_id_org_units" in fk_names:
                batch_op.drop_constraint("fk_tickets_target_unit_id_org_units", type_="foreignkey")
            if "fk_tickets_ticket_type_id_ticket_types" in fk_names:
                batch_op.drop_constraint("fk_tickets_ticket_type_id_ticket_types", type_="foreignkey")

        columns = _column_names(sa.inspect(bind), "tickets")
        with op.batch_alter_table("tickets") as batch_op:
            if "batch_id" in columns:
                batch_op.drop_column("batch_id")
            if "target_unit_id" in columns:
                batch_op.drop_column("target_unit_id")
            if "ticket_type_id" in columns:
                batch_op.drop_column("ticket_type_id")

    insp = sa.inspect(bind)
    if insp.has_table("ticket_templates"):
        op.drop_table("ticket_templates")
    if insp.has_table("ticket_types"):
        op.drop_table("ticket_types")
    if insp.has_table("unit_assignments"):
        op.drop_table("unit_assignments")
    if insp.has_table("org_units"):
        op.drop_table("org_units")
    if insp.has_table("unit_types"):
        op.drop_table("unit_types")
