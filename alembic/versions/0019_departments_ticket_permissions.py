"""Add departments and per-user ticket permissions.

Revision ID: 0019_departments_ticket_permissions
Revises: 0018_user_receipt_notify
Create Date: 2026-03-16
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0019_departments_ticket_permissions"
down_revision = "0018_user_receipt_notify"
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


def _uq_names(insp: sa.Inspector, table_name: str) -> set[str]:
    names: set[str] = set()
    for item in insp.get_unique_constraints(table_name):
        name = item.get("name")
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

    if not insp.has_table("departments"):
        op.create_table(
            "departments",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("company_id", "name", name="uq_departments_company_name"),
        )
    insp = sa.inspect(bind)
    if insp.has_table("departments"):
        _create_if_missing(insp, "departments", "ix_departments_company_name", ["company_id", "name"])
        _create_if_missing(insp, "departments", "ix_departments_company_active", ["company_id", "is_active"])

    if insp.has_table("users"):
        user_cols = _column_names(insp, "users")
        if "can_view_all_tickets" not in user_cols:
            op.add_column(
                "users",
                sa.Column("can_view_all_tickets", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            )
        if "can_create_tickets" not in user_cols:
            op.add_column(
                "users",
                sa.Column("can_create_tickets", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            )
        if "can_close_tickets" not in user_cols:
            op.add_column(
                "users",
                sa.Column("can_close_tickets", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            )

    if insp.has_table("ticket_types"):
        tt_cols = _column_names(insp, "ticket_types")
        with op.batch_alter_table("ticket_types") as batch_op:
            if "department_id" not in tt_cols:
                batch_op.add_column(sa.Column("department_id", sa.Integer(), nullable=True))
        insp = sa.inspect(bind)
        tt_fk_names = _fk_names(insp, "ticket_types")
        with op.batch_alter_table("ticket_types") as batch_op:
            if "fk_ticket_types_department_id_departments" not in tt_fk_names:
                batch_op.create_foreign_key(
                    "fk_ticket_types_department_id_departments",
                    "departments",
                    ["department_id"],
                    ["id"],
                )
        insp = sa.inspect(bind)
        _create_if_missing(insp, "ticket_types", "ix_ticket_types_department_id", ["department_id"])

    if insp.has_table("unit_assignments"):
        ua_cols = _column_names(insp, "unit_assignments")
        with op.batch_alter_table("unit_assignments") as batch_op:
            if "department_id" not in ua_cols:
                batch_op.add_column(sa.Column("department_id", sa.Integer(), nullable=True))
        insp = sa.inspect(bind)
        ua_fk_names = _fk_names(insp, "unit_assignments")
        ua_uq_names = _uq_names(insp, "unit_assignments")
        with op.batch_alter_table("unit_assignments") as batch_op:
            if "fk_unit_assignments_department_id_departments" not in ua_fk_names:
                batch_op.create_foreign_key(
                    "fk_unit_assignments_department_id_departments",
                    "departments",
                    ["department_id"],
                    ["id"],
                )
            if "uq_unit_assignments_company_unit_user_role" in ua_uq_names:
                batch_op.drop_constraint("uq_unit_assignments_company_unit_user_role", type_="unique")
            if "uq_unit_assignments_company_unit_user_role_department" not in ua_uq_names:
                batch_op.create_unique_constraint(
                    "uq_unit_assignments_company_unit_user_role_department",
                    ["company_id", "unit_id", "user_id", "role_code", "department_id"],
                )
        insp = sa.inspect(bind)
        _create_if_missing(insp, "unit_assignments", "ix_unit_assignments_department_id", ["department_id"])

    if insp.has_table("tickets"):
        ticket_cols = _column_names(insp, "tickets")
        with op.batch_alter_table("tickets") as batch_op:
            if "department_id" not in ticket_cols:
                batch_op.add_column(sa.Column("department_id", sa.Integer(), nullable=True))
        insp = sa.inspect(bind)
        ticket_fk_names = _fk_names(insp, "tickets")
        with op.batch_alter_table("tickets") as batch_op:
            if "fk_tickets_department_id_departments" not in ticket_fk_names:
                batch_op.create_foreign_key(
                    "fk_tickets_department_id_departments",
                    "departments",
                    ["department_id"],
                    ["id"],
                )
        insp = sa.inspect(bind)
        _create_if_missing(insp, "tickets", "ix_tickets_company_department_id", ["company_id", "department_id", "id"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("tickets"):
        _drop_if_exists(insp, "tickets", "ix_tickets_company_department_id")
        ticket_fk_names = _fk_names(insp, "tickets")
        with op.batch_alter_table("tickets") as batch_op:
            if "fk_tickets_department_id_departments" in ticket_fk_names:
                batch_op.drop_constraint("fk_tickets_department_id_departments", type_="foreignkey")
        ticket_cols = _column_names(sa.inspect(bind), "tickets")
        with op.batch_alter_table("tickets") as batch_op:
            if "department_id" in ticket_cols:
                batch_op.drop_column("department_id")

    if insp.has_table("unit_assignments"):
        _drop_if_exists(insp, "unit_assignments", "ix_unit_assignments_department_id")
        ua_fk_names = _fk_names(insp, "unit_assignments")
        ua_uq_names = _uq_names(insp, "unit_assignments")
        with op.batch_alter_table("unit_assignments") as batch_op:
            if "fk_unit_assignments_department_id_departments" in ua_fk_names:
                batch_op.drop_constraint("fk_unit_assignments_department_id_departments", type_="foreignkey")
            if "uq_unit_assignments_company_unit_user_role_department" in ua_uq_names:
                batch_op.drop_constraint("uq_unit_assignments_company_unit_user_role_department", type_="unique")
            if "uq_unit_assignments_company_unit_user_role" not in ua_uq_names:
                batch_op.create_unique_constraint(
                    "uq_unit_assignments_company_unit_user_role",
                    ["company_id", "unit_id", "user_id", "role_code"],
                )
        ua_cols = _column_names(sa.inspect(bind), "unit_assignments")
        with op.batch_alter_table("unit_assignments") as batch_op:
            if "department_id" in ua_cols:
                batch_op.drop_column("department_id")

    if insp.has_table("ticket_types"):
        _drop_if_exists(insp, "ticket_types", "ix_ticket_types_department_id")
        tt_fk_names = _fk_names(insp, "ticket_types")
        with op.batch_alter_table("ticket_types") as batch_op:
            if "fk_ticket_types_department_id_departments" in tt_fk_names:
                batch_op.drop_constraint("fk_ticket_types_department_id_departments", type_="foreignkey")
        tt_cols = _column_names(sa.inspect(bind), "ticket_types")
        with op.batch_alter_table("ticket_types") as batch_op:
            if "department_id" in tt_cols:
                batch_op.drop_column("department_id")

    if insp.has_table("users"):
        user_cols = _column_names(insp, "users")
        if "can_close_tickets" in user_cols:
            op.drop_column("users", "can_close_tickets")
        if "can_create_tickets" in user_cols:
            op.drop_column("users", "can_create_tickets")
        if "can_view_all_tickets" in user_cols:
            op.drop_column("users", "can_view_all_tickets")

    insp = sa.inspect(bind)
    if insp.has_table("departments"):
        _drop_if_exists(insp, "departments", "ix_departments_company_active")
        _drop_if_exists(insp, "departments", "ix_departments_company_name")
        op.drop_table("departments")
