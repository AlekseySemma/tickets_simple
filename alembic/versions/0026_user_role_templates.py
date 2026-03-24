"""Add user executor flag and role templates.

Revision ID: 0026_user_role_templates
Revises: 0025_mobile_devices
Create Date: 2026-03-24
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0026_user_role_templates"
down_revision = "0025_mobile_devices"
branch_labels = None
depends_on = None


ROLE_ENUM = postgresql.ENUM(
    "platform_admin",
    "admin",
    "curator",
    "executor",
    name="role",
    create_type=False,
)


def _column_names(inspector: sa.Inspector, table_name: str) -> set[str]:
    return {item["name"] for item in inspector.get_columns(table_name)}


def _index_names(inspector: sa.Inspector, table_name: str) -> set[str]:
    return {item["name"] for item in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    user_columns = _column_names(insp, "users")
    with op.batch_alter_table("users") as batch_op:
        if "role_label" not in user_columns:
            batch_op.add_column(sa.Column("role_label", sa.String(length=80), nullable=True))
        if "is_assignable_executor" not in user_columns:
            batch_op.add_column(
                sa.Column(
                    "is_assignable_executor",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("false"),
                )
            )

    op.execute(
        sa.text(
            "UPDATE users SET is_assignable_executor = true "
            "WHERE role = 'executor' AND coalesce(is_assignable_executor, false) = false"
        )
    )
    op.execute(
        sa.text(
            "UPDATE users SET is_assignable_executor = false "
            "WHERE role = 'platform_admin'"
        )
    )

    insp = sa.inspect(bind)
    if not insp.has_table("role_templates"):
        op.create_table(
            "role_templates",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("name", sa.String(length=80), nullable=False),
            sa.Column("access_level", ROLE_ENUM, nullable=False),
            sa.Column("is_assignable_executor", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("show_receipts_accounting_mode", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("can_view_all_tickets", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("can_create_tickets", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("can_close_tickets", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("company_id", "name", name="uq_role_templates_company_name"),
        )

    insp = sa.inspect(bind)
    indexes = _index_names(insp, "role_templates")
    if "ix_role_templates_company_id" not in indexes:
        op.create_index("ix_role_templates_company_id", "role_templates", ["company_id"], unique=False)
    if "ix_role_templates_access_level" not in indexes:
        op.create_index("ix_role_templates_access_level", "role_templates", ["access_level"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("role_templates"):
        indexes = _index_names(insp, "role_templates")
        for index_name in ("ix_role_templates_access_level", "ix_role_templates_company_id"):
            if index_name in indexes:
                op.drop_index(index_name, table_name="role_templates")
        op.drop_table("role_templates")

    user_columns = _column_names(sa.inspect(bind), "users")
    with op.batch_alter_table("users") as batch_op:
        if "is_assignable_executor" in user_columns:
            batch_op.drop_column("is_assignable_executor")
        if "role_label" in user_columns:
            batch_op.drop_column("role_label")
