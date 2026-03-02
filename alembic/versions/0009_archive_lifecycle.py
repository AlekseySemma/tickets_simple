"""Add archive lifecycle fields and cleanup audit log.

Revision ID: 0009_archive_lifecycle
Revises: 0008_company_deadline_warn
Create Date: 2026-03-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0009_archive_lifecycle"
down_revision = "0008_company_deadline_warn"
branch_labels = None
depends_on = None

DEFAULT_ARCHIVE_RETENTION_DAYS = 180


def _column_names(insp: sa.Inspector, table_name: str) -> set[str]:
    return {col["name"] for col in insp.get_columns(table_name)}


def _index_names(insp: sa.Inspector, table_name: str) -> set[str]:
    return {idx["name"] for idx in insp.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute("ALTER TYPE ticketstatus ADD VALUE IF NOT EXISTS 'ARCHIVED'")

    if insp.has_table("companies"):
        company_cols = _column_names(insp, "companies")
        if "archive_retention_days_default" not in company_cols:
            op.add_column("companies", sa.Column("archive_retention_days_default", sa.Integer(), nullable=True))
        bind.execute(
            sa.text(
                """
                UPDATE companies
                SET archive_retention_days_default = :default_days
                WHERE archive_retention_days_default IS NULL
                """
            ),
            {"default_days": DEFAULT_ARCHIVE_RETENTION_DAYS},
        )
        op.alter_column(
            "companies",
            "archive_retention_days_default",
            existing_type=sa.Integer(),
            nullable=False,
            server_default=sa.text(str(DEFAULT_ARCHIVE_RETENTION_DAYS)),
        )

    insp = sa.inspect(bind)
    if insp.has_table("ticket_types"):
        tt_cols = _column_names(insp, "ticket_types")
        if "archive_retention_days" not in tt_cols:
            op.add_column("ticket_types", sa.Column("archive_retention_days", sa.Integer(), nullable=True))

    insp = sa.inspect(bind)
    if insp.has_table("tickets"):
        ticket_cols = _column_names(insp, "tickets")
        if "archived_at" not in ticket_cols:
            op.add_column("tickets", sa.Column("archived_at", sa.DateTime(), nullable=True))
        if "archived_by" not in ticket_cols:
            op.add_column("tickets", sa.Column("archived_by", sa.Integer(), nullable=True))
        if "retention_days" not in ticket_cols:
            op.add_column("tickets", sa.Column("retention_days", sa.Integer(), nullable=True))
        if "delete_at" not in ticket_cols:
            op.add_column("tickets", sa.Column("delete_at", sa.DateTime(), nullable=True))
        if "is_legal_hold" not in ticket_cols:
            op.add_column("tickets", sa.Column("is_legal_hold", sa.Boolean(), nullable=True))
            bind.execute(sa.text("UPDATE tickets SET is_legal_hold = 0 WHERE is_legal_hold IS NULL"))
            op.alter_column(
                "tickets",
                "is_legal_hold",
                existing_type=sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            )

        ticket_indexes = _index_names(insp, "tickets")
        if "ix_tickets_archived_at" not in ticket_indexes:
            op.create_index("ix_tickets_archived_at", "tickets", ["archived_at"], unique=False)
        if "ix_tickets_delete_at" not in ticket_indexes:
            op.create_index("ix_tickets_delete_at", "tickets", ["delete_at"], unique=False)
        if "ix_tickets_is_legal_hold" not in ticket_indexes:
            op.create_index("ix_tickets_is_legal_hold", "tickets", ["is_legal_hold"], unique=False)
        if "ix_tickets_archived_by" not in ticket_indexes:
            op.create_index("ix_tickets_archived_by", "tickets", ["archived_by"], unique=False)

    insp = sa.inspect(bind)
    if insp.has_table("attachments"):
        attachment_cols = _column_names(insp, "attachments")
        if "file_size_bytes" not in attachment_cols:
            op.add_column("attachments", sa.Column("file_size_bytes", sa.Integer(), nullable=True))
        if "file_sha256" not in attachment_cols:
            op.add_column("attachments", sa.Column("file_sha256", sa.String(length=64), nullable=True))
        if "archived_at" not in attachment_cols:
            op.add_column("attachments", sa.Column("archived_at", sa.DateTime(), nullable=True))

    insp = sa.inspect(bind)
    if not insp.has_table("archive_cleanup_logs"):
        op.create_table(
            "archive_cleanup_logs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=True),
            sa.Column("ticket_id", sa.Integer(), nullable=False),
            sa.Column("archived_by", sa.Integer(), nullable=True),
            sa.Column("ticket_title", sa.String(length=255), nullable=True),
            sa.Column("archived_at", sa.DateTime(), nullable=True),
            sa.Column("retention_days", sa.Integer(), nullable=True),
            sa.Column("delete_at", sa.DateTime(), nullable=True),
            sa.Column("deleted_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        )
    insp = sa.inspect(bind)
    log_indexes = _index_names(insp, "archive_cleanup_logs")
    if "ix_archive_cleanup_logs_company_id" not in log_indexes:
        op.create_index("ix_archive_cleanup_logs_company_id", "archive_cleanup_logs", ["company_id"], unique=False)
    if "ix_archive_cleanup_logs_ticket_id" not in log_indexes:
        op.create_index("ix_archive_cleanup_logs_ticket_id", "archive_cleanup_logs", ["ticket_id"], unique=False)
    if "ix_archive_cleanup_logs_archived_by" not in log_indexes:
        op.create_index("ix_archive_cleanup_logs_archived_by", "archive_cleanup_logs", ["archived_by"], unique=False)
    if "ix_archive_cleanup_logs_deleted_at" not in log_indexes:
        op.create_index("ix_archive_cleanup_logs_deleted_at", "archive_cleanup_logs", ["deleted_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("archive_cleanup_logs"):
        log_indexes = _index_names(insp, "archive_cleanup_logs")
        for idx in (
            "ix_archive_cleanup_logs_company_id",
            "ix_archive_cleanup_logs_ticket_id",
            "ix_archive_cleanup_logs_archived_by",
            "ix_archive_cleanup_logs_deleted_at",
        ):
            if idx in log_indexes:
                op.drop_index(idx, table_name="archive_cleanup_logs")
        op.drop_table("archive_cleanup_logs")

    insp = sa.inspect(bind)
    if insp.has_table("attachments"):
        attachment_cols = _column_names(insp, "attachments")
        if "archived_at" in attachment_cols:
            op.drop_column("attachments", "archived_at")
        if "file_sha256" in attachment_cols:
            op.drop_column("attachments", "file_sha256")
        if "file_size_bytes" in attachment_cols:
            op.drop_column("attachments", "file_size_bytes")

    insp = sa.inspect(bind)
    if insp.has_table("tickets"):
        ticket_cols = _column_names(insp, "tickets")
        ticket_indexes = _index_names(insp, "tickets")
        for idx in ("ix_tickets_archived_at", "ix_tickets_delete_at", "ix_tickets_is_legal_hold", "ix_tickets_archived_by"):
            if idx in ticket_indexes:
                op.drop_index(idx, table_name="tickets")
        if "is_legal_hold" in ticket_cols:
            op.drop_column("tickets", "is_legal_hold")
        if "delete_at" in ticket_cols:
            op.drop_column("tickets", "delete_at")
        if "retention_days" in ticket_cols:
            op.drop_column("tickets", "retention_days")
        if "archived_by" in ticket_cols:
            op.drop_column("tickets", "archived_by")
        if "archived_at" in ticket_cols:
            op.drop_column("tickets", "archived_at")

    insp = sa.inspect(bind)
    if insp.has_table("ticket_types"):
        tt_cols = _column_names(insp, "ticket_types")
        if "archive_retention_days" in tt_cols:
            op.drop_column("ticket_types", "archive_retention_days")

    insp = sa.inspect(bind)
    if insp.has_table("companies"):
        company_cols = _column_names(insp, "companies")
        if "archive_retention_days_default" in company_cols:
            op.drop_column("companies", "archive_retention_days_default")

    # PostgreSQL ENUM value ARCHIVED is intentionally kept.
