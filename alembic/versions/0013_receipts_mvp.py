"""Receipts MVP tables.

Revision ID: 0013_receipts_mvp
Revises: 0012_user_watcher_comment_notify
Create Date: 2026-03-05
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0013_receipts_mvp"
down_revision = "0012_user_watcher_comment_notify"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("payment_cards"):
        op.create_table(
            "payment_cards",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("company_id", "name", name="uq_payment_cards_company_name"),
        )
        op.create_index("ix_payment_cards_company_id", "payment_cards", ["company_id"], unique=False)
        op.create_index("ix_payment_cards_name", "payment_cards", ["name"], unique=False)
        op.create_index("ix_payment_cards_is_active", "payment_cards", ["is_active"], unique=False)

    if not insp.has_table("receipts"):
        op.create_table(
            "receipts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("card_id", sa.Integer(), sa.ForeignKey("payment_cards.id"), nullable=False),
            sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="NEW"),
            sa.Column("comment", sa.Text(), nullable=False),
            sa.Column("amount", sa.Numeric(12, 2), nullable=True),
            sa.Column("receipt_date", sa.Date(), nullable=True),
            sa.Column("category", sa.String(length=255), nullable=True),
            sa.Column("supplier", sa.String(length=255), nullable=True),
            sa.Column("processed_at", sa.DateTime(), nullable=True),
            sa.Column("processed_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("ix_receipts_company_id", "receipts", ["company_id"], unique=False)
        op.create_index("ix_receipts_project_id", "receipts", ["project_id"], unique=False)
        op.create_index("ix_receipts_card_id", "receipts", ["card_id"], unique=False)
        op.create_index("ix_receipts_created_by", "receipts", ["created_by"], unique=False)
        op.create_index("ix_receipts_status", "receipts", ["status"], unique=False)
        op.create_index("ix_receipts_created_at", "receipts", ["created_at"], unique=False)
        op.create_index("ix_receipts_processed_by", "receipts", ["processed_by"], unique=False)

    if not insp.has_table("receipt_files"):
        op.create_table(
            "receipt_files",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("receipt_id", sa.Integer(), sa.ForeignKey("receipts.id"), nullable=False),
            sa.Column("uploader_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("file_path", sa.String(length=500), nullable=False),
            sa.Column("original_name", sa.String(length=255), nullable=True),
            sa.Column("file_size_bytes", sa.Integer(), nullable=True),
            sa.Column("file_sha256", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("ix_receipt_files_receipt_id", "receipt_files", ["receipt_id"], unique=False)
        op.create_index("ix_receipt_files_uploader_id", "receipt_files", ["uploader_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("receipt_files"):
        for idx in ("ix_receipt_files_receipt_id", "ix_receipt_files_uploader_id"):
            if idx in {i["name"] for i in insp.get_indexes("receipt_files")}:
                op.drop_index(idx, table_name="receipt_files")
        op.drop_table("receipt_files")

    if insp.has_table("receipts"):
        for idx in (
            "ix_receipts_company_id",
            "ix_receipts_project_id",
            "ix_receipts_card_id",
            "ix_receipts_created_by",
            "ix_receipts_status",
            "ix_receipts_created_at",
            "ix_receipts_processed_by",
        ):
            if idx in {i["name"] for i in insp.get_indexes("receipts")}:
                op.drop_index(idx, table_name="receipts")
        op.drop_table("receipts")

    if insp.has_table("payment_cards"):
        for idx in ("ix_payment_cards_company_id", "ix_payment_cards_name", "ix_payment_cards_is_active"):
            if idx in {i["name"] for i in insp.get_indexes("payment_cards")}:
                op.drop_index(idx, table_name="payment_cards")
        op.drop_table("payment_cards")
