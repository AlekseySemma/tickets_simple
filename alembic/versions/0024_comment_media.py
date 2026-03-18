"""Add comment media table.

Revision ID: 0024_comment_media
Revises: 0023_auth_token_version
Create Date: 2026-03-18
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0024_comment_media"
down_revision = "0023_auth_token_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if insp.has_table("comment_media"):
        return

    op.create_table(
        "comment_media",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("comment_id", sa.Integer(), sa.ForeignKey("comments.id"), nullable=False),
        sa.Column("file_path", sa.String(length=500), nullable=False),
        sa.Column("original_name", sa.String(length=255), nullable=True),
        sa.Column("media_kind", sa.String(length=16), nullable=False),
        sa.Column("file_size_bytes", sa.Integer(), nullable=True),
        sa.Column("file_sha256", sa.String(length=64), nullable=True),
        sa.Column("archived_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_comment_media_comment_id", "comment_media", ["comment_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("comment_media"):
        return

    indexes = {item["name"] for item in insp.get_indexes("comment_media")}
    if "ix_comment_media_comment_id" in indexes:
        op.drop_index("ix_comment_media_comment_id", table_name="comment_media")
    op.drop_table("comment_media")
