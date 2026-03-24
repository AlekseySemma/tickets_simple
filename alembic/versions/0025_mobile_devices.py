"""Add mobile devices table for Android push.

Revision ID: 0025_mobile_devices
Revises: 0024_comment_media
Create Date: 2026-03-24
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0025_mobile_devices"
down_revision = "0024_comment_media"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if insp.has_table("mobile_devices"):
        return

    op.create_table(
        "mobile_devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("platform", sa.String(length=32), nullable=False),
        sa.Column("device_id", sa.String(length=128), nullable=False),
        sa.Column("token", sa.String(length=2048), nullable=False),
        sa.Column("app_version", sa.String(length=64), nullable=True),
        sa.Column("device_name", sa.String(length=255), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("platform", "device_id", name="uq_mobile_devices_platform_device"),
        sa.UniqueConstraint("token"),
    )
    op.create_index("ix_mobile_devices_user_id", "mobile_devices", ["user_id"], unique=False)
    op.create_index("ix_mobile_devices_platform", "mobile_devices", ["platform"], unique=False)
    op.create_index("ix_mobile_devices_token", "mobile_devices", ["token"], unique=True)
    op.create_index("ix_mobile_devices_last_seen_at", "mobile_devices", ["last_seen_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("mobile_devices"):
        return

    indexes = {item["name"] for item in insp.get_indexes("mobile_devices")}
    for index_name in (
        "ix_mobile_devices_last_seen_at",
        "ix_mobile_devices_token",
        "ix_mobile_devices_platform",
        "ix_mobile_devices_user_id",
    ):
        if index_name in indexes:
            op.drop_index(index_name, table_name="mobile_devices")
    op.drop_table("mobile_devices")
