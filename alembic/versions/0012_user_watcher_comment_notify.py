"""Add user setting for watcher comment notifications.

Revision ID: 0012_user_watcher_comment_notify
Revises: 0011_ticket_watchers
Create Date: 2026-03-04
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0012_user_watcher_comment_notify"
down_revision = "0011_ticket_watchers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    user_cols = {col["name"] for col in insp.get_columns("users")}
    if "notify_comments_as_watcher" not in user_cols:
        op.add_column(
            "users",
            sa.Column("notify_comments_as_watcher", sa.Boolean(), nullable=True, server_default=sa.text("1")),
        )

    bind.execute(sa.text("UPDATE users SET notify_comments_as_watcher = 1 WHERE notify_comments_as_watcher IS NULL"))


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    user_cols = {col["name"] for col in insp.get_columns("users")}
    if "notify_comments_as_watcher" in user_cols:
        op.drop_column("users", "notify_comments_as_watcher")
