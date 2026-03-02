"""Ensure ticketstatus enum contains lowercase archived value.

Revision ID: 0010_ticketstatus_archived_lower
Revises: 0009_archive_lifecycle
Create Date: 2026-03-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0010_ticketstatus_archived_lower"
down_revision = "0009_archive_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_type t
                JOIN pg_enum e ON e.enumtypid = t.oid
                WHERE t.typname = 'ticketstatus' AND e.enumlabel = 'archived'
            ) THEN
                ALTER TYPE ticketstatus ADD VALUE 'archived';
            END IF;
        END
        $$;
        """
    )

    # Normalize rows if uppercase enum label was introduced earlier.
    bind.execute(sa.text("UPDATE tickets SET status = 'archived' WHERE status::text = 'ARCHIVED'"))


def downgrade() -> None:
    # Enum values are intentionally preserved.
    pass
