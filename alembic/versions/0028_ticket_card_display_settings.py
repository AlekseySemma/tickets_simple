"""Add per-user ticket card display settings.

Revision ID: 0028_ticket_card_display
Revises: 0027_ticket_template_title_text
Create Date: 2026-04-19
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0028_ticket_card_display"
down_revision = "0027_ticket_template_title_text"
branch_labels = None
depends_on = None


TICKET_CARD_COLUMNS = (
    "ticket_card_show_department",
    "ticket_card_show_executor",
    "ticket_card_show_creator",
)


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    cols = {col["name"] for col in insp.get_columns("users")}
    for column_name in TICKET_CARD_COLUMNS:
        if column_name not in cols:
            op.add_column(
                "users",
                sa.Column(
                    column_name,
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("true"),
                ),
            )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("users"):
        return

    cols = {col["name"] for col in insp.get_columns("users")}
    for column_name in reversed(TICKET_CARD_COLUMNS):
        if column_name in cols:
            op.drop_column("users", column_name)
