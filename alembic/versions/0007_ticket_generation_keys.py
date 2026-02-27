"""Add persistent ticket generation keys.

Revision ID: 0007_ticket_generation_keys
Revises: 0006_ticket_template_dedupe
Create Date: 2026-02-27
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0007_ticket_generation_keys"
down_revision = "0006_ticket_template_dedupe"
branch_labels = None
depends_on = None


def _index_names(insp: sa.Inspector, table_name: str) -> set[str]:
    return {idx["name"] for idx in insp.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("ticket_generation_keys"):
        op.create_table(
            "ticket_generation_keys",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("company_id", sa.Integer(), sa.ForeignKey("companies.id"), nullable=False),
            sa.Column("ticket_template_id", sa.Integer(), sa.ForeignKey("ticket_templates.id"), nullable=False),
            sa.Column("target_unit_id", sa.Integer(), sa.ForeignKey("org_units.id"), nullable=False),
            sa.Column("period_key", sa.String(length=16), nullable=False),
            sa.Column("ticket_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint(
                "company_id",
                "ticket_template_id",
                "target_unit_id",
                "period_key",
                name="uq_ticket_generation_keys_scope",
            ),
        )

    insp = sa.inspect(bind)
    idx = _index_names(insp, "ticket_generation_keys")
    if "ix_ticket_generation_keys_company_template_period" not in idx:
        op.create_index(
            "ix_ticket_generation_keys_company_template_period",
            "ticket_generation_keys",
            ["company_id", "ticket_template_id", "period_key"],
            unique=False,
        )

    # Backfill keys from already generated tickets so old months stay deduplicated.
    op.execute(
        sa.text(
            """
            INSERT INTO ticket_generation_keys (company_id, ticket_template_id, target_unit_id, period_key, ticket_id, created_at)
            SELECT t.company_id, t.ticket_template_id, t.target_unit_id, t.period_key, t.id, COALESCE(t.created_at, CURRENT_TIMESTAMP)
            FROM tickets t
            WHERE t.ticket_template_id IS NOT NULL
              AND t.target_unit_id IS NOT NULL
              AND t.period_key IS NOT NULL
            ON CONFLICT (company_id, ticket_template_id, target_unit_id, period_key) DO NOTHING
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("ticket_generation_keys"):
        return

    idx = _index_names(insp, "ticket_generation_keys")
    if "ix_ticket_generation_keys_company_template_period" in idx:
        op.drop_index("ix_ticket_generation_keys_company_template_period", table_name="ticket_generation_keys")
    op.drop_table("ticket_generation_keys")
