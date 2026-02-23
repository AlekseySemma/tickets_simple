"""Dedupe projects by company and name

Revision ID: 0002_dedupe_projects_company
Revises: 0001_p1_schema_baseline
Create Date: 2026-02-23

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0002_dedupe_projects_company"
down_revision = "0001_p1_schema_baseline"
branch_labels = None
depends_on = None


def _dedupe_projects(bind) -> None:
    rows = bind.execute(
        sa.text(
            """
            SELECT company_id, name, MIN(id) AS keep_id, COUNT(*) AS cnt
            FROM projects
            GROUP BY company_id, name
            HAVING COUNT(*) > 1
            """
        )
    ).fetchall()
    for row in rows:
        company_id = row[0]
        name = row[1]
        keep_id = int(row[2])
        dup_ids_rows = bind.execute(
            sa.text(
                """
                SELECT id
                FROM projects
                WHERE name = :name
                  AND id <> :keep_id
                  AND (
                    (:company_id IS NULL AND company_id IS NULL)
                    OR company_id = :company_id
                  )
                """
            ),
            {"name": name, "keep_id": keep_id, "company_id": company_id},
        ).fetchall()
        dup_ids = [int(r[0]) for r in dup_ids_rows]
        if not dup_ids:
            continue
        for dup_id in dup_ids:
            bind.execute(
                sa.text("UPDATE tickets SET project_id = :keep_id WHERE project_id = :dup_id"),
                {"keep_id": keep_id, "dup_id": dup_id},
            )
            bind.execute(sa.text("DELETE FROM projects WHERE id = :dup_id"), {"dup_id": dup_id})


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("projects"):
        return

    _dedupe_projects(bind)

    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_projects_company_name ON projects (company_id, name)"
        )
    else:
        project_indexes = {idx["name"] for idx in insp.get_indexes("projects")}
        if "uq_projects_company_name" not in project_indexes:
            op.create_index(
                "uq_projects_company_name",
                "projects",
                ["company_id", "name"],
                unique=True,
            )


def downgrade() -> None:
    # Data dedupe is irreversible.
    pass
