"""P1 baseline migration

Revision ID: 0001_p1_schema_baseline
Revises:
Create Date: 2026-02-23

"""
from __future__ import annotations

from pathlib import Path

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0001_p1_schema_baseline"
down_revision = None
branch_labels = None
depends_on = None


def _normalize_attachment_path(raw_path: str | None) -> str | None:
    raw = (raw_path or "").strip()
    if not raw or raw.startswith("/uploads/"):
        return None
    basename = Path(raw.replace("\\", "/")).name.strip()
    if not basename:
        return None
    return f"/uploads/{basename}"


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
    dialect = bind.dialect.name

    if not insp.has_table("security_events"):
        op.create_table(
            "security_events",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("event_type", sa.String(length=80), nullable=False),
            sa.Column("endpoint", sa.String(length=255), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("email", sa.String(length=255), nullable=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("detail", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("ix_security_events_event_type", "security_events", ["event_type"], unique=False)
        op.create_index("ix_security_events_ip_address", "security_events", ["ip_address"], unique=False)
        op.create_index("ix_security_events_email", "security_events", ["email"], unique=False)
        op.create_index("ix_security_events_user_id", "security_events", ["user_id"], unique=False)

    if insp.has_table("attachments"):
        rows = bind.execute(sa.text("SELECT id, file_path FROM attachments")).fetchall()
        for row in rows:
            aid = int(row[0])
            normalized = _normalize_attachment_path(row[1])
            if not normalized:
                continue
            bind.execute(
                sa.text("UPDATE attachments SET file_path = :p WHERE id = :id"),
                {"p": normalized, "id": aid},
            )

    if insp.has_table("projects"):
        _dedupe_projects(bind)
        if dialect == "postgresql":
            op.execute("ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_name_key")
            op.execute("DROP INDEX IF EXISTS ix_projects_name")
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
    bind = op.get_bind()
    insp = sa.inspect(bind)
    dialect = bind.dialect.name

    if insp.has_table("projects"):
        if dialect == "postgresql":
            op.execute("DROP INDEX IF EXISTS uq_projects_company_name")
        else:
            project_indexes = {idx["name"] for idx in insp.get_indexes("projects")}
            if "uq_projects_company_name" in project_indexes:
                op.drop_index("uq_projects_company_name", table_name="projects")

    if insp.has_table("security_events"):
        for idx in (
            "ix_security_events_event_type",
            "ix_security_events_ip_address",
            "ix_security_events_email",
            "ix_security_events_user_id",
        ):
            if idx in {i["name"] for i in insp.get_indexes("security_events")}:
                op.drop_index(idx, table_name="security_events")
        op.drop_table("security_events")
