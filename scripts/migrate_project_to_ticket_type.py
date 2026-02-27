import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import Project, Ticket, TicketType


def run() -> None:
    db_url = os.getenv("DATABASE_URL", "").strip()
    if not db_url:
        raise RuntimeError("DATABASE_URL is required")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    created_types = 0
    updated_tickets = 0

    with SessionLocal() as db:
        projects = db.query(Project.id, Project.company_id, Project.name).all()
        type_by_company_name: dict[tuple[int | None, str], int] = {}

        existing_types = db.query(TicketType.id, TicketType.company_id, TicketType.name).all()
        for tt_id, company_id, name in existing_types:
            key = (company_id, (name or "").strip().lower())
            type_by_company_name[key] = int(tt_id)

        for _, company_id, project_name in projects:
            normalized_name = (project_name or "").strip()
            if not normalized_name:
                continue
            key = (company_id, normalized_name.lower())
            if key in type_by_company_name:
                continue
            new_type = TicketType(
                company_id=company_id,
                name=normalized_name,
                description="Migrated from project name",
                is_active=True,
            )
            db.add(new_type)
            db.flush()
            type_by_company_name[key] = int(new_type.id)
            created_types += 1

        for project_id, company_id, project_name in projects:
            normalized_name = (project_name or "").strip()
            if not normalized_name:
                continue
            key = (company_id, normalized_name.lower())
            ticket_type_id = type_by_company_name.get(key)
            if ticket_type_id is None:
                continue
            count = (
                db.query(Ticket)
                .filter(
                    Ticket.project_id == project_id,
                    Ticket.company_id == company_id,
                    Ticket.ticket_type_id.is_(None),
                )
                .update({"ticket_type_id": ticket_type_id}, synchronize_session=False)
            )
            updated_tickets += int(count or 0)

        db.commit()

    print(f"Created ticket types: {created_types}")
    print(f"Updated tickets: {updated_tickets}")


if __name__ == "__main__":
    run()
