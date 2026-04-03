from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_ticket_type_routes(
    app,
    *,
    get_db,
    get_current_user,
    is_manager,
    is_admin,
    ensure_company_user,
    parse_archive_retention_days,
    templates,
    ticket_type_model,
    ticket_model,
    department_model,
    http_303_see_other,
):
    @app.get("/web/ticket-types")
    def web_ticket_types(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        ticket_types = (
            db.query(
                ticket_type_model.id,
                ticket_type_model.name,
                ticket_type_model.description,
                ticket_type_model.department_id,
                ticket_type_model.archive_retention_days,
                ticket_type_model.is_active,
                department_model.name.label("department_name"),
            )
            .outerjoin(department_model, department_model.id == ticket_type_model.department_id)
            .filter(ticket_type_model.company_id == user.company_id)
            .order_by(ticket_type_model.id.desc())
            .all()
        )
        departments = (
            db.query(department_model.id, department_model.name, department_model.is_active)
            .filter(department_model.company_id == user.company_id)
            .order_by(department_model.name.asc(), department_model.id.asc())
            .all()
        )
        return templates.TemplateResponse(
            "ticket_types.html",
            {
                "request": request,
                "user": user,
                "ticket_types": ticket_types,
                "departments": departments,
                "can_manage_departments": is_admin(user),
            },
        )

    @app.post("/web/ticket-types/create")
    async def web_ticket_types_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        form = await request.form()
        name = (form.get("name") or "").strip()
        description = (form.get("description") or "").strip() or None
        department_raw = (form.get("department_id") or "").strip()
        archive_retention_days = parse_archive_retention_days(form.get("archive_retention_days"))
        if (form.get("archive_retention_days") or "").strip() and archive_retention_days is None:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        is_active = (form.get("is_active") or "1").strip() == "1"
        if not name:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        department_id = int(department_raw) if department_raw.isdigit() else None
        if department_raw and department_id is None:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        if department_id is not None:
            department = db.get(department_model, department_id)
            if not department or department.company_id != user.company_id:
                return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        exists = (
            db.query(ticket_type_model)
            .filter(ticket_type_model.company_id == user.company_id, ticket_type_model.name == name)
            .first()
        )
        if exists:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        item = ticket_type_model(
            company_id=user.company_id,
            name=name,
            description=description,
            department_id=department_id,
            archive_retention_days=archive_retention_days,
            is_active=is_active,
        )
        db.add(item)
        db.commit()
        return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)

    @app.post("/web/ticket-types/{ticket_type_id}/update")
    async def web_ticket_types_update(
        ticket_type_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        item = db.get(ticket_type_model, ticket_type_id)
        if not item or item.company_id != user.company_id:
            raise HTTPException(404, "Ticket type not found")

        form = await request.form()
        name = (form.get("name") or "").strip()
        description = (form.get("description") or "").strip() or None
        department_raw = (form.get("department_id") or "").strip()
        archive_retention_days = parse_archive_retention_days(form.get("archive_retention_days"))
        if (form.get("archive_retention_days") or "").strip() and archive_retention_days is None:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        is_active = (form.get("is_active") or "").strip() == "1"
        if not name:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        department_id = int(department_raw) if department_raw.isdigit() else None
        if department_raw and department_id is None:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        if department_id is not None:
            department = db.get(department_model, department_id)
            if not department or department.company_id != user.company_id:
                return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)

        exists = (
            db.query(ticket_type_model)
            .filter(
                ticket_type_model.company_id == user.company_id,
                ticket_type_model.name == name,
                ticket_type_model.id != item.id,
            )
            .first()
        )
        if exists:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)

        item.name = name
        item.description = description
        item.department_id = department_id
        item.archive_retention_days = archive_retention_days
        item.is_active = is_active
        db.commit()
        return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)

    @app.post("/web/ticket-types/{ticket_type_id}/delete")
    async def web_ticket_types_delete(
        ticket_type_id: int,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        item = db.get(ticket_type_model, ticket_type_id)
        if not item or item.company_id != user.company_id:
            raise HTTPException(404, "Ticket type not found")

        in_use = db.query(ticket_model.id).filter(ticket_model.ticket_type_id == item.id).first() is not None
        if in_use:
            return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
        db.delete(item)
        db.commit()
        return RedirectResponse(url="/web/ticket-types", status_code=http_303_see_other)
