from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_ticket_template_routes(
    app,
    *,
    get_db,
    get_current_user,
    is_manager,
    ensure_company_user,
    query_assignable_company_users,
    validate_template_links,
    resolve_ticket_department_id,
    parse_template_deadline_rule_from_form,
    create_tickets_from_template,
    normalize_period_key,
    month_period_key,
    quote,
    templates,
    ticket_template_model,
    ticket_type_model,
    department_model,
    org_unit_model,
    user_model,
    ticket_model,
    ticket_generation_key_model,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.get("/web/ticket-templates")
    def web_ticket_templates(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        items = (
            db.query(ticket_template_model)
            .filter(ticket_template_model.company_id == user.company_id)
            .order_by(ticket_template_model.id.desc())
            .all()
        )
        ticket_types = (
            db.query(
                ticket_type_model.id,
                ticket_type_model.name,
                ticket_type_model.is_active,
                ticket_type_model.department_id,
            )
            .filter(ticket_type_model.company_id == user.company_id)
            .order_by(ticket_type_model.name.asc())
            .all()
        )
        departments = (
            db.query(department_model.id, department_model.name, department_model.is_active)
            .filter(department_model.company_id == user.company_id)
            .order_by(department_model.name.asc(), department_model.id.asc())
            .all()
        )
        org_units = (
            db.query(org_unit_model.id, org_unit_model.name, org_unit_model.parent_id, org_unit_model.is_active)
            .filter(org_unit_model.company_id == user.company_id)
            .order_by(org_unit_model.id.asc())
            .all()
        )
        executors = (
            query_assignable_company_users(db, user.company_id)
            .order_by(user_model.name.asc(), user_model.id.asc())
            .all()
        )
        return templates.TemplateResponse(
            "ticket_templates.html",
            {
                "request": request,
                "user": user,
                "items": items,
                "ticket_types": ticket_types,
                "departments": departments,
                "org_units": org_units,
                "executors": executors,
            },
        )

    @app.post("/web/ticket-templates/create")
    async def web_ticket_templates_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        form = await request.form()
        name = (form.get("name") or "").strip()
        if not name:
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        try:
            ticket_type_id = int((form.get("ticket_type_id") or "").strip())
        except ValueError:
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        department_raw = (form.get("department_id") or "").strip()
        scope_raw = (form.get("scope_unit_id") or "").strip()
        executor_raw = (form.get("default_executor_id") or "").strip()
        if department_raw and not department_raw.isdigit():
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        department_id = int(department_raw) if department_raw.isdigit() else None
        scope_unit_id = int(scope_raw) if scope_raw.isdigit() else None
        default_executor_id = int(executor_raw) if executor_raw.isdigit() else None
        is_active = (form.get("is_active") or "1").strip() == "1"
        validate_template_links(db, user.company_id, ticket_type_id, department_id, default_executor_id, scope_unit_id)
        resolved_department_id = resolve_ticket_department_id(
            db,
            company_id=user.company_id,
            ticket_type_id=ticket_type_id,
            department_id=department_id,
        )
        exists = (
            db.query(ticket_template_model.id)
            .filter(ticket_template_model.company_id == user.company_id, ticket_template_model.name == name)
            .first()
        )
        if exists:
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        item = ticket_template_model(
            company_id=user.company_id,
            ticket_type_id=ticket_type_id,
            department_id=resolved_department_id,
            name=name,
            title_template=(form.get("title_template") or "").strip() or None,
            description_template=(form.get("description_template") or "").strip() or None,
            default_deadline_rule=parse_template_deadline_rule_from_form(form),
            default_executor_id=default_executor_id,
            scope_unit_id=scope_unit_id,
            is_active=is_active,
        )
        db.add(item)
        db.commit()
        return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)

    @app.post("/web/ticket-templates/{template_id}/update")
    async def web_ticket_templates_update(
        template_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        item = db.get(ticket_template_model, template_id)
        if not item or item.company_id != user.company_id:
            raise HTTPException(404, "Ticket template not found")
        form = await request.form()
        name = (form.get("name") or "").strip()
        if not name:
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        try:
            ticket_type_id = int((form.get("ticket_type_id") or "").strip())
        except ValueError:
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        department_raw = (form.get("department_id") or "").strip()
        scope_raw = (form.get("scope_unit_id") or "").strip()
        executor_raw = (form.get("default_executor_id") or "").strip()
        if department_raw and not department_raw.isdigit():
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        department_id = int(department_raw) if department_raw.isdigit() else None
        scope_unit_id = int(scope_raw) if scope_raw.isdigit() else None
        default_executor_id = int(executor_raw) if executor_raw.isdigit() else None
        is_active = (form.get("is_active") or "").strip() == "1"
        validate_template_links(db, user.company_id, ticket_type_id, department_id, default_executor_id, scope_unit_id)
        resolved_department_id = resolve_ticket_department_id(
            db,
            company_id=user.company_id,
            ticket_type_id=ticket_type_id,
            department_id=department_id,
        )
        exists = (
            db.query(ticket_template_model.id)
            .filter(
                ticket_template_model.company_id == user.company_id,
                ticket_template_model.name == name,
                ticket_template_model.id != item.id,
            )
            .first()
        )
        if exists:
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        item.ticket_type_id = ticket_type_id
        item.department_id = resolved_department_id
        item.name = name
        item.title_template = (form.get("title_template") or "").strip() or None
        item.description_template = (form.get("description_template") or "").strip() or None
        item.default_deadline_rule = parse_template_deadline_rule_from_form(form)
        item.default_executor_id = default_executor_id
        item.scope_unit_id = scope_unit_id
        item.is_active = is_active
        db.commit()
        return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)

    @app.post("/web/ticket-templates/{template_id}/delete")
    async def web_ticket_templates_delete(
        template_id: int,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        item = db.get(ticket_template_model, template_id)
        if not item or item.company_id != user.company_id:
            raise HTTPException(404, "Ticket template not found")
        try:
            db.query(ticket_model).filter(
                ticket_model.company_id == user.company_id,
                ticket_model.ticket_template_id == item.id,
            ).update({"ticket_template_id": None}, synchronize_session=False)
            db.query(ticket_generation_key_model).filter(
                ticket_generation_key_model.company_id == user.company_id,
                ticket_generation_key_model.ticket_template_id == item.id,
            ).delete(synchronize_session=False)
            db.delete(item)
            db.commit()
            return RedirectResponse(url="/web/ticket-templates", status_code=http_303_see_other)
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/ticket-templates?delete_error=1", status_code=http_303_see_other)

    @app.post("/web/ticket-templates/{template_id}/run")
    async def web_ticket_templates_run(
        template_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        item = db.get(ticket_template_model, template_id)
        if not item or item.company_id != user.company_id:
            raise HTTPException(404, "Ticket template not found")

        form = await request.form()
        raw_period_key = (form.get("period_key") or "").strip() or None
        period_key = normalize_period_key(raw_period_key)
        if raw_period_key and period_key is None:
            return RedirectResponse(url="/web/ticket-templates?run_error=bad_period", status_code=http_303_see_other)
        created_count, skipped_count, effective_period = create_tickets_from_template(
            db=db,
            template=item,
            actor_id=user.id,
            period_key=period_key,
        )
        db.commit()
        return RedirectResponse(
            url=(
                "/web/ticket-templates"
                f"?run_ok=1&run_created={created_count}&run_skipped={skipped_count}&run_period={quote(effective_period)}"
            ),
            status_code=http_303_see_other,
        )

    @app.post("/web/ticket-templates/{template_id}/clear-keys")
    async def web_ticket_templates_clear_keys(
        template_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        item = db.get(ticket_template_model, template_id)
        if not item or item.company_id != user.company_id:
            raise HTTPException(404, "Ticket template not found")

        form = await request.form()
        raw_period_key = (form.get("period_key") or "").strip()
        normalized_period_candidate = normalize_period_key(raw_period_key)
        if raw_period_key and normalized_period_candidate is None:
            return RedirectResponse(url="/web/ticket-templates?keys_error=bad_period", status_code=http_303_see_other)
        normalized_period = normalized_period_candidate or month_period_key()
        deleted_count = (
            db.query(ticket_generation_key_model)
            .filter(
                ticket_generation_key_model.company_id == user.company_id,
                ticket_generation_key_model.ticket_template_id == item.id,
                ticket_generation_key_model.period_key == normalized_period,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        return RedirectResponse(
            url=(
                "/web/ticket-templates"
                f"?keys_cleared=1&keys_period={quote(normalized_period)}&keys_deleted={int(deleted_count or 0)}"
            ),
            status_code=http_303_see_other,
        )
