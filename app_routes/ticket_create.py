import uuid

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_ticket_create_routes(
    app,
    *,
    get_db,
    get_current_user,
    ensure_company_user,
    can_create_company_ticket,
    normalize_ticket_title,
    is_ticket_title_too_long,
    parse_deadline_inputs,
    validate_ticket_links,
    resolve_ticket_department_id,
    resolve_target_unit_id_from_form_input,
    resolve_scope_leaf_units,
    get_or_create_project_for_org_unit,
    get_preferred_executor_for_unit,
    ensure_default_ticket_watchers,
    add_ticket_watcher,
    add_ticket_log,
    notify_executor_new_ticket,
    templates_logger,
    user_model,
    ticket_model,
    role_enum,
    ticket_status_enum,
    org_structure_v2_enabled,
    log_action_created,
    max_ticket_title_len,
    http_303_see_other,
    operational_error,
    sqlalchemy_error,
):
    @app.post("/web/tickets/create")
    async def web_create_ticket(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        def create_redirect(error_code: str | None = None) -> RedirectResponse:
            url = "/web?open_create=1"
            if error_code:
                url = f"{url}&create_error={error_code}"
            return RedirectResponse(url=url, status_code=http_303_see_other)

        def is_schema_outdated_db_error(exc: Exception) -> bool:
            message = str(exc).lower()
            schema_markers = (
                "no such table",
                "no such column",
                "has no column named",
                "undefined table",
                "undefined column",
            )
            return any(marker in message for marker in schema_markers)

        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)
        if not can_create_company_ticket(user):
            raise HTTPException(403, "Forbidden")

        form = await request.form()
        title = normalize_ticket_title(form.get("title"))
        description = (form.get("description") or "").strip() or None

        if is_ticket_title_too_long(title):
            return create_redirect("title_too_long")

        project_id_raw = (form.get("project_id") or "").strip()
        if not title:
            return create_redirect("missing_required")
        project_id: int | None = None
        if project_id_raw:
            try:
                project_id = int(project_id_raw)
            except ValueError:
                return create_redirect("bad_input")

        if user.role == role_enum.executor and not getattr(user, "can_view_all_tickets", False):
            executor_id = user.id
        else:
            executor_id_raw = (form.get("executor_id") or "").strip()
            try:
                executor_id = int(executor_id_raw) if executor_id_raw else None
            except ValueError:
                return create_redirect("bad_input")

        ticket_type_id_raw = (form.get("ticket_type_id") or "").strip()
        try:
            ticket_type_id = int(ticket_type_id_raw) if ticket_type_id_raw else None
        except ValueError:
            return create_redirect("bad_input")

        department_id_raw = (form.get("department_id") or "").strip()
        try:
            department_id = int(department_id_raw) if department_id_raw else None
        except ValueError:
            return create_redirect("bad_input")

        target_unit_id_raw = (form.get("target_unit_id") or "").strip()
        target_unit_label_raw = (form.get("target_unit_label") or "").strip()
        try:
            target_unit_id = int(target_unit_id_raw) if target_unit_id_raw else None
        except ValueError:
            return create_redirect("bad_input")

        org_v2_enabled = bool(org_structure_v2_enabled())

        if org_v2_enabled and target_unit_id is None and target_unit_label_raw:
            target_unit_id = resolve_target_unit_id_from_form_input(db, user.company_id, target_unit_label_raw)
        if org_v2_enabled and target_unit_id is None:
            return create_redirect("target_unit_required")
        if not org_v2_enabled and project_id is None:
            return create_redirect("missing_required")

        watcher_id_values = form.getlist("watcher_user_ids")
        selected_watcher_ids: list[int] = []
        seen_watcher_ids: set[int] = set()
        for raw_value in watcher_id_values:
            value = (raw_value or "").strip()
            if not value:
                continue
            try:
                watcher_id = int(value)
            except ValueError:
                return create_redirect("bad_input")
            if watcher_id in seen_watcher_ids:
                continue
            seen_watcher_ids.add(watcher_id)
            selected_watcher_ids.append(watcher_id)

        if selected_watcher_ids:
            valid_watcher_ids = {
                int(row[0])
                for row in (
                    db.query(user_model.id)
                    .filter(
                        user_model.company_id == user.company_id,
                        user_model.role.in_([role_enum.admin, role_enum.curator, role_enum.executor]),
                        user_model.role != role_enum.platform_admin,
                        user_model.id.in_(selected_watcher_ids),
                    )
                    .all()
                )
            }
            if len(valid_watcher_ids) != len(selected_watcher_ids):
                return create_redirect("bad_input")

        deadline = parse_deadline_inputs(form.get("deadline_date"), form.get("deadline_time4"))

        try:
            validate_ticket_links(
                db,
                user.company_id,
                project_id,
                executor_id,
                ticket_type_id,
                target_unit_id,
                None,
                department_id,
            )
            resolved_department_id = resolve_ticket_department_id(
                db,
                company_id=user.company_id,
                ticket_type_id=ticket_type_id,
                department_id=department_id,
            )
            created_tickets: list[object] = []
            if target_unit_id is not None:
                leaf_unit_ids = resolve_scope_leaf_units(db, user.company_id, target_unit_id)
                if not leaf_unit_ids:
                    return create_redirect("target_unit_required")
                batch_id = uuid.uuid4().hex
                for leaf_unit_id in leaf_unit_ids:
                    resolved_project_id = get_or_create_project_for_org_unit(db, user.company_id, leaf_unit_id)
                    resolved_executor_id = (
                        executor_id
                        if executor_id is not None
                        else get_preferred_executor_for_unit(
                            db,
                            user.company_id,
                            leaf_unit_id,
                            department_id=resolved_department_id,
                        )
                    )
                    ticket = ticket_model(
                        title=title,
                        description=description,
                        deadline=deadline,
                        company_id=user.company_id,
                        executor_id=resolved_executor_id,
                        ticket_type_id=ticket_type_id,
                        department_id=resolved_department_id,
                        target_unit_id=leaf_unit_id,
                        batch_id=batch_id,
                        project_id=resolved_project_id,
                        created_by=user.id,
                    )
                    db.add(ticket)
                    db.flush()
                    ensure_default_ticket_watchers(db, ticket)
                    for watcher_id in selected_watcher_ids:
                        add_ticket_watcher(db, ticket, watcher_user_id=watcher_id, added_by=user.id)
                    add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action=log_action_created)
                    created_tickets.append(ticket)
            else:
                ticket = ticket_model(
                    title=title,
                    description=description,
                    deadline=deadline,
                    company_id=user.company_id,
                    executor_id=executor_id,
                    ticket_type_id=ticket_type_id,
                    department_id=resolved_department_id,
                    project_id=project_id,
                    created_by=user.id,
                    status=ticket_status_enum.new,
                )
                db.add(ticket)
                db.flush()
                ensure_default_ticket_watchers(db, ticket)
                for watcher_id in selected_watcher_ids:
                    add_ticket_watcher(db, ticket, watcher_user_id=watcher_id, added_by=user.id)
                add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action=log_action_created)
                created_tickets.append(ticket)
            db.commit()
        except HTTPException as exc:
            db.rollback()
            detail = str(exc.detail or "").lower()
            if "target unit" in detail:
                return create_redirect("target_unit_required")
            if "title" in detail:
                return create_redirect("title_too_long")
            return create_redirect("bad_input")
        except operational_error as exc:
            db.rollback()
            templates_logger.exception(
                "Ticket create operational error: user_id=%s company_id=%s role=%s project_id=%s executor_id=%s ticket_type_id=%s target_unit_id=%s",
                user.id,
                user.company_id,
                user.role,
                project_id,
                executor_id,
                ticket_type_id,
                target_unit_id,
            )
            if is_schema_outdated_db_error(exc):
                return create_redirect("schema_outdated")
            return create_redirect("save_failed")
        except sqlalchemy_error:
            db.rollback()
            templates_logger.exception(
                "Ticket create SQLAlchemy error: user_id=%s company_id=%s role=%s project_id=%s executor_id=%s ticket_type_id=%s target_unit_id=%s",
                user.id,
                user.company_id,
                user.role,
                project_id,
                executor_id,
                ticket_type_id,
                target_unit_id,
            )
            return create_redirect("save_failed")

        for created_ticket in created_tickets:
            notify_executor_new_ticket(db, created_ticket, user)
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()

        return RedirectResponse(url="/web", status_code=http_303_see_other)
