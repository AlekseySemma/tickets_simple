from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_ticket_overview_routes(
    app,
    *,
    get_db,
    get_current_user,
    ensure_company_user,
    is_platform_admin,
    can_access_ticket,
    can_archive_ticket,
    can_delete_ticket,
    can_restore_ticket,
    can_manage_ticket_legal_hold,
    can_take_ticket_in_work,
    can_close_ticket,
    get_company_ticket_or_404,
    render_web_tickets_page,
    safe_next,
    append_query_params,
    archive_ticket,
    delete_ticket_with_related_data,
    restore_ticket_from_archive,
    resolve_ticket_archive_retention_days,
    local_now,
    add_ticket_log,
    ensure_default_ticket_watchers,
    notify_executor_reassigned,
    notify_curators_status_changed,
    ticket_field_change_log_action,
    ticket_status_change_log_action,
    ticket_user_name,
    bulk_action_labels,
    ticket_model,
    company_model,
    ticket_status_enum,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.get("/web")
    def web_tickets(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
        status_filter: str | None = None,
        project_id: str | None = None,
        ticket_type_id: str | None = None,
        department_id: str | None = None,
        executor_id: str | None = None,
        target_unit_id: str | None = None,
        unit_executor_id: str | None = None,
        q: str | None = None,
        only_overdue: str | None = None,
        sort: str | None = None,
        view_mode: str | None = None,
        open_create: str | None = None,
        create_error: str | None = None,
        page: int = 1,
        page_size: str | None = None,
    ):
        return render_web_tickets_page(
            request=request,
            db=db,
            user=user,
            status_filter=status_filter,
            project_id=project_id,
            ticket_type_id=ticket_type_id,
            department_id=department_id,
            executor_id=executor_id,
            target_unit_id=target_unit_id,
            unit_executor_id=unit_executor_id,
            q=q,
            only_overdue=only_overdue,
            sort=sort,
            view_mode=view_mode,
            open_create=open_create,
            create_error=create_error,
            page=page,
            page_size=page_size,
            archive_mode=False,
        )

    @app.get("/web/archive")
    def web_archive_tickets(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
        status_filter: str | None = None,
        project_id: str | None = None,
        ticket_type_id: str | None = None,
        department_id: str | None = None,
        executor_id: str | None = None,
        target_unit_id: str | None = None,
        unit_executor_id: str | None = None,
        q: str | None = None,
        only_overdue: str | None = None,
        sort: str | None = None,
        view_mode: str | None = None,
        page: int = 1,
        page_size: str | None = None,
    ):
        return render_web_tickets_page(
            request=request,
            db=db,
            user=user,
            status_filter=status_filter,
            project_id=project_id,
            ticket_type_id=ticket_type_id,
            department_id=department_id,
            executor_id=executor_id,
            target_unit_id=target_unit_id,
            unit_executor_id=unit_executor_id,
            q=q,
            only_overdue=only_overdue,
            sort=sort,
            view_mode=view_mode,
            open_create=None,
            create_error=None,
            page=page,
            page_size=page_size,
            archive_mode=True,
        )

    @app.post("/web/tickets/bulk-action")
    async def web_tickets_bulk_action(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if is_platform_admin(user):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)

        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web")
        action = (form.get("action") or "").strip().lower()
        if action not in bulk_action_labels:
            return RedirectResponse(
                url=append_query_params(next_url, bulk_error="bad_action"),
                status_code=http_303_see_other,
            )

        ticket_ids: list[int] = []
        for raw_ticket_id in form.getlist("ticket_ids"):
            try:
                ticket_id = int((raw_ticket_id or "").strip())
            except (TypeError, ValueError):
                continue
            if ticket_id > 0 and ticket_id not in ticket_ids:
                ticket_ids.append(ticket_id)
        if not ticket_ids:
            return RedirectResponse(
                url=append_query_params(next_url, bulk_error="no_selection"),
                status_code=http_303_see_other,
            )

        tickets = (
            db.query(ticket_model)
            .filter(ticket_model.company_id == user.company_id, ticket_model.id.in_(ticket_ids))
            .all()
        )
        tickets_by_id = {int(ticket.id): ticket for ticket in tickets}
        company = db.get(company_model, user.company_id) if user.company_id is not None else None
        status_notifications: list[tuple[object, object]] = []
        executor_notifications: list[tuple[object, object]] = []
        done_count = 0
        skipped_count = 0

        try:
            for ticket_id in ticket_ids:
                ticket = tickets_by_id.get(ticket_id)
                if ticket is None or not can_access_ticket(user, ticket):
                    skipped_count += 1
                    continue

                if action == "archive":
                    if not can_archive_ticket(user, ticket):
                        skipped_count += 1
                        continue
                    old_status = ticket.status
                    archive_ticket(db, ticket, actor_id=user.id, company=company)
                    status_notifications.append((ticket, old_status))
                    done_count += 1
                    continue

                if action == "delete":
                    if not can_delete_ticket(user, ticket):
                        skipped_count += 1
                        continue
                    delete_ticket_with_related_data(db, ticket, remove_files=True)
                    done_count += 1
                    continue

                if action == "restore":
                    if not can_restore_ticket(user, ticket):
                        skipped_count += 1
                        continue
                    old_status = ticket.status
                    restore_ticket_from_archive(db, ticket, actor_id=user.id)
                    status_notifications.append((ticket, old_status))
                    done_count += 1
                    continue

                if action == "take_in_work":
                    if not can_take_ticket_in_work(user, ticket):
                        skipped_count += 1
                        continue
                    old_status = ticket.status
                    old_executor_id = ticket.executor_id
                    changed = False
                    if ticket.executor_id != user.id:
                        ticket.executor_id = user.id
                        add_ticket_log(
                            db,
                            ticket_id=ticket.id,
                            actor_id=user.id,
                            action=ticket_field_change_log_action(
                                "исполнителя",
                                ticket_user_name(db, old_executor_id),
                                ticket_user_name(db, ticket.executor_id),
                            ),
                        )
                        changed = True
                    if ticket.status != ticket_status_enum.in_progress:
                        ticket.status = ticket_status_enum.in_progress
                        add_ticket_log(
                            db,
                            ticket_id=ticket.id,
                            actor_id=user.id,
                            action=ticket_status_change_log_action(old_status, ticket.status),
                        )
                        changed = True
                    if not changed:
                        skipped_count += 1
                        continue
                    ensure_default_ticket_watchers(db, ticket)
                    executor_notifications.append((ticket, old_executor_id))
                    if ticket.status != old_status:
                        status_notifications.append((ticket, old_status))
                    done_count += 1
                    continue

                if action == "complete":
                    if not can_close_ticket(user, ticket) or ticket.status != ticket_status_enum.in_progress:
                        skipped_count += 1
                        continue
                    old_status = ticket.status
                    ticket.status = ticket_status_enum.done
                    add_ticket_log(
                        db,
                        ticket_id=ticket.id,
                        actor_id=user.id,
                        action=ticket_status_change_log_action(old_status, ticket.status),
                    )
                    ensure_default_ticket_watchers(db, ticket)
                    status_notifications.append((ticket, old_status))
                    done_count += 1
                    continue

                if action in {"legal_hold_on", "legal_hold_off"}:
                    if not can_manage_ticket_legal_hold(user, ticket):
                        skipped_count += 1
                        continue
                    hold_enabled = action == "legal_hold_on"
                    if bool(ticket.is_legal_hold) == hold_enabled:
                        skipped_count += 1
                        continue
                    ticket.is_legal_hold = hold_enabled
                    if not hold_enabled:
                        if ticket.retention_days is None:
                            ticket.retention_days = resolve_ticket_archive_retention_days(db, ticket, company)
                        if ticket.archived_at is None:
                            ticket.archived_at = local_now()
                        ticket.delete_at = ticket.archived_at + timedelta(days=ticket.retention_days)
                    add_ticket_log(
                        db,
                        ticket_id=ticket.id,
                        actor_id=user.id,
                        action="установлен legal hold" if hold_enabled else "снят legal hold",
                    )
                    done_count += 1
                    continue

                skipped_count += 1

            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=append_query_params(next_url, bulk_error="save_failed"),
                status_code=http_303_see_other,
            )

        for ticket, old_executor_id in executor_notifications:
            notify_executor_reassigned(db, ticket, old_executor_id=old_executor_id, actor=user)
        for ticket, old_status in status_notifications:
            notify_curators_status_changed(db, ticket, actor=user, old_status=old_status)
        if executor_notifications or status_notifications:
            try:
                db.commit()
            except sqlalchemy_error:
                db.rollback()

        return RedirectResponse(
            url=append_query_params(
                next_url,
                bulk_ok=True,
                bulk_action=action,
                bulk_done=done_count,
                bulk_skipped=skipped_count,
            ),
            status_code=http_303_see_other,
        )

    @app.post("/web/tickets/{ticket_id}/quick-action")
    async def web_ticket_quick_action(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")

        form = await request.form()
        action = (form.get("action") or "").strip()
        default_next = "/web/archive" if ticket.status == ticket_status_enum.archived else "/web"
        next_url = safe_next(form.get("next"), fallback=default_next)

        old_status = ticket.status
        old_executor_id = ticket.executor_id
        changed = False

        if action == "take_in_work":
            if not can_take_ticket_in_work(user, ticket):
                raise HTTPException(403, "Forbidden")
            if ticket.executor_id != user.id:
                ticket.executor_id = user.id
                add_ticket_log(
                    db,
                    ticket_id=ticket.id,
                    actor_id=user.id,
                    action=ticket_field_change_log_action(
                        "исполнителя",
                        ticket_user_name(db, old_executor_id),
                        ticket_user_name(db, ticket.executor_id),
                    ),
                )
                changed = True
            if ticket.status != ticket_status_enum.in_progress:
                ticket.status = ticket_status_enum.in_progress
                add_ticket_log(
                    db,
                    ticket_id=ticket.id,
                    actor_id=user.id,
                    action=ticket_status_change_log_action(old_status, ticket.status),
                )
                changed = True
        elif action == "complete":
            if not can_close_ticket(user, ticket):
                raise HTTPException(403, "Forbidden")
            if ticket.status != ticket_status_enum.in_progress:
                return RedirectResponse(url=next_url, status_code=http_303_see_other)
            ticket.status = ticket_status_enum.done
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_status_change_log_action(old_status, ticket.status),
            )
            changed = True
        else:
            raise HTTPException(400, "Unknown quick action")

        if not changed:
            return RedirectResponse(url=next_url, status_code=http_303_see_other)

        ensure_default_ticket_watchers(db, ticket)
        db.commit()
        db.refresh(ticket)

        notify_executor_reassigned(db, ticket, old_executor_id=old_executor_id, actor=user)
        if ticket.status != old_status:
            notify_curators_status_changed(db, ticket, actor=user, old_status=old_status)
        db.commit()

        return RedirectResponse(url=next_url, status_code=http_303_see_other)
