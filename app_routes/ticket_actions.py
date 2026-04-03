from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse


def register_ticket_action_routes(
    app,
    *,
    get_db,
    get_current_user,
    is_manager,
    can_access_ticket,
    can_archive_ticket,
    can_delete_ticket,
    get_company_ticket_or_404,
    safe_next,
    archive_ticket,
    restore_ticket_from_archive,
    resolve_ticket_archive_retention_days,
    local_now,
    add_ticket_log,
    delete_ticket_with_related_data,
    notify_curators_status_changed,
    get_company_deadline_soon_warning_minutes,
    ticket_status_change_log_action,
    ticket_status_enum,
    final_ticket_statuses,
    company_model,
    http_303_see_other,
):
    @app.post("/web/tickets/{ticket_id}/delete")
    async def web_delete_ticket(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_delete_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")

        default_next = "/web/archive" if ticket.status == ticket_status_enum.archived else "/web"
        delete_ticket_with_related_data(db, ticket, remove_files=True)
        db.commit()

        form = await request.form()
        next_url = safe_next(form.get("next"), fallback=default_next)
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.post("/web/tickets/{ticket_id}/status")
    async def web_update_status(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")

        form = await request.form()
        status_raw = (form.get("status") or "").strip()
        if not status_raw:
            raise HTTPException(400, "Missing status")
        if status_raw == ticket_status_enum.archived.value:
            raise HTTPException(400, "Use archive action")
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket must be restored first")

        old_status = ticket.status
        ticket.status = ticket_status_enum(status_raw)
        if ticket.status != old_status:
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_status_change_log_action(old_status, ticket.status),
            )
        db.commit()
        notify_curators_status_changed(db, ticket, actor=user, old_status=old_status)
        db.commit()

        now = local_now()
        is_overdue = bool(ticket.deadline and ticket.deadline < now and ticket.status not in final_ticket_statuses)
        company = db.get(company_model, user.company_id) if user.company_id is not None else None
        deadline_soon_warning_minutes = get_company_deadline_soon_warning_minutes(company)
        is_deadline_soon = bool(
            ticket.deadline
            and not is_overdue
            and ticket.status not in final_ticket_statuses
            and ticket.deadline <= now + timedelta(minutes=deadline_soon_warning_minutes)
        )

        accept = (request.headers.get("accept") or "").lower()
        if "application/json" in accept:
            return JSONResponse(
                {
                    "ok": True,
                    "ticket_id": ticket.id,
                    "status": ticket.status.value,
                    "is_overdue": is_overdue,
                    "is_deadline_soon": is_deadline_soon,
                }
            )

        return RedirectResponse(url="/web", status_code=http_303_see_other)

    @app.post("/web/tickets/{ticket_id}/archive")
    async def web_archive_ticket(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_archive_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web")
        if ticket.status == ticket_status_enum.archived:
            return RedirectResponse(url=next_url, status_code=http_303_see_other)
        company = db.get(company_model, user.company_id) if user.company_id is not None else None
        old_status = ticket.status
        archive_ticket(db, ticket, actor_id=user.id, company=company)
        db.commit()
        notify_curators_status_changed(db, ticket, actor=user, old_status=old_status)
        db.commit()
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.post("/web/tickets/{ticket_id}/restore")
    async def web_restore_ticket(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web/archive")
        old_status = ticket.status
        restore_ticket_from_archive(db, ticket, actor_id=user.id)
        db.commit()
        notify_curators_status_changed(db, ticket, actor=user, old_status=old_status)
        db.commit()
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.post("/web/tickets/{ticket_id}/legal-hold")
    async def web_ticket_legal_hold(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if ticket.status != ticket_status_enum.archived:
            raise HTTPException(400, "Legal hold works only for archived tickets")
        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web/archive")
        hold_enabled = (form.get("is_legal_hold") or "").strip() == "1"
        ticket.is_legal_hold = hold_enabled
        if not hold_enabled:
            if ticket.retention_days is None:
                company = db.get(company_model, user.company_id) if user.company_id is not None else None
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
        db.commit()
        return RedirectResponse(url=next_url, status_code=http_303_see_other)
