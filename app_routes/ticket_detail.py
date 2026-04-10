from datetime import timedelta
from urllib.parse import quote

from fastapi import Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse


STATUS_LABELS = {
    "NEW": "\u041d\u043e\u0432\u0430\u044f",
    "IN_PROGRESS": "\u0412 \u0440\u0430\u0431\u043e\u0442\u0435",
    "DONE": "\u0412\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0430",
    "CANCELED": "\u041e\u0442\u043c\u0435\u043d\u0435\u043d\u0430",
    "ARCHIVED": "\u0412 \u0430\u0440\u0445\u0438\u0432\u0435",
}


def register_ticket_detail_routes(
    app,
    *,
    get_db,
    get_current_user,
    safe_next,
    get_company_ticket_or_404,
    can_access_ticket,
    add_ticket_watcher,
    ensure_default_ticket_watchers,
    normalize_optional_uploaded_files,
    create_comment_with_media_async,
    delete_stored_file,
    notify_comment_added,
    can_delete_comment,
    is_manager,
    normalize_uploaded_files,
    make_safe_upload_name,
    build_attachment_object_key,
    store_upload_file_to_storage_async,
    create_ticket_attachment_record,
    notify_curators_executor_act,
    add_ticket_log,
    can_edit_ticket,
    query_assignable_company_users,
    validate_ticket_links,
    resolve_ticket_department_id,
    parse_deadline_inputs,
    ticket_field_change_log_action,
    ticket_status_change_log_action,
    ticket_deadline_text,
    ticket_user_name,
    ticket_project_name,
    ticket_type_name,
    department_name,
    notify_executor_reassigned,
    notify_curators_status_changed,
    can_close_ticket,
    can_archive_ticket,
    local_now,
    get_company_deadline_soon_warning_minutes,
    normalize_ticket_title,
    is_ticket_title_too_long,
    templates,
    comment_model,
    comment_media_model,
    attachment_model,
    ticket_log_model,
    project_model,
    ticket_type_model,
    department_model,
    user_model,
    ticket_watcher_model,
    company_model,
    role_enum,
    ticket_status_enum,
    final_ticket_statuses,
    log_action_changed,
    log_action_file_deleted,
    max_ticket_title_len,
    org_structure_v2_enabled,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.post("/web/tickets/{ticket_id}/watchers/self")
    async def web_add_self_watcher(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        form = await request.form()
        next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")
        add_ticket_watcher(db, ticket, watcher_user_id=user.id, added_by=user.id)
        ensure_default_ticket_watchers(db, ticket)
        db.commit()
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.post("/web/tickets/{ticket_id}/comments")
    async def web_add_comment(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        form = await request.form()
        text = (form.get("text") or "").strip()
        photo_uploads = normalize_optional_uploaded_files(list(form.getlist("photos")))
        voice_uploads = normalize_optional_uploaded_files(list(form.getlist("voice_messages")))
        attachment_uploads = normalize_optional_uploaded_files(list(form.getlist("attachments")))
        next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}?tab=overview")

        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket is read-only")

        stored_paths: list[str] = []
        try:
            comment, media_items, stored_paths = await create_comment_with_media_async(
                db=db,
                ticket_id=ticket_id,
                author_id=user.id,
                text=text,
                photos=photo_uploads,
                voice_messages=voice_uploads,
                attachments=attachment_uploads,
            )
            db.commit()
            db.refresh(comment)
            for item in media_items:
                db.refresh(item)
        except HTTPException as exc:
            db.rollback()
            for stored_path in stored_paths:
                delete_stored_file(stored_path)
            error_code = "too_large" if exc.status_code == 413 else "invalid"
            return RedirectResponse(
                url=f"/web/tickets/{ticket_id}?tab=overview&comment_error={error_code}",
                status_code=http_303_see_other,
            )
        except sqlalchemy_error:
            db.rollback()
            for stored_path in stored_paths:
                delete_stored_file(stored_path)
            return RedirectResponse(
                url=f"/web/tickets/{ticket_id}?tab=overview&comment_error=save_failed",
                status_code=http_303_see_other,
            )

        try:
            notify_comment_added(
                db,
                ticket=ticket,
                author=user,
                comment_text=text,
                photo_count=sum(1 for item in media_items if item.media_kind == "photo"),
                voice_count=sum(1 for item in media_items if item.media_kind == "voice"),
                file_count=sum(1 for item in media_items if item.media_kind == "file"),
            )
            db.commit()
        except sqlalchemy_error:
            db.rollback()
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.post("/web/comments/{comment_id}/delete")
    async def web_delete_comment(
        comment_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        comment = db.get(comment_model, comment_id)
        if not comment:
            raise HTTPException(404, "Comment not found")
        ticket = get_company_ticket_or_404(db, user, comment.ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket is read-only")
        if not can_delete_comment(user, comment):
            raise HTTPException(403, "Forbidden")

        form = await request.form()
        next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket.id}?tab=overview")
        media_items = db.query(comment_media_model).filter(comment_media_model.comment_id == comment.id).all()
        for item in media_items:
            delete_stored_file(item.file_path)
        db.query(comment_media_model).filter(comment_media_model.comment_id == comment.id).delete(
            synchronize_session=False
        )
        db.delete(comment)
        db.commit()
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.post("/web/tickets/{ticket_id}/attachments")
    async def web_add_attachment(
        ticket_id: int,
        request: Request,
        files: list[UploadFile] = File(...),
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket is read-only")

        saved_attachments: list[object] = []
        for upload in normalize_uploaded_files(files):
            safe_name = make_safe_upload_name(upload.filename, ticket_id=ticket_id)
            object_key = build_attachment_object_key(safe_name)
            stored_path, file_hash, file_size = await store_upload_file_to_storage_async(upload, object_key)
            attachment = create_ticket_attachment_record(
                db=db,
                ticket_id=ticket_id,
                uploader_id=user.id,
                upload=upload,
                stored_path=stored_path,
                file_hash=file_hash,
                file_size=file_size,
            )
            saved_attachments.append(attachment)

        db.commit()
        for attachment in saved_attachments:
            notify_curators_executor_act(
                db,
                ticket=ticket,
                uploader=user,
                original_name=attachment.original_name,
            )
        db.commit()

        form = await request.form()
        next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.post("/web/attachments/{attachment_id}/delete")
    async def web_delete_attachment(
        attachment_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        attachment = db.get(attachment_model, attachment_id)
        if not attachment:
            raise HTTPException(404, "Attachment not found")
        ticket = get_company_ticket_or_404(db, user, attachment.ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket is read-only")

        can_delete_file = bool(
            is_manager(user) or (user.role == role_enum.executor and attachment.uploader_id == user.id)
        )
        if not can_delete_file:
            raise HTTPException(403, "Forbidden")

        delete_stored_file(attachment.file_path)
        db.delete(attachment)
        add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action=log_action_file_deleted)
        db.commit()

        form = await request.form()
        next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket.id}")
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.get("/web/tickets/{ticket_id}/edit")
    def web_edit_ticket_page(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if ticket.status == ticket_status_enum.archived:
            return RedirectResponse(url=f"/web/tickets/{ticket_id}", status_code=http_303_see_other)
        if not can_edit_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")

        projects = (
            db.query(project_model.id, project_model.name)
            .filter(project_model.company_id == user.company_id)
            .order_by(project_model.id.desc())
            .all()
        )
        executors = query_assignable_company_users(db, user.company_id).order_by(user_model.id.desc()).all()
        ticket_types = (
            db.query(
                ticket_type_model.id,
                ticket_type_model.name,
                ticket_type_model.is_active,
                ticket_type_model.department_id,
            )
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
        next_url = safe_next(request.query_params.get("next"), fallback=f"/web/tickets/{ticket_id}")
        error_code = (request.query_params.get("error") or "").strip().lower()
        error_message = None
        if error_code == "title_too_long":
            error_message = (
                f"\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435 \u0441\u043b\u0438\u0448\u043a\u043e\u043c "
                f"\u0434\u043b\u0438\u043d\u043d\u043e\u0435. \u041c\u0430\u043a\u0441\u0438\u043c\u0443\u043c: "
                f"{max_ticket_title_len} \u0441\u0438\u043c\u0432\u043e\u043b\u043e\u0432."
            )

        deadline_date = None
        deadline_time4 = None
        if ticket.deadline:
            deadline_date = ticket.deadline.strftime("%Y-%m-%d")
            deadline_time4 = ticket.deadline.strftime("%H%M")

        return templates.TemplateResponse(
            request,
            "ticket_edit.html",
            {
                "request": request,
                "user": user,
                "t": ticket,
                "projects": projects,
                "executors": executors,
                "ticket_types": ticket_types,
                "departments": departments,
                "can_edit_full": can_edit_ticket(user, ticket),
                "deadline_date": deadline_date,
                "deadline_time4": deadline_time4,
                "error": error_message,
                "max_ticket_title_len": max_ticket_title_len,
                "next_url": next_url,
                "org_v2_enabled": org_structure_v2_enabled,
            },
        )

    @app.post("/web/tickets/{ticket_id}/edit")
    async def web_ticket_edit_save(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_edit_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket is read-only")

        can_edit_full = is_manager(user)
        can_change_status = can_close_ticket(user, ticket)
        form = await request.form()
        status_raw = (form.get("status") or "").strip()
        if status_raw == ticket_status_enum.archived.value:
            raise HTTPException(400, "Use archive action")
        next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")

        title = normalize_ticket_title(form.get("title"))
        description = (form.get("description") or "").strip()
        project_id_raw = (form.get("project_id") or "").strip()
        executor_id_raw = (form.get("executor_id") or "").strip()
        ticket_type_id_raw = (form.get("ticket_type_id") or "").strip()
        department_id_raw = (form.get("department_id") or "").strip()

        if is_ticket_title_too_long(title):
            edit_url = f"/web/tickets/{ticket_id}/edit?error=title_too_long&next={quote(next_url, safe='')}"
            return RedirectResponse(url=edit_url, status_code=http_303_see_other)

        old_deadline = ticket.deadline
        old_executor_id = ticket.executor_id
        old_project_id = ticket.project_id
        old_ticket_type_id = ticket.ticket_type_id
        old_department_id = ticket.department_id
        old_status = ticket.status

        if status_raw and can_change_status:
            try:
                ticket.status = ticket_status_enum(status_raw)
            except ValueError:
                pass

        if title:
            ticket.title = title
        ticket.description = description

        if can_edit_full:
            try:
                project_id_candidate = int(project_id_raw)
            except ValueError:
                project_id_candidate = None
            try:
                executor_id_candidate = int(executor_id_raw) if executor_id_raw else None
            except ValueError:
                executor_id_candidate = None
            try:
                ticket_type_id_candidate = int(ticket_type_id_raw) if ticket_type_id_raw else None
            except ValueError:
                ticket_type_id_candidate = None
            try:
                department_id_candidate = int(department_id_raw) if department_id_raw else None
            except ValueError:
                department_id_candidate = None

            validate_ticket_links(
                db,
                user.company_id,
                project_id_candidate,
                executor_id_candidate,
                ticket_type_id_candidate,
                None,
                None,
                department_id_candidate,
            )
            resolved_department_id = resolve_ticket_department_id(
                db,
                company_id=user.company_id,
                ticket_type_id=ticket_type_id_candidate,
                department_id=department_id_candidate,
            )

            if project_id_candidate is not None:
                ticket.project_id = project_id_candidate
            ticket.executor_id = executor_id_candidate
            ticket.ticket_type_id = ticket_type_id_candidate
            ticket.department_id = resolved_department_id

        ticket.deadline = parse_deadline_inputs(form.get("deadline_date"), form.get("deadline_time4"))

        has_specific_log = False
        if ticket.deadline != old_deadline:
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_field_change_log_action(
                    "\u0441\u0440\u043e\u043a\u0430",
                    ticket_deadline_text(old_deadline),
                    ticket_deadline_text(ticket.deadline),
                ),
            )
            has_specific_log = True
        if ticket.executor_id != old_executor_id:
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_field_change_log_action(
                    "\u0438\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044f",
                    ticket_user_name(db, old_executor_id),
                    ticket_user_name(db, ticket.executor_id),
                ),
            )
            has_specific_log = True
        if ticket.project_id != old_project_id:
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_field_change_log_action(
                    "\u043f\u0440\u043e\u0435\u043a\u0442\u0430",
                    ticket_project_name(db, old_project_id),
                    ticket_project_name(db, ticket.project_id),
                ),
            )
            has_specific_log = True
        if ticket.ticket_type_id != old_ticket_type_id:
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_field_change_log_action(
                    "\u0442\u0438\u043f\u0430 \u0437\u0430\u044f\u0432\u043a\u0438",
                    ticket_type_name(db, old_ticket_type_id),
                    ticket_type_name(db, ticket.ticket_type_id),
                ),
            )
            has_specific_log = True
        if ticket.department_id != old_department_id:
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_field_change_log_action(
                    "\u043e\u0442\u0434\u0435\u043b\u0430",
                    department_name(db, old_department_id),
                    department_name(db, ticket.department_id),
                ),
            )
            has_specific_log = True
        if ticket.status != old_status:
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_status_change_log_action(old_status, ticket.status),
            )
            has_specific_log = True

        if not has_specific_log:
            add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action=log_action_changed)

        ensure_default_ticket_watchers(db, ticket)
        db.commit()
        db.refresh(ticket)
        notify_executor_reassigned(db, ticket, old_executor_id=old_executor_id, actor=user)
        notify_curators_status_changed(db, ticket, actor=user, old_status=old_status)
        db.commit()

        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.get("/web/tickets/{ticket_id}")
    def web_ticket_detail(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_company_ticket_or_404(db, user, ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if ensure_default_ticket_watchers(db, ticket):
            db.commit()

        watcher_rows = (
            db.query(ticket_watcher_model.user_id)
            .filter(ticket_watcher_model.ticket_id == ticket.id)
            .order_by(ticket_watcher_model.created_at.asc(), ticket_watcher_model.id.asc())
            .all()
        )
        watcher_user_ids = [int(row[0]) for row in watcher_rows]
        is_current_user_watcher = user.id in set(watcher_user_ids)
        default_next = "/web/archive" if ticket.status == ticket_status_enum.archived else "/web"
        next_url = safe_next(request.query_params.get("next"), fallback=default_next)
        next_url_encoded = quote(next_url, safe="")
        can_restore = is_manager(user) and ticket.status == ticket_status_enum.archived

        comments = (
            db.query(comment_model)
            .filter(comment_model.ticket_id == ticket.id)
            .order_by(comment_model.id.asc())
            .all()
        )
        comment_media_by_comment: dict[int, list[object]] = {}
        if comments:
            comment_ids = [comment.id for comment in comments]
            comment_media_items = (
                db.query(comment_media_model)
                .filter(comment_media_model.comment_id.in_(comment_ids))
                .order_by(comment_media_model.id.asc())
                .all()
            )
            for item in comment_media_items:
                comment_media_by_comment.setdefault(item.comment_id, []).append(item)

        attachments = (
            db.query(attachment_model)
            .filter(attachment_model.ticket_id == ticket.id)
            .order_by(attachment_model.id.asc())
            .all()
        )
        ticket_logs = (
            db.query(ticket_log_model)
            .filter(ticket_log_model.ticket_id == ticket.id)
            .order_by(ticket_log_model.id.desc())
            .all()
        )

        project_row = (
            db.query(project_model.id, project_model.name)
            .filter(project_model.company_id == user.company_id, project_model.id == ticket.project_id)
            .first()
        )
        projects_by_id = {project_row[0]: project_row[1]} if project_row else {}

        ticket_type_row = None
        if ticket.ticket_type_id is not None:
            ticket_type_row = (
                db.query(ticket_type_model.id, ticket_type_model.name)
                .filter(
                    ticket_type_model.company_id == user.company_id,
                    ticket_type_model.id == ticket.ticket_type_id,
                )
                .first()
            )
        ticket_types_by_id = {ticket_type_row[0]: ticket_type_row[1]} if ticket_type_row else {}

        departments_by_id: dict[int, str] = {}
        if ticket.department_id is not None:
            department_row = (
                db.query(department_model.id, department_model.name)
                .filter(department_model.company_id == user.company_id, department_model.id == ticket.department_id)
                .first()
            )
            if department_row:
                departments_by_id = {department_row[0]: department_row[1]}

        relevant_user_ids: set[int] = {ticket.created_by}
        if ticket.executor_id is not None:
            relevant_user_ids.add(ticket.executor_id)
        relevant_user_ids.update(watcher_user_ids)
        relevant_user_ids.update(comment.author_id for comment in comments if comment.author_id is not None)
        relevant_user_ids.update(attachment.uploader_id for attachment in attachments if attachment.uploader_id is not None)
        relevant_user_ids.update(log.actor_id for log in ticket_logs if log.actor_id is not None)

        users_by_id: dict[int, str] = {}
        if relevant_user_ids:
            users = (
                db.query(user_model.id, user_model.name)
                .filter(user_model.company_id == user.company_id, user_model.id.in_(relevant_user_ids))
                .all()
            )
            users_by_id = {user_id: user_name for user_id, user_name in users}

        company = db.get(company_model, user.company_id) if user.company_id is not None else None
        deadline_soon_warning_minutes = get_company_deadline_soon_warning_minutes(company)
        now = local_now()
        is_overdue = bool(
            ticket.deadline and ticket.deadline < now and ticket.status not in final_ticket_statuses
        )
        is_deadline_soon = bool(
            ticket.deadline
            and not is_overdue
            and ticket.status not in final_ticket_statuses
            and ticket.deadline <= now + timedelta(minutes=deadline_soon_warning_minutes)
        )

        return templates.TemplateResponse(
            request,
            "ticket_detail.html",
            {
                "request": request,
                "user": user,
                "t": ticket,
                "projects_by_id": projects_by_id,
                "ticket_types_by_id": ticket_types_by_id,
                "departments_by_id": departments_by_id,
                "users_by_id": users_by_id,
                "comments": comments,
                "comment_media_by_comment": comment_media_by_comment,
                "attachments": attachments,
                "ticket_logs": ticket_logs,
                "now": now,
                "is_overdue": is_overdue,
                "is_deadline_soon": is_deadline_soon,
                "status_labels": STATUS_LABELS,
                "next_url": next_url,
                "next_url_encoded": next_url_encoded,
                "can_archive": can_archive_ticket(user, ticket),
                "can_restore": can_restore,
                "can_close_ticket": can_close_ticket(user, ticket),
                "watcher_user_ids": watcher_user_ids,
                "is_current_user_watcher": is_current_user_watcher,
            },
        )
