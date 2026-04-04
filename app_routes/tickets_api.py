from fastapi import Depends, File, HTTPException, Request, UploadFile


def register_tickets_api_routes(
    app,
    *,
    get_db,
    get_current_user,
    is_platform_admin,
    ensure_company_user,
    can_create_company_ticket,
    can_access_ticket,
    can_close_ticket,
    normalize_ticket_title,
    is_ticket_title_too_long,
    validate_ticket_links,
    resolve_ticket_department_id,
    ensure_default_ticket_watchers,
    add_ticket_log,
    notify_executor_new_ticket,
    get_api_ticket_or_404,
    ticket_field_change_log_action,
    ticket_status_change_log_action,
    ticket_deadline_text,
    ticket_user_name,
    ticket_project_name,
    ticket_type_name,
    department_name,
    notify_executor_reassigned,
    notify_curators_status_changed,
    normalize_optional_uploaded_files,
    create_comment_with_media_async,
    delete_stored_file,
    notify_comment_added,
    serialize_comment_out,
    normalize_uploaded_files,
    make_safe_upload_name,
    build_attachment_object_key,
    store_upload_file_to_storage,
    create_ticket_attachment_record,
    notify_curators_executor_act,
    get_storage_basename,
    serve_stored_file_response,
    ticket_model,
    comment_model,
    comment_media_model,
    attachment_model,
    role_enum,
    ticket_status_enum,
    ticket_create_model,
    ticket_update_model,
    ticket_out_model,
    comment_out_model,
    attachment_out_model,
    log_action_created,
    log_action_changed,
    log_action_target_unit_changed,
    log_action_template_changed,
    log_action_template_period_changed,
    max_ticket_title_len,
    sqlalchemy_error,
):
    @app.post("/tickets", response_model=ticket_out_model)
    def create_ticket(
        payload: ticket_create_model,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if is_platform_admin(user):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)
        if not can_create_company_ticket(user):
            raise HTTPException(403, "Forbidden")
        title = normalize_ticket_title(payload.title)
        if not title:
            raise HTTPException(422, "Title is required")
        if is_ticket_title_too_long(title):
            raise HTTPException(422, f"Title is too long (max {max_ticket_title_len})")

        validate_ticket_links(
            db,
            user.company_id,
            payload.project_id,
            payload.executor_id,
            payload.ticket_type_id,
            payload.target_unit_id,
            payload.ticket_template_id,
            payload.department_id,
        )
        resolved_department_id = resolve_ticket_department_id(
            db,
            company_id=user.company_id,
            ticket_type_id=payload.ticket_type_id,
            department_id=payload.department_id,
        )
        item = ticket_model(
            title=title,
            description=payload.description,
            deadline=payload.deadline,
            company_id=user.company_id,
            executor_id=payload.executor_id,
            ticket_type_id=payload.ticket_type_id,
            department_id=resolved_department_id,
            target_unit_id=payload.target_unit_id,
            ticket_template_id=payload.ticket_template_id,
            period_key=(payload.period_key or "").strip() or None,
            project_id=payload.project_id,
            created_by=user.id,
        )
        try:
            db.add(item)
            db.flush()
            ensure_default_ticket_watchers(db, item)
            add_ticket_log(db, ticket_id=item.id, actor_id=user.id, action=log_action_created)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            raise HTTPException(400, "РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ Р·Р°СЏРІРєСѓ")
        db.refresh(item)
        notify_executor_new_ticket(db, item, user)
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
        return item

    @app.get("/tickets", response_model=list[ticket_out_model])
    def list_tickets(
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        query = db.query(ticket_model).order_by(ticket_model.id.desc())
        if not is_platform_admin(user):
            ensure_company_user(user)
            query = query.filter(ticket_model.company_id == user.company_id)
        if user.role == role_enum.executor and not getattr(user, "can_view_all_tickets", False):
            query = query.filter((ticket_model.executor_id == user.id) | (ticket_model.created_by == user.id))
        return query.all()

    @app.patch("/tickets/{ticket_id}", response_model=ticket_out_model)
    def update_ticket(
        ticket_id: int,
        patch: ticket_update_model,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_api_ticket_or_404(db, user, ticket_id)
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket is read-only")

        incoming = patch.model_dump(exclude_unset=True)
        if incoming.get("status") == ticket_status_enum.archived:
            raise HTTPException(400, "Use archive endpoint")

        if user.role == role_enum.executor:
            if not can_access_ticket(user, ticket):
                raise HTTPException(403, "Forbidden")
            allowed = {"description"}
            if can_close_ticket(user, ticket):
                allowed.add("status")
            incoming = {k: v for k, v in incoming.items() if k in allowed}

        if "title" in incoming:
            incoming["title"] = normalize_ticket_title(incoming.get("title"))
            if incoming["title"] and is_ticket_title_too_long(incoming["title"]):
                raise HTTPException(422, f"Title is too long (max {max_ticket_title_len})")

        validate_ticket_links(
            db,
            ticket.company_id,
            incoming.get("project_id"),
            incoming.get("executor_id"),
            incoming.get("ticket_type_id"),
            incoming.get("target_unit_id"),
            incoming.get("ticket_template_id"),
            incoming.get("department_id"),
        )

        old_deadline = ticket.deadline
        old_executor_id = ticket.executor_id
        old_project_id = ticket.project_id
        old_ticket_type_id = ticket.ticket_type_id
        old_department_id = ticket.department_id
        old_target_unit_id = ticket.target_unit_id
        old_template_id = ticket.ticket_template_id
        old_period_key = ticket.period_key
        old_status = ticket.status

        for key, value in incoming.items():
            setattr(ticket, key, value)
        if "ticket_type_id" in incoming or "department_id" in incoming:
            ticket.department_id = resolve_ticket_department_id(
                db,
                company_id=ticket.company_id,
                ticket_type_id=ticket.ticket_type_id,
                department_id=ticket.department_id,
            )

        has_specific_log = False
        if ticket.deadline != old_deadline:
            add_ticket_log(
                db,
                ticket_id=ticket.id,
                actor_id=user.id,
                action=ticket_field_change_log_action(
                    "срока",
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
                    "исполнителя",
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
                    "проекта",
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
                    "типа заявки",
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
                    "отдела",
                    department_name(db, old_department_id),
                    department_name(db, ticket.department_id),
                ),
            )
            has_specific_log = True
        if ticket.target_unit_id != old_target_unit_id:
            add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action=log_action_target_unit_changed)
            has_specific_log = True
        if ticket.ticket_template_id != old_template_id:
            add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action=log_action_template_changed)
            has_specific_log = True
        if ticket.period_key != old_period_key:
            add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action=log_action_template_period_changed)
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
        return ticket

    @app.post("/tickets/{ticket_id}/comments", response_model=comment_out_model)
    async def add_comment(
        ticket_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_api_ticket_or_404(db, user, ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if not can_close_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket is read-only")

        content_type = (request.headers.get("content-type") or "").lower()
        text_value = ""
        photo_uploads: list[UploadFile] = []
        voice_uploads: list[UploadFile] = []
        attachment_uploads: list[UploadFile] = []
        if "application/json" in content_type:
            try:
                payload = await request.json()
            except Exception as exc:
                raise HTTPException(400, "Invalid JSON payload") from exc
            if not isinstance(payload, dict):
                raise HTTPException(400, "Invalid JSON payload")
            text_value = (payload.get("text") or "").strip()
        else:
            form = await request.form()
            text_value = (form.get("text") or "").strip()
            photo_uploads = normalize_optional_uploaded_files(list(form.getlist("photos")))
            voice_uploads = normalize_optional_uploaded_files(list(form.getlist("voice_messages")))
            attachment_uploads = normalize_optional_uploaded_files(list(form.getlist("attachments")))

        comment, media_items, stored_paths = await create_comment_with_media_async(
            db=db,
            ticket_id=ticket_id,
            author_id=user.id,
            text=text_value,
            photos=photo_uploads,
            voice_messages=voice_uploads,
            attachments=attachment_uploads,
        )
        try:
            db.commit()
            db.refresh(comment)
            for media_item in media_items:
                db.refresh(media_item)
        except Exception:
            db.rollback()
            for stored_path in stored_paths:
                delete_stored_file(stored_path)
            raise
        try:
            notify_comment_added(
                db,
                ticket=ticket,
                author=user,
                comment_text=text_value,
                photo_count=sum(1 for media_item in media_items if media_item.media_kind == "photo"),
                voice_count=sum(1 for media_item in media_items if media_item.media_kind == "voice"),
                file_count=sum(1 for media_item in media_items if media_item.media_kind == "file"),
            )
            db.commit()
        except sqlalchemy_error:
            db.rollback()
        return serialize_comment_out(comment, media_items)

    @app.post("/tickets/{ticket_id}/attachments", response_model=list[attachment_out_model])
    def upload_attachment(
        ticket_id: int,
        files: list[UploadFile] = File(...),
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ticket = get_api_ticket_or_404(db, user, ticket_id)
        if not can_access_ticket(user, ticket):
            raise HTTPException(403, "Forbidden")
        if ticket.status == ticket_status_enum.archived:
            raise HTTPException(400, "Archived ticket is read-only")

        saved_attachments = []
        for upload in normalize_uploaded_files(files):
            safe_name = make_safe_upload_name(upload.filename, ticket_id=ticket_id)
            object_key = build_attachment_object_key(safe_name)
            stored_path, file_hash, file_size = store_upload_file_to_storage(upload, object_key)
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
            db.refresh(attachment)
        for attachment in saved_attachments:
            notify_curators_executor_act(db, ticket=ticket, uploader=user, original_name=attachment.original_name)
        db.commit()
        return saved_attachments

    @app.get("/attachments/{attachment_id}")
    def download_attachment(
        attachment_id: int,
        download: int | None = None,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        attachment = db.get(attachment_model, attachment_id)
        if not attachment:
            raise HTTPException(404, "Attachment not found")
        _ = get_api_ticket_or_404(db, user, attachment.ticket_id)
        display_name = ((attachment.original_name or "").strip() or get_storage_basename(attachment.file_path) or "file")[
            :255
        ]
        disposition = "attachment" if str(download or "").strip() == "1" else "inline"
        return serve_stored_file_response(
            attachment.file_path,
            display_name,
            disposition,
            "Attachment file not found",
        )

    @app.get("/comment-media/{media_id}")
    def download_comment_media(
        media_id: int,
        download: int | None = None,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        item = db.get(comment_media_model, media_id)
        if not item:
            raise HTTPException(404, "Comment media not found")
        comment = db.get(comment_model, item.comment_id)
        if not comment:
            raise HTTPException(404, "Comment not found")
        _ = get_api_ticket_or_404(db, user, comment.ticket_id)
        display_name = ((item.original_name or "").strip() or get_storage_basename(item.file_path) or "file")[:255]
        disposition = "attachment" if str(download or "").strip() == "1" else "inline"
        return serve_stored_file_response(
            item.file_path,
            display_name,
            disposition,
            "Comment media file not found",
        )
