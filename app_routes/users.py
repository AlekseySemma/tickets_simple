import secrets
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_user_management_routes(
    app,
    *,
    get_db,
    get_current_user,
    is_manager,
    ensure_company_user,
    manageable_roles_for_web_user_management,
    can_manage_company_user,
    manageable_template_access_levels_for_actor,
    ensure_default_role_templates,
    get_manageable_role_template,
    role_template_payload,
    normalize_role_template_name,
    normalize_role_label,
    parse_optional_int,
    parse_bool_text,
    normalize_capability_flags,
    hash_password,
    prepare_user_email_verification,
    send_user_verification_email,
    bump_user_auth_token_version,
    access_level_label_ru,
    templates,
    logger,
    func,
    or_,
    user_model,
    role_template_model,
    registration_invite_model,
    ticket_model,
    comment_model,
    attachment_model,
    ticket_log_model,
    ticket_template_model,
    unit_assignment_model,
    ticket_watcher_model,
    push_subscription_model,
    mobile_device_model,
    deadline_reminder_log_model,
    notification_model,
    role_enum,
    email_delivery_error,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.get("/web/executors")
    def web_executors():
        return RedirectResponse(url="/web/users", status_code=http_303_see_other)

    @app.get("/web/users")
    def web_users(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
        ok: str | None = None,
        err: str | None = None,
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        allowed_roles = manageable_roles_for_web_user_management(user)
        if not allowed_roles:
            raise HTTPException(403, "Forbidden")
        template_access_levels = manageable_template_access_levels_for_actor(user)
        ensure_default_role_templates(db, user.company_id, template_access_levels)

        users = (
            db.query(
                user_model.id,
                user_model.name,
                user_model.email,
                user_model.role,
                user_model.role_label,
                user_model.is_assignable_executor,
                user_model.show_receipts_accounting_mode,
                user_model.can_view_all_tickets,
                user_model.can_create_tickets,
                user_model.can_close_tickets,
            )
            .filter(
                user_model.company_id == user.company_id,
                user_model.role != role_enum.platform_admin,
            )
            .order_by(user_model.id.desc())
            .all()
        )
        visible_users = [item for item in users if item.id == user.id or item.role in allowed_roles]
        role_templates = (
            db.query(role_template_model)
            .filter(
                role_template_model.company_id == user.company_id,
                role_template_model.access_level.in_(template_access_levels),
            )
            .order_by(
                role_template_model.access_level.asc(),
                role_template_model.name.asc(),
                role_template_model.id.asc(),
            )
            .all()
        )
        invites = (
            db.query(
                registration_invite_model.id,
                registration_invite_model.role,
                registration_invite_model.token,
                registration_invite_model.created_at,
                registration_invite_model.expires_at,
                registration_invite_model.used_by,
            )
            .filter(
                registration_invite_model.company_id == user.company_id,
                registration_invite_model.role.in_(allowed_roles),
            )
            .order_by(registration_invite_model.id.desc())
            .limit(30)
            .all()
        )
        base_url = str(request.base_url).rstrip("/")
        invite_links = [
            {
                "id": inv.id,
                "role": inv.role.value,
                "url": f"{base_url}/web/register?token={inv.token}",
                "created_at": inv.created_at,
                "expires_at": inv.expires_at,
                "is_used": inv.used_by is not None,
            }
            for inv in invites
        ]
        ok_code = (ok or "").strip().lower()
        err_code = (err or "").strip().lower()
        ok_messages = {
            "created": "Пользователь создан.",
            "updated": "Данные пользователя обновлены.",
            "deleted": "Пользователь удален.",
            "invite_created": "Ссылка приглашения создана.",
            "template_created": "Шаблон роли создан.",
            "template_updated": "Шаблон роли обновлен.",
            "template_deleted": "Шаблон роли удален.",
        }
        err_messages = {
            "bad_input": "Заполните обязательные поля.",
            "bad_role": "Недопустимый уровень доступа.",
            "bad_template": "Шаблон роли не найден или недоступен.",
            "bad_template_input": "Заполните название шаблона и проверьте параметры.",
            "template_name_exists": "Шаблон с таким названием уже существует.",
            "template_not_found": "Шаблон роли не найден.",
            "email_exists": "Пользователь с таким email уже существует.",
            "user_not_found": "Пользователь не найден или недоступен для управления.",
            "save_failed": "Не удалось сохранить изменения.",
            "delete_blocked": "Нельзя удалить пользователя: он уже участвует в заявках или шаблонах.",
            "delete_failed": "Не удалось удалить пользователя.",
            "delete_self": "Свой аккаунт удалить нельзя.",
        }
        return templates.TemplateResponse(
            "users.html",
            {
                "request": request,
                "user": user,
                "managed_users": visible_users,
                "role_templates": role_templates,
                "access_level_options": [
                    {"value": role.value, "label": access_level_label_ru(role)}
                    for role in allowed_roles
                ],
                "invite_links": invite_links,
                "ok_message": ok_messages.get(ok_code, ""),
                "err_message": err_messages.get(err_code, ""),
            },
        )

    @app.post("/web/users/invites/create")
    async def web_users_invite_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        allowed_roles = manageable_roles_for_web_user_management(user)
        if not allowed_roles:
            raise HTTPException(403, "Forbidden")

        form = await request.form()
        role_raw = (form.get("role") or "").strip().upper()
        expires_days_raw = (form.get("expires_days") or "").strip()
        if user.role == role_enum.curator:
            role_value = role_enum.executor
        else:
            if role_raw not in ("CURATOR", "EXECUTOR"):
                return RedirectResponse(url="/web/users?err=bad_role", status_code=http_303_see_other)
            role_value = role_enum(role_raw)
            if role_value not in allowed_roles:
                return RedirectResponse(url="/web/users?err=bad_role", status_code=http_303_see_other)

        try:
            expires_days = int(expires_days_raw) if expires_days_raw else 7
        except ValueError:
            expires_days = 7
        expires_days = max(1, min(expires_days, 30))

        invite = registration_invite_model(
            token=secrets.token_urlsafe(24),
            role=role_value,
            company_id=user.company_id,
            created_by=user.id,
            expires_at=datetime.utcnow() + timedelta(days=expires_days),
        )
        try:
            db.add(invite)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/users?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url="/web/users?ok=invite_created", status_code=http_303_see_other)

    @app.post("/web/users/templates/create")
    async def web_user_role_templates_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        allowed_roles = manageable_template_access_levels_for_actor(user)
        if not allowed_roles:
            raise HTTPException(403, "Forbidden")

        form = await request.form()
        name = normalize_role_template_name(form.get("name"))
        role_raw = (form.get("access_level") or "").strip().upper()
        if user.role == role_enum.curator:
            role_value = role_enum.executor
        else:
            if role_raw not in {role.value for role in allowed_roles}:
                return RedirectResponse(url="/web/users?err=bad_role", status_code=http_303_see_other)
            role_value = role_enum(role_raw)
        if not name:
            return RedirectResponse(url="/web/users?err=bad_template_input", status_code=http_303_see_other)
        exists = (
            db.query(role_template_model.id)
            .filter(
                role_template_model.company_id == user.company_id,
                func.lower(role_template_model.name) == name.lower(),
            )
            .first()
        )
        if exists:
            return RedirectResponse(url="/web/users?err=template_name_exists", status_code=http_303_see_other)

        flags = normalize_capability_flags(
            role_value,
            show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
            is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
            can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
            can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
            can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
        )
        try:
            db.add(
                role_template_model(
                    company_id=user.company_id,
                    name=name,
                    access_level=role_value,
                    **flags,
                )
            )
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/users?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url="/web/users?ok=template_created", status_code=http_303_see_other)

    @app.post("/web/users/templates/{template_id}/update")
    async def web_user_role_templates_update(
        template_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        allowed_roles = manageable_template_access_levels_for_actor(user)
        if not allowed_roles:
            raise HTTPException(403, "Forbidden")

        item = get_manageable_role_template(db, user, template_id, allowed_access_levels=allowed_roles)
        if not item:
            return RedirectResponse(url="/web/users?err=template_not_found", status_code=http_303_see_other)

        form = await request.form()
        name = normalize_role_template_name(form.get("name"))
        role_raw = (form.get("access_level") or "").strip().upper()
        if user.role == role_enum.curator:
            role_value = role_enum.executor
        else:
            if role_raw not in {role.value for role in allowed_roles}:
                return RedirectResponse(url="/web/users?err=bad_role", status_code=http_303_see_other)
            role_value = role_enum(role_raw)
        if not name:
            return RedirectResponse(url="/web/users?err=bad_template_input", status_code=http_303_see_other)
        duplicate = (
            db.query(role_template_model.id)
            .filter(
                role_template_model.company_id == user.company_id,
                func.lower(role_template_model.name) == name.lower(),
                role_template_model.id != item.id,
            )
            .first()
        )
        if duplicate:
            return RedirectResponse(url="/web/users?err=template_name_exists", status_code=http_303_see_other)

        flags = normalize_capability_flags(
            role_value,
            show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
            is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
            can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
            can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
            can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
        )
        item.name = name
        item.access_level = role_value
        item.show_receipts_accounting_mode = flags["show_receipts_accounting_mode"]
        item.is_assignable_executor = flags["is_assignable_executor"]
        item.can_view_all_tickets = flags["can_view_all_tickets"]
        item.can_create_tickets = flags["can_create_tickets"]
        item.can_close_tickets = flags["can_close_tickets"]
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/users?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url="/web/users?ok=template_updated", status_code=http_303_see_other)

    @app.post("/web/users/templates/{template_id}/delete")
    async def web_user_role_templates_delete(
        template_id: int,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        allowed_roles = manageable_template_access_levels_for_actor(user)
        item = get_manageable_role_template(db, user, template_id, allowed_access_levels=allowed_roles)
        if not item:
            return RedirectResponse(url="/web/users?err=template_not_found", status_code=http_303_see_other)
        try:
            db.delete(item)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/users?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url="/web/users?ok=template_deleted", status_code=http_303_see_other)

    @app.post("/web/users/create")
    async def web_users_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        form = await request.form()
        name = (form.get("name") or "").strip()
        email = (form.get("email") or "").strip()
        password = (form.get("password") or "").strip()
        role_raw = (form.get("role") or "").strip().upper()
        role_label = normalize_role_label(form.get("role_label"))
        role_template_id = parse_optional_int(form.get("role_template_id"))
        allowed_roles = manageable_roles_for_web_user_management(user)
        if not allowed_roles:
            raise HTTPException(403, "Forbidden")

        if not (name and email and password):
            return RedirectResponse(url="/web/users?err=bad_input", status_code=http_303_see_other)
        if db.query(user_model.id).filter(user_model.email == email).first():
            return RedirectResponse(url="/web/users?err=email_exists", status_code=http_303_see_other)

        template = get_manageable_role_template(db, user, role_template_id, allowed_access_levels=allowed_roles)
        if role_template_id is not None and not template:
            return RedirectResponse(url="/web/users?err=bad_template", status_code=http_303_see_other)
        if template:
            role_value = template.access_level
            capability_flags = role_template_payload(template)
        elif user.role == role_enum.curator:
            role_value = role_enum.executor
            capability_flags = normalize_capability_flags(
                role_value,
                show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
                is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
                can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
                can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
                can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
            )
        else:
            if role_raw not in {role.value for role in allowed_roles}:
                return RedirectResponse(url="/web/users?err=bad_role", status_code=http_303_see_other)
            role_value = role_enum(role_raw)
            capability_flags = normalize_capability_flags(
                role_value,
                show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
                is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
                can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
                can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
                can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
            )

        item = user_model(
            email=email,
            name=name,
            password_hash=hash_password(password),
            role=role_value,
            company_id=user.company_id,
            role_label=role_label or (template.name if template else None),
            **capability_flags,
        )
        prepare_user_email_verification(item, force_new_token=True)
        try:
            db.add(item)
            db.commit()
            db.refresh(item)
            send_user_verification_email(request, db, item)
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/users?err=save_failed", status_code=http_303_see_other)
        except email_delivery_error:
            logger.exception("Could not send verification email to %s", item.email)
        return RedirectResponse(url="/web/users?ok=created", status_code=http_303_see_other)

    @app.post("/web/users/{managed_user_id}/update")
    async def web_users_update(
        managed_user_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        form = await request.form()
        name = (form.get("name") or "").strip()
        email = (form.get("email") or "").strip()
        password = (form.get("password") or "").strip()
        role_raw = (form.get("role") or "").strip().upper()
        role_label = normalize_role_label(form.get("role_label"))
        role_template_id = parse_optional_int(form.get("role_template_id"))
        if not (name and email):
            return RedirectResponse(url="/web/users?err=bad_input", status_code=http_303_see_other)

        item = db.get(user_model, managed_user_id)
        if not item or not can_manage_company_user(user, item):
            return RedirectResponse(url="/web/users?err=user_not_found", status_code=http_303_see_other)

        email_owner = db.query(user_model.id).filter(user_model.email == email, user_model.id != item.id).first()
        if email_owner:
            return RedirectResponse(url="/web/users?err=email_exists", status_code=http_303_see_other)

        allowed_template_roles = (item.role,) if item.id == user.id else manageable_roles_for_web_user_management(user)
        template = get_manageable_role_template(
            db,
            user,
            role_template_id,
            allowed_access_levels=allowed_template_roles,
        )
        if role_template_id is not None and not template:
            return RedirectResponse(url="/web/users?err=bad_template", status_code=http_303_see_other)
        if item.id == user.id:
            next_role = item.role
            if template and template.access_level != item.role:
                return RedirectResponse(url="/web/users?err=bad_template", status_code=http_303_see_other)
        elif user.role == role_enum.admin:
            if template:
                next_role = template.access_level
            else:
                allowed_roles = manageable_roles_for_web_user_management(user)
                if role_raw not in {role.value for role in allowed_roles}:
                    return RedirectResponse(url="/web/users?err=bad_role", status_code=http_303_see_other)
                next_role = role_enum(role_raw)
        else:
            next_role = item.role
            if template and template.access_level != item.role:
                return RedirectResponse(url="/web/users?err=bad_template", status_code=http_303_see_other)

        capability_flags = (
            role_template_payload(template)
            if template
            else normalize_capability_flags(
                next_role,
                show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
                is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
                can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
                can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
                can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
            )
        )
        email_changed = (item.email or "").strip() != email
        item.name = name
        item.email = email
        item.role = next_role
        item.role_label = role_label or (template.name if template else None)
        item.show_receipts_accounting_mode = capability_flags["show_receipts_accounting_mode"]
        item.is_assignable_executor = capability_flags["is_assignable_executor"]
        item.can_view_all_tickets = capability_flags["can_view_all_tickets"]
        item.can_create_tickets = capability_flags["can_create_tickets"]
        item.can_close_tickets = capability_flags["can_close_tickets"]
        if password:
            item.password_hash = hash_password(password)
            bump_user_auth_token_version(item)
        if email_changed:
            prepare_user_email_verification(item, force_new_token=True)
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/users?err=save_failed", status_code=http_303_see_other)
        if email_changed:
            try:
                send_user_verification_email(request, db, item)
            except email_delivery_error:
                logger.exception("Could not send verification email to %s", item.email)
        return RedirectResponse(url="/web/users?ok=updated", status_code=http_303_see_other)

    @app.post("/web/users/{managed_user_id}/delete")
    async def web_users_delete(
        managed_user_id: int,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        item = db.get(user_model, managed_user_id)
        if not item or not can_manage_company_user(user, item):
            return RedirectResponse(url="/web/users?err=user_not_found", status_code=http_303_see_other)
        if item.id == user.id:
            return RedirectResponse(url="/web/users?err=delete_self", status_code=http_303_see_other)

        has_ticket_refs = db.query(ticket_model.id).filter(
            ticket_model.company_id == user.company_id,
            or_(ticket_model.created_by == item.id, ticket_model.executor_id == item.id, ticket_model.archived_by == item.id),
        ).first()
        has_comment_refs = (
            db.query(comment_model.id)
            .join(ticket_model, ticket_model.id == comment_model.ticket_id)
            .filter(ticket_model.company_id == user.company_id, comment_model.author_id == item.id)
            .first()
        )
        has_attachment_refs = (
            db.query(attachment_model.id)
            .join(ticket_model, ticket_model.id == attachment_model.ticket_id)
            .filter(ticket_model.company_id == user.company_id, attachment_model.uploader_id == item.id)
            .first()
        )
        has_log_refs = (
            db.query(ticket_log_model.id)
            .join(ticket_model, ticket_model.id == ticket_log_model.ticket_id)
            .filter(ticket_model.company_id == user.company_id, ticket_log_model.actor_id == item.id)
            .first()
        )
        has_template_refs = db.query(ticket_template_model.id).filter(
            ticket_template_model.company_id == user.company_id,
            ticket_template_model.default_executor_id == item.id,
        ).first()
        if has_ticket_refs or has_comment_refs or has_attachment_refs or has_log_refs or has_template_refs:
            return RedirectResponse(url="/web/users?err=delete_blocked", status_code=http_303_see_other)

        try:
            db.query(unit_assignment_model).filter(
                unit_assignment_model.company_id == user.company_id,
                unit_assignment_model.user_id == item.id,
            ).delete(synchronize_session=False)
            db.query(ticket_watcher_model).filter(ticket_watcher_model.user_id == item.id).delete(synchronize_session=False)
            db.query(ticket_watcher_model).filter(ticket_watcher_model.added_by == item.id).update(
                {ticket_watcher_model.added_by: None},
                synchronize_session=False,
            )
            db.query(push_subscription_model).filter(push_subscription_model.user_id == item.id).delete(synchronize_session=False)
            db.query(mobile_device_model).filter(mobile_device_model.user_id == item.id).delete(synchronize_session=False)
            db.query(deadline_reminder_log_model).filter(deadline_reminder_log_model.user_id == item.id).delete(synchronize_session=False)
            db.query(notification_model).filter(notification_model.user_id == item.id).delete(synchronize_session=False)
            db.query(registration_invite_model).filter(
                registration_invite_model.company_id == user.company_id,
                registration_invite_model.used_by == item.id,
            ).update(
                {registration_invite_model.used_by: None, registration_invite_model.used_at: None},
                synchronize_session=False,
            )
            db.query(registration_invite_model).filter(
                registration_invite_model.company_id == user.company_id,
                registration_invite_model.created_by == item.id,
            ).delete(synchronize_session=False)
            db.delete(item)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/users?err=delete_failed", status_code=http_303_see_other)
        return RedirectResponse(url="/web/users?ok=deleted", status_code=http_303_see_other)
