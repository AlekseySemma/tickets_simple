from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_admin_company_routes(
    app,
    *,
    get_db,
    get_current_user,
    is_platform_admin,
    delete_company_with_data,
    parse_deadline_soon_warning_minutes,
    parse_archive_retention_days,
    normalize_capability_flags,
    hash_password,
    prepare_user_email_verification,
    send_user_verification_email,
    bump_user_auth_token_version,
    templates,
    logger,
    func,
    or_,
    company_model,
    user_model,
    org_unit_model,
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
    registration_invite_model,
    role_enum,
    min_deadline_soon_warning_minutes,
    max_deadline_soon_warning_minutes,
    min_archive_retention_days,
    max_archive_retention_days,
    email_delivery_error,
    http_303_see_other,
    sqlalchemy_error,
):
    def platform_manageable_roles() -> tuple:
        return (role_enum.admin, role_enum.curator, role_enum.executor)

    @app.get("/web/admin/companies")
    def web_admin_companies(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_platform_admin(user):
            raise HTTPException(403, "Only platform admin")

        companies = db.query(company_model).order_by(company_model.id.desc()).all()
        company_ids = [company.id for company in companies]

        users_count_by_company: dict[int, int] = {}
        org_units_count_by_company: dict[int, int] = {}
        tickets_count_by_company: dict[int, int] = {}

        if company_ids:
            users_count_rows = (
                db.query(user_model.company_id, func.count(user_model.id))
                .filter(user_model.company_id.in_(company_ids))
                .group_by(user_model.company_id)
                .all()
            )
            users_count_by_company = {
                int(company_id): int(count_value)
                for company_id, count_value in users_count_rows
                if company_id is not None
            }

            org_units_count_rows = (
                db.query(org_unit_model.company_id, func.count(org_unit_model.id))
                .filter(org_unit_model.company_id.in_(company_ids))
                .group_by(org_unit_model.company_id)
                .all()
            )
            org_units_count_by_company = {
                int(company_id): int(count_value)
                for company_id, count_value in org_units_count_rows
                if company_id is not None
            }

            tickets_count_rows = (
                db.query(ticket_model.company_id, func.count(ticket_model.id))
                .filter(ticket_model.company_id.in_(company_ids))
                .group_by(ticket_model.company_id)
                .all()
            )
            tickets_count_by_company = {
                int(company_id): int(count_value)
                for company_id, count_value in tickets_count_rows
                if company_id is not None
            }

        items = []
        for company in companies:
            items.append(
                {
                    "id": company.id,
                    "name": company.name,
                    "created_at": company.created_at,
                    "users_count": users_count_by_company.get(company.id, 0),
                    "org_units_count": org_units_count_by_company.get(company.id, 0),
                    "tickets_count": tickets_count_by_company.get(company.id, 0),
                }
            )

        return templates.TemplateResponse(
            request,
            "admin_companies.html",
            {
                "request": request,
                "user": user,
                "companies": items,
            },
        )

    @app.post("/web/admin/companies/{company_id}/delete")
    async def web_admin_company_delete(
        company_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_platform_admin(user):
            raise HTTPException(403, "Only platform admin")
        company = db.get(company_model, company_id)
        if not company:
            raise HTTPException(404, "Company not found")

        delete_company_with_data(db, company_id)
        db.commit()
        return RedirectResponse(url="/web/admin/companies", status_code=http_303_see_other)

    @app.get("/web/admin/companies/{company_id}/settings")
    def web_admin_company_settings(
        company_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
        ok: str | None = None,
        err: str | None = None,
    ):
        if not is_platform_admin(user):
            raise HTTPException(403, "Only platform admin")
        company = db.get(company_model, company_id)
        if not company:
            raise HTTPException(404, "Company not found")

        users = (
            db.query(
                user_model.id,
                user_model.name,
                user_model.email,
                user_model.role,
                user_model.show_receipts_accounting_mode,
            )
            .filter(
                user_model.company_id == company_id,
                user_model.role.in_(platform_manageable_roles()),
            )
            .order_by(user_model.id.desc())
            .all()
        )
        role_options = [role.value for role in platform_manageable_roles()]

        ok_code = (ok or "").strip().lower()
        err_code = (err or "").strip().lower()
        ok_messages = {
            "company_updated": "Данные компании успешно обновлены.",
            "user_created": "Пользователь успешно создан.",
            "user_updated": "Данные пользователя успешно обновлены.",
            "user_deleted": "Пользователь успешно удален.",
        }
        err_messages = {
            "bad_company_name": "Укажите корректное название компании.",
            "bad_deadline_warning": "Некорректное значение предупреждения о дедлайне.",
            "bad_archive_retention": "Некорректное значение хранения в архиве.",
            "company_name_exists": "Компания с таким названием уже существует.",
            "bad_input": "Проверьте заполнение обязательных полей.",
            "bad_role": "Выбрана недопустимая роль пользователя.",
            "email_exists": "Пользователь с таким email уже существует.",
            "user_not_found": "Пользователь не найден.",
            "delete_blocked": "Нельзя удалить пользователя: есть связанные рабочие данные.",
            "save_failed": "Не удалось сохранить изменения. Повторите попытку.",
            "delete_failed": "Не удалось удалить пользователя. Повторите попытку.",
        }
        return templates.TemplateResponse(
            request,
            "admin_company_settings.html",
            {
                "request": request,
                "user": user,
                "company": company,
                "users": users,
                "role_options": role_options,
                "ok": ok_messages.get(ok_code, ""),
                "err": err_messages.get(err_code, ""),
                "min_deadline_soon_warning_minutes": min_deadline_soon_warning_minutes,
                "max_deadline_soon_warning_minutes": max_deadline_soon_warning_minutes,
                "min_archive_retention_days": min_archive_retention_days,
                "max_archive_retention_days": max_archive_retention_days,
            },
        )

    @app.post("/web/admin/companies/{company_id}/update")
    async def web_admin_company_settings_update(
        company_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_platform_admin(user):
            raise HTTPException(403, "Only platform admin")
        company = db.get(company_model, company_id)
        if not company:
            raise HTTPException(404, "Company not found")

        form = await request.form()
        name = (form.get("name") or "").strip()
        if not name:
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=bad_company_name",
                status_code=http_303_see_other,
            )

        warning_parsed = parse_deadline_soon_warning_minutes(form.get("deadline_soon_warning_minutes"))
        retention_parsed = parse_archive_retention_days(form.get("archive_retention_days_default"))
        if warning_parsed is None:
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=bad_deadline_warning",
                status_code=http_303_see_other,
            )
        if retention_parsed is None:
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=bad_archive_retention",
                status_code=http_303_see_other,
            )

        duplicate = (
            db.query(company_model.id)
            .filter(company_model.name == name, company_model.id != company_id)
            .first()
        )
        if duplicate:
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=company_name_exists",
                status_code=http_303_see_other,
            )

        company.name = name
        company.deadline_soon_warning_minutes = warning_parsed
        company.archive_retention_days_default = retention_parsed
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=save_failed",
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?ok=company_updated",
            status_code=http_303_see_other,
        )

    @app.post("/web/admin/companies/{company_id}/users/create")
    async def web_admin_company_user_create(
        company_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_platform_admin(user):
            raise HTTPException(403, "Only platform admin")
        company = db.get(company_model, company_id)
        if not company:
            raise HTTPException(404, "Company not found")

        form = await request.form()
        name = (form.get("name") or "").strip()
        email = (form.get("email") or "").strip()
        password = (form.get("password") or "").strip()
        role_raw = (form.get("role") or "").strip().upper()

        if not (name and email and password):
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=bad_input",
                status_code=http_303_see_other,
            )
        if role_raw not in {role.value for role in platform_manageable_roles()}:
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=bad_role",
                status_code=http_303_see_other,
            )
        role_value = role_enum(role_raw)
        if db.query(user_model.id).filter(user_model.email == email).first():
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=email_exists",
                status_code=http_303_see_other,
            )

        item = user_model(
            email=email,
            name=name,
            password_hash=hash_password(password),
            role=role_value,
            company_id=company_id,
            **normalize_capability_flags(role_value),
        )
        prepare_user_email_verification(item, force_new_token=True)
        try:
            db.add(item)
            db.commit()
            db.refresh(item)
            send_user_verification_email(request, db, item)
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=save_failed",
                status_code=http_303_see_other,
            )
        except email_delivery_error:
            logger.exception("Could not send verification email to %s", item.email)
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?ok=user_created",
            status_code=http_303_see_other,
        )

    @app.post("/web/admin/companies/{company_id}/users/{managed_user_id}/update")
    async def web_admin_company_user_update(
        company_id: int,
        managed_user_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_platform_admin(user):
            raise HTTPException(403, "Only platform admin")
        company = db.get(company_model, company_id)
        if not company:
            raise HTTPException(404, "Company not found")

        item = db.get(user_model, managed_user_id)
        if not item or item.company_id != company_id or item.role not in platform_manageable_roles():
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=user_not_found",
                status_code=http_303_see_other,
            )

        form = await request.form()
        name = (form.get("name") or "").strip()
        email = (form.get("email") or "").strip()
        password = (form.get("password") or "").strip()
        role_raw = (form.get("role") or "").strip().upper()
        if not (name and email):
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=bad_input",
                status_code=http_303_see_other,
            )
        if role_raw not in {role.value for role in platform_manageable_roles()}:
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=bad_role",
                status_code=http_303_see_other,
            )
        email_owner = db.query(user_model.id).filter(user_model.email == email, user_model.id != item.id).first()
        if email_owner:
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=email_exists",
                status_code=http_303_see_other,
            )

        email_changed = (item.email or "").strip() != email
        item.name = name
        item.email = email
        item.role = role_enum(role_raw)
        capability_flags = normalize_capability_flags(item.role)
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
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=save_failed",
                status_code=http_303_see_other,
            )
        if email_changed:
            try:
                send_user_verification_email(request, db, item)
            except email_delivery_error:
                logger.exception("Could not send verification email to %s", item.email)
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?ok=user_updated",
            status_code=http_303_see_other,
        )

    @app.post("/web/admin/companies/{company_id}/users/{managed_user_id}/delete")
    async def web_admin_company_user_delete(
        company_id: int,
        managed_user_id: int,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_platform_admin(user):
            raise HTTPException(403, "Only platform admin")
        company = db.get(company_model, company_id)
        if not company:
            raise HTTPException(404, "Company not found")

        item = db.get(user_model, managed_user_id)
        if not item or item.company_id != company_id or item.role not in platform_manageable_roles():
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=user_not_found",
                status_code=http_303_see_other,
            )

        has_ticket_refs = db.query(ticket_model.id).filter(
            ticket_model.company_id == company_id,
            or_(
                ticket_model.created_by == item.id,
                ticket_model.executor_id == item.id,
                ticket_model.archived_by == item.id,
            ),
        ).first()
        has_comment_refs = (
            db.query(comment_model.id)
            .join(ticket_model, ticket_model.id == comment_model.ticket_id)
            .filter(ticket_model.company_id == company_id, comment_model.author_id == item.id)
            .first()
        )
        has_attachment_refs = (
            db.query(attachment_model.id)
            .join(ticket_model, ticket_model.id == attachment_model.ticket_id)
            .filter(ticket_model.company_id == company_id, attachment_model.uploader_id == item.id)
            .first()
        )
        has_log_refs = (
            db.query(ticket_log_model.id)
            .join(ticket_model, ticket_model.id == ticket_log_model.ticket_id)
            .filter(ticket_model.company_id == company_id, ticket_log_model.actor_id == item.id)
            .first()
        )
        has_template_refs = db.query(ticket_template_model.id).filter(
            ticket_template_model.company_id == company_id,
            ticket_template_model.default_executor_id == item.id,
        ).first()
        if has_ticket_refs or has_comment_refs or has_attachment_refs or has_log_refs or has_template_refs:
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=delete_blocked",
                status_code=http_303_see_other,
            )

        try:
            db.query(unit_assignment_model).filter(
                unit_assignment_model.company_id == company_id,
                unit_assignment_model.user_id == item.id,
            ).delete(synchronize_session=False)
            db.query(ticket_watcher_model).filter(ticket_watcher_model.user_id == item.id).delete(
                synchronize_session=False
            )
            db.query(ticket_watcher_model).filter(ticket_watcher_model.added_by == item.id).update(
                {ticket_watcher_model.added_by: None},
                synchronize_session=False,
            )
            db.query(push_subscription_model).filter(push_subscription_model.user_id == item.id).delete(
                synchronize_session=False
            )
            db.query(mobile_device_model).filter(mobile_device_model.user_id == item.id).delete(
                synchronize_session=False
            )
            db.query(deadline_reminder_log_model).filter(deadline_reminder_log_model.user_id == item.id).delete(
                synchronize_session=False
            )
            db.query(notification_model).filter(notification_model.user_id == item.id).delete(
                synchronize_session=False
            )
            db.query(registration_invite_model).filter(
                registration_invite_model.company_id == company_id,
                registration_invite_model.used_by == item.id,
            ).update(
                {
                    registration_invite_model.used_by: None,
                    registration_invite_model.used_at: None,
                },
                synchronize_session=False,
            )
            db.query(registration_invite_model).filter(
                registration_invite_model.company_id == company_id,
                registration_invite_model.created_by == item.id,
            ).delete(synchronize_session=False)
            db.delete(item)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=f"/web/admin/companies/{company_id}/settings?err=delete_failed",
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?ok=user_deleted",
            status_code=http_303_see_other,
        )
