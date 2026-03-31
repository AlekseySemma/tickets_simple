from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def _sanitize_query_error(raw_value: str | None, allowed: set[str]) -> str:
    value = (raw_value or "").strip().lower()
    if value in allowed:
        return value
    return ""


def register_settings_routes(
    app,
    *,
    get_db,
    get_current_user,
    require_role,
    ensure_company_user,
    is_platform_admin,
    normalize_settings_section,
    build_settings_url,
    get_company_deadline_soon_warning_minutes,
    get_company_archive_retention_days,
    parse_deadline_soon_warning_minutes,
    parse_archive_retention_days,
    is_native_android_app_request,
    templates,
    user_model,
    company_model,
    payment_card_model,
    role_enum,
    settings_sections,
    org_structure_v2_enabled,
    min_deadline_soon_warning_minutes,
    max_deadline_soon_warning_minutes,
    min_archive_retention_days,
    max_archive_retention_days,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.get("/web/settings")
    def web_settings(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        selected_settings_section = normalize_settings_section(request.query_params.get("section"))
        company = None
        if not is_platform_admin(user):
            ensure_company_user(user)
            if user.company_id is not None:
                company = db.get(company_model, user.company_id)

        deadline_soon_warning_minutes = get_company_deadline_soon_warning_minutes(company)
        archive_retention_days_default = get_company_archive_retention_days(company)
        deadline_warning_saved = (request.query_params.get("deadline_warning_saved") or "").strip() == "1"
        deadline_warning_error = _sanitize_query_error(
            request.query_params.get("deadline_warning_error"),
            {"bad_value", "save_failed"},
        )
        archive_retention_saved = (request.query_params.get("archive_retention_saved") or "").strip() == "1"
        archive_retention_error = _sanitize_query_error(
            request.query_params.get("archive_retention_error"),
            {"bad_value", "save_failed"},
        )
        watcher_comments_saved = (request.query_params.get("watcher_comments_saved") or "").strip() == "1"
        watcher_comments_error = _sanitize_query_error(
            request.query_params.get("watcher_comments_error"),
            {"save_failed"},
        )
        receipt_notifications_saved = (request.query_params.get("receipt_notifications_saved") or "").strip() == "1"
        receipt_notifications_error = _sanitize_query_error(
            request.query_params.get("receipt_notifications_error"),
            {"save_failed"},
        )
        preferred_card_saved = (request.query_params.get("preferred_card_saved") or "").strip() == "1"
        preferred_card_error = _sanitize_query_error(
            request.query_params.get("preferred_card_error"),
            {"bad_value", "save_failed"},
        )
        card_created = (request.query_params.get("card_created") or "").strip() == "1"
        card_create_error = _sanitize_query_error(
            request.query_params.get("card_create_error"),
            {"missing_required", "card_exists", "save_failed"},
        )
        card_deleted = (request.query_params.get("card_deleted") or "").strip() == "1"
        card_delete_error = _sanitize_query_error(
            request.query_params.get("card_delete_error"),
            {"not_found", "in_use", "save_failed"},
        )
        session_revoke_error = _sanitize_query_error(
            request.query_params.get("session_revoke_error"),
            {"save_failed"},
        )
        password_change_error = _sanitize_query_error(
            request.query_params.get("password_change_error"),
            {"invalid_current_password", "password_mismatch", "password_too_short", "save_failed"},
        )
        cards = (
            db.query(payment_card_model.id, payment_card_model.name, payment_card_model.is_active)
            .filter(payment_card_model.company_id == user.company_id, payment_card_model.owner_user_id == user.id)
            .order_by(payment_card_model.name.asc())
            .all()
        ) if user.company_id is not None else []
        can_manage_deadline_warning = user.role in (role_enum.admin, role_enum.curator)
        can_manage_archive_retention = user.role in (role_enum.admin, role_enum.curator)
        rendered_settings_sections = [
            {
                **meta,
                "href": build_settings_url(meta["id"]),
                "is_active": meta["id"] == selected_settings_section,
            }
            for meta in settings_sections.values()
        ]
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "org_v2_enabled": org_structure_v2_enabled,
                "deadline_soon_warning_minutes": deadline_soon_warning_minutes,
                "deadline_warning_saved": deadline_warning_saved,
                "deadline_warning_error": deadline_warning_error,
                "archive_retention_days_default": archive_retention_days_default,
                "archive_retention_saved": archive_retention_saved,
                "archive_retention_error": archive_retention_error,
                "watcher_comments_saved": watcher_comments_saved,
                "watcher_comments_error": watcher_comments_error,
                "receipt_notifications_saved": receipt_notifications_saved,
                "receipt_notifications_error": receipt_notifications_error,
                "preferred_card_saved": preferred_card_saved,
                "preferred_card_error": preferred_card_error,
                "card_created": card_created,
                "card_create_error": card_create_error,
                "card_deleted": card_deleted,
                "card_delete_error": card_delete_error,
                "session_revoke_error": session_revoke_error,
                "password_change_error": password_change_error,
                "cards": cards,
                "preferred_payment_card_id": user.preferred_payment_card_id,
                "settings_sections": rendered_settings_sections,
                "selected_settings_section": selected_settings_section,
                "selected_settings_section_meta": settings_sections.get(selected_settings_section),
                "native_push_managed": is_native_android_app_request(request),
                "can_manage_deadline_warning": can_manage_deadline_warning,
                "can_manage_archive_retention": can_manage_archive_retention,
                "can_manage_cards": not is_platform_admin(user),
                "can_manage_receipt_settings": user.company_id is not None and not is_platform_admin(user),
                "min_deadline_soon_warning_minutes": min_deadline_soon_warning_minutes,
                "max_deadline_soon_warning_minutes": max_deadline_soon_warning_minutes,
                "min_archive_retention_days": min_archive_retention_days,
                "max_archive_retention_days": max_archive_retention_days,
            },
        )

    @app.post("/web/settings/deadline-warning")
    async def web_settings_deadline_warning(
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        company = db.get(company_model, user.company_id)
        if not company:
            raise HTTPException(404, "Company not found")

        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        parsed = parse_deadline_soon_warning_minutes(form.get("deadline_soon_warning_minutes"))
        if parsed is None:
            return RedirectResponse(
                url=build_settings_url(section, deadline_warning_error="bad_value"),
                status_code=http_303_see_other,
            )
        try:
            company.deadline_soon_warning_minutes = parsed
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, deadline_warning_error="save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=build_settings_url(section, deadline_warning_saved=True),
            status_code=http_303_see_other,
        )

    @app.post("/web/settings/archive-retention")
    async def web_settings_archive_retention(
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        company = db.get(company_model, user.company_id)
        if not company:
            raise HTTPException(404, "Company not found")

        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        parsed = parse_archive_retention_days(form.get("archive_retention_days_default"))
        if parsed is None:
            return RedirectResponse(
                url=build_settings_url(section, archive_retention_error="bad_value"),
                status_code=http_303_see_other,
            )
        try:
            company.archive_retention_days_default = parsed
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, archive_retention_error="save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=build_settings_url(section, archive_retention_saved=True),
            status_code=http_303_see_other,
        )

    @app.post("/web/settings/watcher-comments")
    async def web_settings_watcher_comments(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        enabled = (form.get("notify_comments_as_watcher") or "").strip() in {"1", "true", "on"}
        try:
            user.notify_comments_as_watcher = enabled
            db.add(user)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, watcher_comments_error="save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=build_settings_url(section, watcher_comments_saved=True),
            status_code=http_303_see_other,
        )

    @app.post("/web/settings/receipt-notifications")
    async def web_settings_receipt_notifications(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        enabled = (form.get("notify_receipt_created") or "").strip() in {"1", "true", "on"}
        try:
            user.notify_receipt_created = enabled
            db.add(user)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, receipt_notifications_error="save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=build_settings_url(section, receipt_notifications_saved=True),
            status_code=http_303_see_other,
        )

    @app.post("/web/settings/preferred-card")
    async def web_settings_preferred_card(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ensure_company_user(user)
        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        raw_value = (form.get("preferred_payment_card_id") or "").strip()
        preferred_card_id = None
        if raw_value:
            try:
                preferred_card_id = int(raw_value)
            except ValueError:
                preferred_card_id = None
        if raw_value and preferred_card_id is None:
            return RedirectResponse(
                url=build_settings_url(section, preferred_card_error="bad_value"),
                status_code=http_303_see_other,
            )
        if preferred_card_id is not None:
            exists = (
                db.query(payment_card_model.id)
                .filter(
                    payment_card_model.id == preferred_card_id,
                    payment_card_model.company_id == user.company_id,
                    payment_card_model.owner_user_id == user.id,
                    payment_card_model.is_active.is_(True),
                )
                .first()
            )
            if not exists:
                return RedirectResponse(
                    url=build_settings_url(section, preferred_card_error="bad_value"),
                    status_code=http_303_see_other,
                )
        try:
            user.preferred_payment_card_id = preferred_card_id
            db.add(user)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, preferred_card_error="save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=build_settings_url(section, preferred_card_saved=True),
            status_code=http_303_see_other,
        )
