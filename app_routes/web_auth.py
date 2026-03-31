from fastapi import Depends, Request
from fastapi.responses import RedirectResponse


def register_web_auth_routes(
    app,
    *,
    get_db,
    get_current_user,
    get_client_ip,
    hit_rate_limit,
    audit_security_event,
    verify_password,
    is_user_email_verified,
    create_access_token,
    get_user_auth_token_version,
    get_auth_cookie_params,
    delete_auth_cookie,
    normalize_settings_section,
    build_settings_url,
    bump_user_auth_token_version,
    clear_password_reset_state,
    hash_password,
    templates,
    user_model,
    rl_login_limit,
    rl_login_window_sec,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.get("/web/login")
    def web_login_page(request: Request):
        info = (request.query_params.get("info") or "").strip().lower()
        info_message = None
        if info == "logged_out_all":
            info_message = "Сессии на всех устройствах завершены. Войдите снова."
        elif info == "password_changed":
            info_message = "Пароль изменён. Войдите с новым паролем."
        return templates.TemplateResponse("login.html", {"request": request, "error": None, "info": info_message})

    @app.post("/web/login")
    async def web_login(request: Request, db=Depends(get_db)):
        form = await request.form()
        email = (form.get("email") or "").strip()
        password = form.get("password")
        ip = get_client_ip(request)

        limited_ip, _ = hit_rate_limit(f"web-login-ip:{ip}", rl_login_limit * 3, rl_login_window_sec)
        limited_user, _ = hit_rate_limit(f"web-login-user:{ip}:{email.lower()}", rl_login_limit, rl_login_window_sec)
        if limited_ip or limited_user:
            audit_security_event("web_login", request, success=False, email=email, detail="rate_limited")
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Слишком много попыток входа. Попробуйте позже.", "info": None},
                status_code=429,
            )

        user = db.query(user_model).filter(user_model.email == email).first()
        if not user or not verify_password(password, user.password_hash):
            audit_security_event("web_login", request, success=False, email=email, detail="invalid_credentials")
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Неверный email или пароль", "info": None},
            )
        if not is_user_email_verified(user):
            audit_security_event("web_login", request, success=False, email=email, user_id=user.id, detail="email_not_verified")
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Подтвердите email по ссылке из письма, затем повторите вход.",
                    "info": None,
                },
                status_code=403,
            )

        token = create_access_token(str(user.id), get_user_auth_token_version(user))
        response = RedirectResponse(url="/web", status_code=http_303_see_other)
        response.set_cookie(
            "access_token",
            token,
            **get_auth_cookie_params(request),
        )
        audit_security_event("web_login", request, success=True, email=email, user_id=user.id)
        return response

    @app.post("/web/settings/logout-all")
    async def web_settings_logout_all(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        try:
            bump_user_auth_token_version(user)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, session_revoke_error="save_failed"),
                status_code=http_303_see_other,
            )
        audit_security_event("logout_all_devices", request, success=True, email=user.email, user_id=user.id)
        response = RedirectResponse(url="/web/login?info=logged_out_all", status_code=http_303_see_other)
        delete_auth_cookie(response, request)
        return response

    @app.post("/web/settings/change-password")
    async def web_settings_change_password(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        current_password = (form.get("current_password") or "").strip()
        new_password = (form.get("new_password") or "").strip()
        new_password_confirm = (form.get("new_password_confirm") or "").strip()
        if not verify_password(current_password, user.password_hash):
            return RedirectResponse(
                url=build_settings_url(section, password_change_error="invalid_current_password"),
                status_code=http_303_see_other,
            )
        if len(new_password) < 8:
            return RedirectResponse(
                url=build_settings_url(section, password_change_error="password_too_short"),
                status_code=http_303_see_other,
            )
        if new_password != new_password_confirm:
            return RedirectResponse(
                url=build_settings_url(section, password_change_error="password_mismatch"),
                status_code=http_303_see_other,
            )
        try:
            user.password_hash = hash_password(new_password)
            bump_user_auth_token_version(user)
            clear_password_reset_state(user)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, password_change_error="save_failed"),
                status_code=http_303_see_other,
            )
        audit_security_event("password_change", request, success=True, email=user.email, user_id=user.id)
        response = RedirectResponse(url="/web/login?info=password_changed", status_code=http_303_see_other)
        delete_auth_cookie(response, request)
        return response
