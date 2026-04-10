from datetime import datetime
from app_support.time_support import utc_now_naive

from fastapi import Depends, HTTPException, Request
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
    normalize_capability_flags,
    prepare_user_email_verification,
    send_user_verification_email,
    send_user_password_reset_email,
    get_active_invite,
    register_company_owner,
    templates,
    logger,
    user_model,
    company_model,
    role_enum,
    email_delivery_error,
    bootstrap_setup_in_model,
    rl_login_limit,
    rl_login_window_sec,
    rl_register_limit,
    rl_register_window_sec,
    rl_password_reset_limit,
    rl_password_reset_window_sec,
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
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": None, "info": info_message})

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
                request,
                "login.html",
                {"request": request, "error": "Слишком много попыток входа. Попробуйте позже.", "info": None},
                status_code=429,
            )

        user = db.query(user_model).filter(user_model.email == email).first()
        if not user or not verify_password(password, user.password_hash):
            audit_security_event("web_login", request, success=False, email=email, detail="invalid_credentials")
            return templates.TemplateResponse(
                request,
                "login.html",
                {"request": request, "error": "Неверный email или пароль", "info": None},
            )
        if not is_user_email_verified(user):
            audit_security_event("web_login", request, success=False, email=email, user_id=user.id, detail="email_not_verified")
            return templates.TemplateResponse(
                request,
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

    @app.get("/web/register-company")
    def web_register_company_page(request: Request):
        return templates.TemplateResponse(
            request,
            "register_company.html",
            {"request": request, "error": None, "success": False},
        )

    @app.post("/web/register-company")
    async def web_register_company_submit(request: Request, db=Depends(get_db)):
        form = await request.form()
        company_name = (form.get("company_name") or "").strip()
        admin_name = (form.get("admin_name") or "").strip()
        admin_email = (form.get("admin_email") or "").strip()
        admin_password = (form.get("admin_password") or "").strip()

        try:
            payload = bootstrap_setup_in_model(
                company_name=company_name,
                admin_name=admin_name,
                admin_email=admin_email,
                admin_password=admin_password,
            )
            _ = register_company_owner(
                payload=payload,
                request=request,
                db=db,
                get_client_ip=get_client_ip,
                hit_rate_limit=hit_rate_limit,
                audit_security_event=audit_security_event,
                hash_password=hash_password,
                normalize_capability_flags=normalize_capability_flags,
                prepare_user_email_verification=prepare_user_email_verification,
                send_user_verification_email=send_user_verification_email,
                logger=logger,
                user_model=user_model,
                company_model=company_model,
                role_enum=role_enum,
                email_delivery_error=email_delivery_error,
                rl_register_limit=rl_register_limit,
                rl_register_window_sec=rl_register_window_sec,
            )
            return templates.TemplateResponse(
                request,
                "register_company.html",
                {"request": request, "error": None, "success": True},
            )
        except HTTPException as exc:
            return templates.TemplateResponse(
                request,
                "register_company.html",
                {"request": request, "error": str(exc.detail), "success": False},
            )
        except Exception:
            audit_security_event("register_company", request, success=False, email=admin_email, detail="validation_error")
            return templates.TemplateResponse(
                request,
                "register_company.html",
                {"request": request, "error": "РџСЂРѕРІРµСЂСЊС‚Рµ РІРІРµРґРµРЅРЅС‹Рµ РґР°РЅРЅС‹Рµ", "success": False},
            )

    @app.get("/web/register")
    def web_register_page(request: Request, token: str | None = None, db=Depends(get_db)):
        invite = get_active_invite(db, token)
        role_value = invite.role.value if invite else ""
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "request": request,
                "token": (token or "").strip(),
                "role_value": role_value,
                "error": None,
                "success": False,
            },
        )

    @app.post("/web/register")
    async def web_register_submit(request: Request, db=Depends(get_db)):
        form = await request.form()
        token = (form.get("token") or "").strip()
        name = (form.get("name") or "").strip()
        email = (form.get("email") or "").strip()
        password = (form.get("password") or "").strip()
        ip = get_client_ip(request)
        limited, _ = hit_rate_limit(f"web-register:{ip}", rl_register_limit * 2, rl_register_window_sec)
        if limited:
            audit_security_event("web_register", request, success=False, email=email, detail="rate_limited")
            return templates.TemplateResponse(
                request,
                "register.html",
                {"request": request, "token": token, "role_value": "", "error": "Слишком много попыток. Попробуйте позже.", "success": False},
                status_code=429,
            )

        invite = get_active_invite(db, token)
        role_value = invite.role.value if invite else ""

        if not invite:
            audit_security_event("web_register", request, success=False, email=email, detail="invalid_invite")
            return templates.TemplateResponse(
                request,
                "register.html",
                {"request": request, "token": token, "role_value": role_value, "error": "Ссылка недействительна", "success": False},
            )
        if not (name and email and password):
            audit_security_event("web_register", request, success=False, email=email, detail="missing_fields")
            return templates.TemplateResponse(
                request,
                "register.html",
                {"request": request, "token": token, "role_value": role_value, "error": "Заполните все поля", "success": False},
            )
        if db.query(user_model).filter(user_model.email == email).first():
            audit_security_event("web_register", request, success=False, email=email, detail="email_exists")
            return templates.TemplateResponse(
                request,
                "register.html",
                {"request": request, "token": token, "role_value": role_value, "error": "Email уже используется", "success": False},
            )

        try:
            user = user_model(
                email=email,
                name=name,
                password_hash=hash_password(password),
                role=invite.role,
                company_id=invite.company_id,
                **normalize_capability_flags(invite.role),
            )
            prepare_user_email_verification(user, force_new_token=True)
            db.add(user)
            db.flush()

            invite.used_by = user.id
            invite.used_at = utc_now_naive()
            db.commit()
        except sqlalchemy_error:
            audit_security_event("web_register", request, success=False, email=email, detail="db_error")
            db.rollback()
            return templates.TemplateResponse(
                request,
                "register.html",
                {"request": request, "token": token, "role_value": role_value, "error": "Не удалось завершить регистрацию", "success": False},
            )
        try:
            send_user_verification_email(request, db, user)
        except email_delivery_error:
            logger.exception("Could not send verification email to %s", user.email)

        audit_security_event("web_register", request, success=True, email=email, user_id=user.id)
        return templates.TemplateResponse(
            request,
            "register.html",
            {"request": request, "token": "", "role_value": invite.role.value, "error": None, "success": True},
        )

    @app.get("/web/password-reset")
    def web_password_reset_page(request: Request):
        return templates.TemplateResponse(
            request,
            "password_reset_request.html",
            {"request": request, "success": False, "message": None},
        )

    @app.post("/web/password-reset")
    async def web_password_reset_submit(request: Request, db=Depends(get_db)):
        form = await request.form()
        email = (form.get("email") or "").strip()
        ip = get_client_ip(request)
        limited_ip, _ = hit_rate_limit(
            f"password-reset-ip:{ip}",
            rl_password_reset_limit * 2,
            rl_password_reset_window_sec,
        )
        limited_email, _ = hit_rate_limit(
            f"password-reset-email:{(email or '').lower()}",
            rl_password_reset_limit,
            rl_password_reset_window_sec,
        )
        if not limited_ip and not limited_email and email:
            user = db.query(user_model).filter(user_model.email == email).first()
            if user:
                try:
                    send_user_password_reset_email(request, db, user, force_new_token=True)
                    audit_security_event("password_reset_request", request, success=True, email=email, user_id=user.id)
                except email_delivery_error:
                    logger.exception("Could not send password reset email to %s", user.email)
            else:
                audit_security_event("password_reset_request", request, success=True, email=email, detail="ignored")
        else:
            audit_security_event("password_reset_request", request, success=False, email=email, detail="rate_limited")
        return templates.TemplateResponse(
            request,
            "password_reset_request.html",
            {
                "request": request,
                "success": True,
                "message": "Если аккаунт существует, мы отправили письмо со ссылкой для сброса пароля.",
            },
        )

    @app.get("/web/password-reset/confirm")
    def web_password_reset_confirm_page(request: Request, token: str | None = None, db=Depends(get_db)):
        token_value = (token or "").strip()
        user = None
        if token_value:
            user = db.query(user_model).filter(user_model.password_reset_token == token_value).first()
        if not user:
            return templates.TemplateResponse(
                request,
                "password_reset_confirm.html",
                {"request": request, "token": "", "success": False, "error": "Ссылка сброса пароля недействительна или уже использована."},
                status_code=400,
            )
        if user.password_reset_expires_at and user.password_reset_expires_at <= utc_now_naive():
            return templates.TemplateResponse(
                request,
                "password_reset_confirm.html",
                {"request": request, "token": "", "success": False, "error": "Срок действия ссылки истёк. Запросите новое письмо."},
                status_code=400,
            )
        return templates.TemplateResponse(
            request,
            "password_reset_confirm.html",
            {"request": request, "token": token_value, "success": False, "error": None},
        )

    @app.post("/web/password-reset/confirm")
    async def web_password_reset_confirm_submit(request: Request, db=Depends(get_db)):
        form = await request.form()
        token_value = (form.get("token") or "").strip()
        password = (form.get("password") or "").strip()
        password_confirm = (form.get("password_confirm") or "").strip()
        user = None
        if token_value:
            user = db.query(user_model).filter(user_model.password_reset_token == token_value).first()
        if not user:
            return templates.TemplateResponse(
                request,
                "password_reset_confirm.html",
                {"request": request, "token": "", "success": False, "error": "Ссылка сброса пароля недействительна или уже использована."},
                status_code=400,
            )
        if user.password_reset_expires_at and user.password_reset_expires_at <= utc_now_naive():
            return templates.TemplateResponse(
                request,
                "password_reset_confirm.html",
                {"request": request, "token": "", "success": False, "error": "Срок действия ссылки истёк. Запросите новое письмо."},
                status_code=400,
            )
        if not password:
            return templates.TemplateResponse(
                request,
                "password_reset_confirm.html",
                {"request": request, "token": token_value, "success": False, "error": "Введите новый пароль."},
                status_code=400,
            )
        if len(password) < 8:
            return templates.TemplateResponse(
                request,
                "password_reset_confirm.html",
                {"request": request, "token": token_value, "success": False, "error": "Пароль должен быть не короче 8 символов."},
                status_code=400,
            )
        if password != password_confirm:
            return templates.TemplateResponse(
                request,
                "password_reset_confirm.html",
                {"request": request, "token": token_value, "success": False, "error": "Пароли не совпадают."},
                status_code=400,
            )
        user.password_hash = hash_password(password)
        bump_user_auth_token_version(user)
        clear_password_reset_state(user)
        db.commit()
        audit_security_event("password_reset_confirm", request, success=True, email=user.email, user_id=user.id)
        return templates.TemplateResponse(
            request,
            "password_reset_confirm.html",
            {"request": request, "token": "", "success": True, "error": None},
        )

    @app.get("/web/logout")
    def web_logout(request: Request):
        response = RedirectResponse(url="/web/login", status_code=http_303_see_other)
        delete_auth_cookie(response, request)
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
