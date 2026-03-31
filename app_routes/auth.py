from datetime import datetime

from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm


def register_company_owner(
    *,
    payload,
    request,
    db,
    get_client_ip,
    hit_rate_limit,
    audit_security_event,
    hash_password,
    normalize_capability_flags,
    prepare_user_email_verification,
    send_user_verification_email,
    logger,
    user_model,
    company_model,
    role_enum,
    email_delivery_error,
    rl_register_limit,
    rl_register_window_sec,
):
    ip = get_client_ip(request)
    limited, _ = hit_rate_limit(f"register-company:{ip}", rl_register_limit, rl_register_window_sec)
    if limited:
        audit_security_event("register_company", request, success=False, email=payload.admin_email, detail="rate_limited")
        raise HTTPException(429, "Too many registration attempts")

    company_name = (payload.company_name or "").strip()
    if not company_name:
        audit_security_event("register_company", request, success=False, email=payload.admin_email, detail="missing_company_name")
        raise HTTPException(422, "Company name is required")
    if db.query(company_model).filter(company_model.name == company_name).first():
        audit_security_event("register_company", request, success=False, email=payload.admin_email, detail="company_exists")
        raise HTTPException(400, "Company already exists")
    if db.query(user_model).filter(user_model.email == payload.admin_email).first():
        audit_security_event("register_company", request, success=False, email=payload.admin_email, detail="email_exists")
        raise HTTPException(400, "Email already exists")

    company = company_model(name=company_name)
    db.add(company)
    db.flush()

    owner = user_model(
        email=payload.admin_email,
        name=payload.admin_name,
        password_hash=hash_password(payload.admin_password),
        role=role_enum.admin,
        company_id=company.id,
        **normalize_capability_flags(role_enum.admin, is_assignable_executor=True),
    )
    prepare_user_email_verification(owner, force_new_token=True)
    db.add(owner)
    db.commit()
    db.refresh(owner)
    db.refresh(company)
    try:
        send_user_verification_email(request, db, owner)
    except email_delivery_error:
        logger.exception("Could not send verification email to %s", owner.email)
    audit_security_event("register_company", request, success=True, email=payload.admin_email, user_id=owner.id)
    return company, owner


def register_auth_routes(
    app,
    *,
    get_db,
    get_client_ip,
    hit_rate_limit,
    audit_security_event,
    hash_password,
    normalize_capability_flags,
    prepare_user_email_verification,
    send_user_verification_email,
    create_access_token,
    get_user_auth_token_version,
    verify_password,
    ensure_user_can_authenticate,
    mark_user_email_verified,
    is_user_email_verified,
    templates,
    logger,
    user_model,
    company_model,
    role_enum,
    bootstrap_setup_in_model,
    bootstrap_setup_out_model,
    token_out_model,
    email_delivery_error,
    sqlalchemy_error,
    rl_register_limit,
    rl_register_window_sec,
    rl_login_limit,
    rl_login_window_sec,
    rl_email_verification_limit,
    rl_email_verification_window_sec,
):
    @app.post("/auth/bootstrap", response_model=bootstrap_setup_out_model)
    def bootstrap_platform_admin(payload: bootstrap_setup_in_model, db=Depends(get_db)):
        if db.query(user_model).filter(user_model.role == role_enum.platform_admin).first():
            raise HTTPException(400, "Bootstrap already done")
        if db.query(user_model).filter(user_model.email == payload.admin_email).first():
            raise HTTPException(400, "Admin email already exists")

        company_name = (payload.company_name or "").strip() or "Platform"
        company = db.query(company_model).filter(company_model.name == company_name).first()
        if not company:
            company = company_model(name=company_name)
            db.add(company)
            db.flush()

        user = user_model(
            email=payload.admin_email,
            name=payload.admin_name,
            password_hash=hash_password(payload.admin_password),
            role=role_enum.platform_admin,
            company_id=None,
            email_verified=True,
            email_verified_at=datetime.utcnow(),
            **normalize_capability_flags(role_enum.platform_admin),
        )
        try:
            db.add(user)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            raise HTTPException(400, "Could not create platform admin")
        db.refresh(user)
        db.refresh(company)
        return bootstrap_setup_out_model(company=company, admin=user)

    @app.post("/auth/register-company", response_model=bootstrap_setup_out_model)
    def register_company_and_owner(payload: bootstrap_setup_in_model, request: Request, db=Depends(get_db)):
        company, owner = register_company_owner(
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
        return bootstrap_setup_out_model(company=company, admin=owner)

    @app.post("/auth/login", response_model=token_out_model)
    def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
        ip = get_client_ip(request)
        email = (form.username or "").strip()
        limited_ip, _ = hit_rate_limit(f"auth-login-ip:{ip}", rl_login_limit * 3, rl_login_window_sec)
        limited_user, _ = hit_rate_limit(f"auth-login-user:{ip}:{(email or '').lower()}", rl_login_limit, rl_login_window_sec)
        if limited_ip or limited_user:
            audit_security_event("auth_login", request, success=False, email=email, detail="rate_limited")
            raise HTTPException(status_code=429, detail="Too many login attempts")
        user = db.query(user_model).filter(user_model.email == form.username).first()
        if not user or not verify_password(form.password, user.password_hash):
            audit_security_event("auth_login", request, success=False, email=email, detail="invalid_credentials")
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        try:
            ensure_user_can_authenticate(user)
        except HTTPException:
            audit_security_event("auth_login", request, success=False, email=email, user_id=user.id, detail="email_not_verified")
            raise
        audit_security_event("auth_login", request, success=True, email=email, user_id=user.id)
        return token_out_model(access_token=create_access_token(str(user.id), get_user_auth_token_version(user)))

    @app.get("/web/verify-email")
    def web_verify_email_page(request: Request, token: str | None = None, db=Depends(get_db)):
        token_value = (token or "").strip()
        user = None
        if token_value:
            user = db.query(user_model).filter(user_model.email_verification_token == token_value).first()

        if not user:
            return templates.TemplateResponse(
                "verify_email.html",
                {"request": request, "success": False, "error": "Ссылка подтверждения недействительна или уже использована."},
                status_code=400,
            )
        if user.email_verification_expires_at and user.email_verification_expires_at <= datetime.utcnow():
            return templates.TemplateResponse(
                "verify_email.html",
                {"request": request, "success": False, "error": "Срок действия ссылки истёк. Запросите новое письмо."},
                status_code=400,
            )

        mark_user_email_verified(user)
        db.commit()
        audit_security_event("email_verify", request, success=True, email=user.email, user_id=user.id)
        return templates.TemplateResponse(
            "verify_email.html",
            {"request": request, "success": True, "error": None},
        )

    @app.get("/web/verify-email/resend")
    def web_resend_verification_page(request: Request):
        return templates.TemplateResponse(
            "verify_email_resend.html",
            {"request": request, "success": False, "message": None},
        )

    @app.post("/web/verify-email/resend")
    async def web_resend_verification_submit(request: Request, db=Depends(get_db)):
        form = await request.form()
        email = (form.get("email") or "").strip()
        ip = get_client_ip(request)
        limited_ip, _ = hit_rate_limit(
            f"email-verify-resend-ip:{ip}",
            rl_email_verification_limit * 2,
            rl_email_verification_window_sec,
        )
        limited_email, _ = hit_rate_limit(
            f"email-verify-resend-email:{(email or '').lower()}",
            rl_email_verification_limit,
            rl_email_verification_window_sec,
        )
        if not limited_ip and not limited_email and email:
            user = db.query(user_model).filter(user_model.email == email).first()
            if user and not is_user_email_verified(user):
                try:
                    send_user_verification_email(request, db, user, force_new_token=True)
                    audit_security_event("email_verify_resend", request, success=True, email=email, user_id=user.id)
                except email_delivery_error:
                    logger.exception("Could not resend verification email to %s", user.email)
            else:
                audit_security_event("email_verify_resend", request, success=True, email=email, detail="ignored")
        else:
            audit_security_event("email_verify_resend", request, success=False, email=email, detail="rate_limited")
        return templates.TemplateResponse(
            "verify_email_resend.html",
            {
                "request": request,
                "success": True,
                "message": "Если аккаунт существует и ещё не подтверждён, мы отправили новое письмо.",
            },
        )
