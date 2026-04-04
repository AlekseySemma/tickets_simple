from fastapi import Depends, HTTPException, Request


def register_users_api_routes(
    app,
    *,
    get_db,
    get_current_user,
    require_role,
    ensure_company_user,
    normalize_bk_last4,
    normalize_role_label,
    normalize_capability_flags,
    hash_password,
    prepare_user_email_verification,
    send_user_verification_email,
    logger,
    user_model,
    role_enum,
    user_create_model,
    user_out_model,
    email_delivery_error,
):
    @app.get("/users/me", response_model=user_out_model)
    def me(user=Depends(get_current_user)):
        return user

    @app.post("/users", response_model=user_out_model)
    def create_user(
        payload: user_create_model,
        request: Request,
        db=Depends(get_db),
        _admin=Depends(require_role(role_enum.admin)),
    ):
        ensure_company_user(_admin)
        if db.query(user_model).filter(user_model.email == payload.email).first():
            raise HTTPException(400, "Email already exists")
        if payload.role not in (role_enum.curator, role_enum.executor):
            raise HTTPException(400, "Only CURATOR or EXECUTOR can be created")
        bk_last4 = normalize_bk_last4(payload.bk_last4)
        if payload.bk_last4 and bk_last4 is None:
            raise HTTPException(422, "bk_last4 must contain exactly 4 digits")
        capability_flags = normalize_capability_flags(
            payload.role,
            show_receipts_accounting_mode=payload.show_receipts_accounting_mode,
            is_assignable_executor=payload.is_assignable_executor,
            can_view_all_tickets=payload.can_view_all_tickets,
            can_create_tickets=payload.can_create_tickets,
            can_close_tickets=payload.can_close_tickets,
        )
        item = user_model(
            email=payload.email,
            name=payload.name,
            password_hash=hash_password(payload.password),
            role=payload.role,
            company_id=_admin.company_id,
            bk_last4=bk_last4,
            preferred_payment_card_id=None,
            role_label=normalize_role_label(payload.role_label),
            notify_receipt_created=(
                bool(payload.notify_receipt_created)
                if payload.notify_receipt_created is not None
                else True
            ),
            **capability_flags,
        )
        prepare_user_email_verification(item, force_new_token=True)
        db.add(item)
        db.commit()
        db.refresh(item)
        try:
            send_user_verification_email(request, db, item)
        except email_delivery_error:
            logger.exception("Could not send verification email to %s", item.email)
        return item
