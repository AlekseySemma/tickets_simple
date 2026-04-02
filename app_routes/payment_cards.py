from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_payment_card_routes(
    app,
    *,
    get_db,
    get_current_user,
    ensure_company_user,
    normalize_settings_section,
    build_settings_url,
    func,
    payment_card_model,
    receipt_model,
    user_model,
    role_enum,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.post("/web/payment-cards/create")
    async def web_payment_cards_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)
        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        name = (form.get("name") or "").strip()
        if not name:
            return RedirectResponse(
                url=build_settings_url(section, card_create_error="missing_required"),
                status_code=http_303_see_other,
            )
        exists = (
            db.query(payment_card_model.id)
            .filter(
                payment_card_model.company_id == user.company_id,
                payment_card_model.owner_user_id == user.id,
                func.lower(payment_card_model.name) == name.lower(),
            )
            .first()
        )
        if exists:
            return RedirectResponse(
                url=build_settings_url(section, card_create_error="card_exists"),
                status_code=http_303_see_other,
            )
        db.add(payment_card_model(company_id=user.company_id, owner_user_id=user.id, name=name, is_active=True))
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, card_create_error="save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=build_settings_url(section, card_created=True),
            status_code=http_303_see_other,
        )

    @app.post("/web/payment-cards/{card_id}/delete")
    async def web_payment_cards_delete(
        card_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)
        form = await request.form()
        section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
        card = db.get(payment_card_model, card_id)
        if not card or card.company_id != user.company_id or card.owner_user_id != user.id:
            return RedirectResponse(
                url=build_settings_url(section, card_delete_error="not_found"),
                status_code=http_303_see_other,
            )

        used_in_receipts = (
            db.query(receipt_model.id)
            .filter(receipt_model.company_id == user.company_id, receipt_model.card_id == card_id)
            .first()
        )
        used_in_user_defaults = (
            db.query(user_model.id)
            .filter(user_model.company_id == user.company_id, user_model.preferred_payment_card_id == card_id)
            .first()
        )
        if used_in_receipts or used_in_user_defaults:
            return RedirectResponse(
                url=build_settings_url(section, card_delete_error="in_use"),
                status_code=http_303_see_other,
            )
        try:
            db.delete(card)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_settings_url(section, card_delete_error="save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(
            url=build_settings_url(section, card_deleted=True),
            status_code=http_303_see_other,
        )
