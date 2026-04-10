from datetime import datetime
from app_support.time_support import utc_now_naive

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_receipt_action_routes(
    app,
    *,
    get_db,
    get_current_user,
    ensure_company_user,
    is_manager,
    can_access_receipt,
    get_company_receipt_or_404,
    safe_next,
    parse_receipt_amount,
    parse_receipt_date,
    delete_stored_file,
    receipt_status_enum,
    receipt_model,
    receipt_file_model,
    project_model,
    payment_card_model,
    role_enum,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.post("/web/receipts/{receipt_id}/status")
    async def web_receipt_update_status(
        receipt_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        receipt = get_company_receipt_or_404(db, user, receipt_id)
        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web/receipts")
        status_raw = (form.get("status") or "").strip()
        try:
            new_status = receipt_status_enum(status_raw)
        except ValueError:
            return RedirectResponse(url="/web/receipts?err=bad_status", status_code=http_303_see_other)
        receipt.status = new_status
        receipt.updated_at = utc_now_naive()
        if new_status in (receipt_status_enum.accepted, receipt_status_enum.rejected):
            receipt.processed_at = utc_now_naive()
            receipt.processed_by = user.id
        else:
            receipt.processed_at = None
            receipt.processed_by = None
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/receipts?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url=next_url, status_code=http_303_see_other)

    @app.post("/web/receipts/{receipt_id}/edit")
    async def web_receipt_edit(
        receipt_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)
        receipt = get_company_receipt_or_404(db, user, receipt_id)
        if not can_access_receipt(user, receipt):
            raise HTTPException(403, "Forbidden")
        if receipt.created_by != user.id:
            raise HTTPException(403, "Forbidden")

        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web/receipts?mode=field")
        success_url = f"{next_url}&ok=updated" if "?" in next_url else f"{next_url}?ok=updated"
        project_id_raw = (form.get("project_id") or "").strip()
        card_id_raw = (form.get("card_id") or "").strip()
        comment = (form.get("comment") or "").strip()
        category = (form.get("category") or "").strip() or None
        supplier = (form.get("supplier") or "").strip() or None
        amount = parse_receipt_amount(form.get("amount"))
        receipt_date = parse_receipt_date(form.get("receipt_date"))

        if not project_id_raw or not card_id_raw:
            return RedirectResponse(url="/web/receipts?err=missing_required", status_code=http_303_see_other)
        if (form.get("amount") or "").strip() and amount is None:
            return RedirectResponse(url="/web/receipts?err=bad_amount", status_code=http_303_see_other)
        try:
            project_id = int(project_id_raw)
            card_id = int(card_id_raw)
        except ValueError:
            return RedirectResponse(url="/web/receipts?err=bad_links", status_code=http_303_see_other)

        project_exists = (
            db.query(project_model.id)
            .filter(project_model.id == project_id, project_model.company_id == user.company_id)
            .first()
        )
        card_exists = (
            db.query(payment_card_model.id)
            .filter(
                payment_card_model.id == card_id,
                payment_card_model.company_id == user.company_id,
                payment_card_model.owner_user_id == user.id,
                payment_card_model.is_active.is_(True),
            )
            .first()
        )
        if not project_exists or not card_exists:
            return RedirectResponse(url="/web/receipts?err=bad_links", status_code=http_303_see_other)

        receipt.project_id = project_id
        receipt.card_id = card_id
        receipt.comment = comment or ""
        receipt.amount = amount
        receipt.receipt_date = receipt_date
        receipt.category = category
        receipt.supplier = supplier
        receipt.updated_at = utc_now_naive()
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/receipts?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url=success_url, status_code=http_303_see_other)

    @app.post("/web/receipts/{receipt_id}/delete")
    async def web_receipt_delete(
        receipt_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)
        receipt = get_company_receipt_or_404(db, user, receipt_id)
        if not can_access_receipt(user, receipt):
            raise HTTPException(403, "Forbidden")
        if receipt.created_by != user.id:
            raise HTTPException(403, "Forbidden")

        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web/receipts?mode=field")
        success_url = f"{next_url}&ok=deleted" if "?" in next_url else f"{next_url}?ok=deleted"
        files = db.query(receipt_file_model).filter(receipt_file_model.receipt_id == receipt.id).all()
        for file_row in files:
            delete_stored_file(file_row.file_path)
        db.query(receipt_file_model).filter(receipt_file_model.receipt_id == receipt.id).delete(synchronize_session=False)
        db.delete(receipt)
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/receipts?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url=success_url, status_code=http_303_see_other)

    @app.post("/web/receipts/delete/bulk")
    async def web_receipt_bulk_delete(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web/receipts?mode=accounting")
        success_url = f"{next_url}&ok=deleted" if "?" in next_url else f"{next_url}?ok=deleted"

        receipt_ids = []
        for raw_id in form.getlist("receipt_ids"):
            try:
                receipt_ids.append(int((raw_id or "").strip()))
            except (TypeError, ValueError):
                continue
        if not receipt_ids:
            return RedirectResponse(url=next_url, status_code=http_303_see_other)

        receipts = (
            db.query(receipt_model)
            .filter(receipt_model.company_id == user.company_id, receipt_model.id.in_(receipt_ids))
            .all()
        )
        if not receipts:
            return RedirectResponse(url=next_url, status_code=http_303_see_other)

        found_ids = [item.id for item in receipts]
        files = db.query(receipt_file_model).filter(receipt_file_model.receipt_id.in_(found_ids)).all()
        for file_row in files:
            delete_stored_file(file_row.file_path)
        db.query(receipt_file_model).filter(receipt_file_model.receipt_id.in_(found_ids)).delete(synchronize_session=False)
        db.query(receipt_model).filter(receipt_model.id.in_(found_ids)).delete(synchronize_session=False)
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/receipts?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url=success_url, status_code=http_303_see_other)

    @app.post("/web/receipts/status/bulk")
    async def web_receipt_bulk_status(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        form = await request.form()
        next_url = safe_next(form.get("next"), fallback="/web/receipts")
        status_raw = (form.get("status") or "").strip()
        try:
            new_status = receipt_status_enum(status_raw)
        except ValueError:
            return RedirectResponse(url="/web/receipts?err=bad_status", status_code=http_303_see_other)

        receipt_ids = []
        for raw_id in form.getlist("receipt_ids"):
            try:
                receipt_ids.append(int((raw_id or "").strip()))
            except (TypeError, ValueError):
                continue
        if not receipt_ids:
            return RedirectResponse(url=next_url, status_code=http_303_see_other)

        receipts = (
            db.query(receipt_model)
            .filter(receipt_model.company_id == user.company_id, receipt_model.id.in_(receipt_ids))
            .all()
        )
        now = utc_now_naive()
        for receipt in receipts:
            receipt.status = new_status
            receipt.updated_at = now
            if new_status in (receipt_status_enum.accepted, receipt_status_enum.rejected):
                receipt.processed_at = now
                receipt.processed_by = user.id
            else:
                receipt.processed_at = None
                receipt.processed_by = None
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(url="/web/receipts?err=save_failed", status_code=http_303_see_other)
        return RedirectResponse(url=next_url, status_code=http_303_see_other)
