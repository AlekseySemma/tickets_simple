import re

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


def register_receipt_routes(
    app,
    *,
    get_db,
    get_current_user,
    ensure_company_user,
    is_manager,
    build_receipts_query,
    parse_receipt_date,
    parse_receipt_amount,
    make_safe_upload_name,
    build_receipt_object_key,
    store_upload_file_to_storage_async,
    build_receipt_original_name,
    notify_receipt_created,
    delete_stored_file,
    templates,
    receipt_model,
    receipt_file_model,
    project_model,
    payment_card_model,
    user_model,
    receipt_status_enum,
    role_enum,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.get("/web/receipts")
    def web_receipts(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
        mode: str | None = None,
        status_filter: str | None = None,
        project_id: str | None = None,
        card_id: str | None = None,
        employee_id: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        q: str | None = None,
        edit_id: str | None = None,
    ):
        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)

        can_view_accounting_mode = bool(user.show_receipts_accounting_mode)
        default_receipts_mode = "accounting" if user.role in (role_enum.admin, role_enum.curator) else "field"
        mode_value = (mode or "").strip().lower()
        if mode_value not in {"field", "accounting"}:
            mode_value = default_receipts_mode
        if not can_view_accounting_mode:
            mode_value = "field"

        def parse_int(raw: str | None) -> int | None:
            value = (raw or "").strip()
            if not value:
                return None
            try:
                return int(value)
            except ValueError:
                return None

        project_id_int = parse_int(project_id)
        card_id_int = parse_int(card_id)
        employee_id_int = parse_int(employee_id)
        date_from_value = parse_receipt_date(date_from)
        date_to_value = parse_receipt_date(date_to)
        q_value = (q or "").strip()
        edit_id_int = parse_int(edit_id)

        projects = (
            db.query(project_model.id, project_model.name)
            .filter(project_model.company_id == user.company_id)
            .order_by(project_model.name.asc())
            .all()
        )
        cards = (
            db.query(payment_card_model.id, payment_card_model.name, payment_card_model.is_active)
            .filter(payment_card_model.company_id == user.company_id, payment_card_model.owner_user_id == user.id)
            .order_by(payment_card_model.name.asc())
            .all()
        )
        preferred_card_id = None
        if user.preferred_payment_card_id is not None:
            for card in cards:
                if int(card.id) == int(user.preferred_payment_card_id) and bool(card.is_active):
                    preferred_card_id = int(card.id)
                    break
        employees = (
            db.query(user_model.id, user_model.name)
            .filter(user_model.company_id == user.company_id, user_model.role != role_enum.platform_admin)
            .order_by(user_model.name.asc())
            .all()
        )

        receipts = (
            build_receipts_query(
                db,
                user,
                status_filter=status_filter,
                project_id=project_id_int,
                card_id=card_id_int,
                employee_id=employee_id_int,
                date_from_value=date_from_value,
                date_to_value=date_to_value,
                q=q_value,
            )
            .limit(300)
            .all()
        )
        receipt_ids = [item.id for item in receipts]
        files = (
            db.query(receipt_file_model)
            .filter(receipt_file_model.receipt_id.in_(receipt_ids))
            .order_by(receipt_file_model.id.asc())
            .all()
            if receipt_ids
            else []
        )
        files_by_receipt: dict[int, list] = {}
        for file_row in files:
            files_by_receipt.setdefault(file_row.receipt_id, []).append(file_row)

        projects_by_id = {int(row[0]): row[1] for row in projects}
        cards_by_id = {int(row[0]): row[1] for row in cards}
        visible_card_ids = {int(item.card_id) for item in receipts if getattr(item, "card_id", None) is not None}
        cards_for_display = list(cards)
        if visible_card_ids:
            cards_for_display = (
                db.query(payment_card_model.id, payment_card_model.name, payment_card_model.is_active)
                .filter(payment_card_model.company_id == user.company_id, payment_card_model.id.in_(visible_card_ids))
                .all()
            )
        cards_last4_by_id: dict[int, str] = {}
        for row in cards_for_display:
            card_id_value = int(row[0])
            card_name = str(row[1] or "")
            only_digits = re.sub(r"\D+", "", card_name)
            cards_last4_by_id[card_id_value] = only_digits[-4:] if len(only_digits) >= 4 else card_name or f"#{card_id_value}"
        users_by_id = {int(row[0]): row[1] for row in employees}
        status_options = [status.value for status in receipt_status_enum]

        ok = (request.query_params.get("ok") or "").strip().lower()
        err = (request.query_params.get("err") or "").strip().lower()
        if ok not in {"created", "card_created", "status_updated", "bulk_updated", "updated", "deleted"}:
            ok = ""
        if err not in {"missing_required", "bad_links", "bad_amount", "missing_files", "save_failed", "card_exists", "bad_status"}:
            err = ""

        return templates.TemplateResponse(
            request,
            "receipts.html",
            {
                "request": request,
                "user": user,
                "mode": mode_value,
                "receipts": receipts,
                "files_by_receipt": files_by_receipt,
                "projects": projects,
                "cards": cards,
                "employees": employees,
                "projects_by_id": projects_by_id,
                "cards_by_id": cards_by_id,
                "cards_last4_by_id": cards_last4_by_id,
                "users_by_id": users_by_id,
                "status_options": status_options,
                "status_filter": status_filter or "",
                "project_id_filter": project_id_int if project_id_int is not None else "",
                "card_id_filter": card_id_int if card_id_int is not None else "",
                "employee_id_filter": employee_id_int if employee_id_int is not None else "",
                "date_from_filter": date_from_value.isoformat() if date_from_value else "",
                "date_to_filter": date_to_value.isoformat() if date_to_value else "",
                "q_filter": q_value,
                "edit_id": edit_id_int if edit_id_int is not None else 0,
                "ok": ok,
                "err": err,
                "can_manage_cards": is_manager(user),
                "can_manage_status": is_manager(user),
                "can_view_accounting_mode": can_view_accounting_mode,
                "preferred_card_id": preferred_card_id,
            },
        )

    @app.post("/web/receipts/create")
    async def web_receipts_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)
        form = await request.form()
        project_id_raw = (form.get("project_id") or "").strip()
        card_id_raw = (form.get("card_id") or "").strip()
        comment = (form.get("comment") or "").strip()
        category = (form.get("category") or "").strip() or None
        supplier = (form.get("supplier") or "").strip() or None
        amount = parse_receipt_amount(form.get("amount"))
        receipt_date = parse_receipt_date(form.get("receipt_date"))
        uploads = [
            item
            for item in form.getlist("files")
            if hasattr(item, "filename") and ((getattr(item, "filename", "") or "").strip())
        ]

        if not project_id_raw or not card_id_raw:
            return RedirectResponse(url="/web/receipts?err=missing_required", status_code=http_303_see_other)
        if not uploads:
            return RedirectResponse(url="/web/receipts?err=missing_files&mode=field", status_code=http_303_see_other)
        if (form.get("amount") or "").strip() and amount is None:
            return RedirectResponse(url="/web/receipts?err=bad_amount&mode=field", status_code=http_303_see_other)

        try:
            project_id = int(project_id_raw)
            card_id = int(card_id_raw)
        except ValueError:
            return RedirectResponse(url="/web/receipts?err=bad_links", status_code=http_303_see_other)

        project_row = (
            db.query(project_model.id, project_model.name)
            .filter(project_model.id == project_id, project_model.company_id == user.company_id)
            .first()
        )
        card_row = (
            db.query(payment_card_model.id, payment_card_model.name)
            .filter(
                payment_card_model.id == card_id,
                payment_card_model.company_id == user.company_id,
                payment_card_model.owner_user_id == user.id,
                payment_card_model.is_active.is_(True),
            )
            .first()
        )
        if not project_row or not card_row:
            return RedirectResponse(url="/web/receipts?err=bad_links", status_code=http_303_see_other)
        project_name = str(project_row[1] or "")
        card_name = str(card_row[1] or "")

        written_paths: list[str] = []
        try:
            receipt = receipt_model(
                company_id=user.company_id,
                project_id=project_id,
                card_id=card_id,
                created_by=user.id,
                status=receipt_status_enum.new,
                comment=comment or "",
                amount=amount,
                receipt_date=receipt_date,
                category=category,
                supplier=supplier,
            )
            db.add(receipt)
            db.flush()
            for upload in uploads:
                safe_name = make_safe_upload_name(upload.filename, ticket_id=receipt.id)
                object_key = build_receipt_object_key(safe_name)
                stored_path, file_hash, file_size = await store_upload_file_to_storage_async(upload, object_key)
                written_paths.append(stored_path)
                display_name = build_receipt_original_name(
                    receipt_date_value=receipt.receipt_date,
                    card_name=card_name,
                    project_name=project_name,
                    source_filename=upload.filename,
                    fallback_card_id=card_id,
                )
                db.add(
                    receipt_file_model(
                        receipt_id=receipt.id,
                        uploader_id=user.id,
                        file_path=stored_path,
                        original_name=display_name[:255] or None,
                        file_size_bytes=file_size,
                        file_sha256=file_hash,
                    )
                )
            notify_receipt_created(db=db, receipt=receipt, actor=user)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            for path in written_paths:
                delete_stored_file(path)
            return RedirectResponse(url="/web/receipts?err=save_failed", status_code=http_303_see_other)

        return RedirectResponse(url="/web/receipts?ok=created&mode=field", status_code=http_303_see_other)
