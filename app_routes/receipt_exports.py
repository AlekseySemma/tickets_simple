import csv
import io
import zipfile
from datetime import datetime
from pathlib import Path

from fastapi import Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse


def register_receipt_export_routes(
    app,
    *,
    get_db,
    get_current_user,
    ensure_company_user,
    can_access_receipt,
    get_company_receipt_or_404,
    parse_receipt_date,
    get_storage_basename,
    serve_stored_file_response,
    build_receipts_query,
    read_stored_file_bytes,
    sanitize_export_token,
    receipt_status_label_ru,
    receipt_file_model,
    project_model,
    payment_card_model,
    user_model,
    role_enum,
):
    @app.get("/web/receipt-files/{file_id}")
    def web_receipt_file_download(
        file_id: int,
        download: int | None = None,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        file_row = db.get(receipt_file_model, file_id)
        if not file_row:
            raise HTTPException(404, "Receipt file not found")
        receipt = get_company_receipt_or_404(db, user, file_row.receipt_id)
        if not can_access_receipt(user, receipt):
            raise HTTPException(403, "Forbidden")
        display_name = ((file_row.original_name or "").strip() or get_storage_basename(file_row.file_path) or "file")[:255]
        disposition = "attachment" if str(download or "").strip() == "1" else "inline"
        return serve_stored_file_response(file_row.file_path, display_name, disposition, "File not found")

    @app.get("/web/receipts/export.xlsx")
    def web_receipts_export_xlsx(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
        status_filter: str | None = None,
        project_id: str | None = None,
        card_id: str | None = None,
        employee_id: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        q: str | None = None,
    ):
        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)

        def parse_int(raw: str | None) -> int | None:
            value = (raw or "").strip()
            if not value:
                return None
            try:
                return int(value)
            except ValueError:
                return None

        receipts = build_receipts_query(
            db,
            user,
            status_filter=status_filter,
            project_id=parse_int(project_id),
            card_id=parse_int(card_id),
            employee_id=parse_int(employee_id),
            date_from_value=parse_receipt_date(date_from),
            date_to_value=parse_receipt_date(date_to),
            q=(q or "").strip(),
        ).all()
        ids = [item.id for item in receipts]
        first_files = {}
        if ids:
            for file_row in (
                db.query(receipt_file_model)
                .filter(receipt_file_model.receipt_id.in_(ids))
                .order_by(receipt_file_model.id.asc())
                .all()
            ):
                first_files.setdefault(file_row.receipt_id, file_row.id)
        projects = {
            int(row[0]): row[1]
            for row in db.query(project_model.id, project_model.name).filter(project_model.company_id == user.company_id).all()
        }
        cards = {
            int(row[0]): row[1]
            for row in (
                db.query(payment_card_model.id, payment_card_model.name)
                .filter(payment_card_model.company_id == user.company_id, payment_card_model.owner_user_id == user.id)
                .all()
            )
        }
        users = {
            int(row[0]): row[1]
            for row in db.query(user_model.id, user_model.name).filter(user_model.company_id == user.company_id).all()
        }
        base_url = str(request.base_url).rstrip("/")

        try:
            from openpyxl import Workbook  # type: ignore

            workbook = Workbook()
            worksheet = workbook.active
            worksheet.title = "Receipts"
            worksheet.append(["Дата", "Объект", "Карта", "Сотрудник", "Сумма", "Комментарий", "Статус", "Ссылка на файл"])
            for receipt in receipts:
                file_id = first_files.get(receipt.id)
                file_url = f"{base_url}/web/receipt-files/{file_id}?download=1" if file_id else ""
                worksheet.append(
                    [
                        receipt.receipt_date.isoformat() if receipt.receipt_date else receipt.created_at.date().isoformat(),
                        projects.get(receipt.project_id, f"#{receipt.project_id}"),
                        cards.get(receipt.card_id, f"#{receipt.card_id}"),
                        users.get(receipt.created_by, f"#{receipt.created_by}"),
                        float(receipt.amount) if receipt.amount is not None else None,
                        receipt.comment,
                        receipt_status_label_ru(receipt.status),
                        file_url,
                    ]
                )
            output = io.BytesIO()
            workbook.save(output)
            output.seek(0)
            filename = f"receipts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
            headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
            return StreamingResponse(
                output,
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers=headers,
            )
        except Exception:
            text_buffer = io.StringIO()
            writer = csv.writer(text_buffer, delimiter=";")
            writer.writerow(["Дата", "Объект", "Карта", "Сотрудник", "Сумма", "Комментарий", "Статус", "Ссылка на файл"])
            for receipt in receipts:
                file_id = first_files.get(receipt.id)
                file_url = f"{base_url}/web/receipt-files/{file_id}?download=1" if file_id else ""
                writer.writerow(
                    [
                        receipt.receipt_date.isoformat() if receipt.receipt_date else receipt.created_at.date().isoformat(),
                        projects.get(receipt.project_id, f"#{receipt.project_id}"),
                        cards.get(receipt.card_id, f"#{receipt.card_id}"),
                        users.get(receipt.created_by, f"#{receipt.created_by}"),
                        str(receipt.amount or ""),
                        receipt.comment,
                        receipt_status_label_ru(receipt.status),
                        file_url,
                    ]
                )
            payload = ("\ufeff" + text_buffer.getvalue()).encode("utf-8")
            filename = f"receipts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
            return Response(payload, media_type="text/csv; charset=utf-8", headers=headers)

    @app.get("/web/receipts/export.zip")
    def web_receipts_export_zip(
        db=Depends(get_db),
        user=Depends(get_current_user),
        status_filter: str | None = None,
        project_id: str | None = None,
        card_id: str | None = None,
        employee_id: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        q: str | None = None,
    ):
        if user.role not in (role_enum.admin, role_enum.curator, role_enum.executor):
            raise HTTPException(403, "Forbidden")
        ensure_company_user(user)

        def parse_int(raw: str | None) -> int | None:
            value = (raw or "").strip()
            if not value:
                return None
            try:
                return int(value)
            except ValueError:
                return None

        receipts = build_receipts_query(
            db,
            user,
            status_filter=status_filter,
            project_id=parse_int(project_id),
            card_id=parse_int(card_id),
            employee_id=parse_int(employee_id),
            date_from_value=parse_receipt_date(date_from),
            date_to_value=parse_receipt_date(date_to),
            q=(q or "").strip(),
        ).all()
        if not receipts:
            raise HTTPException(400, "No receipts for selected filters")
        receipt_ids = [item.id for item in receipts]
        files = (
            db.query(receipt_file_model)
            .filter(receipt_file_model.receipt_id.in_(receipt_ids))
            .order_by(receipt_file_model.receipt_id.asc(), receipt_file_model.id.asc())
            .all()
        )
        if not files:
            raise HTTPException(400, "No files for selected receipts")

        cards = {
            int(row[0]): row[1]
            for row in (
                db.query(payment_card_model.id, payment_card_model.name)
                .filter(payment_card_model.company_id == user.company_id, payment_card_model.owner_user_id == user.id)
                .all()
            )
        }
        receipts_by_id = {item.id: item for item in receipts}
        output = io.BytesIO()
        with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file_row in files:
                receipt = receipts_by_id.get(file_row.receipt_id)
                if not receipt:
                    continue
                payload_info = read_stored_file_bytes(file_row.file_path)
                if not payload_info:
                    continue
                payload, stored_name = payload_info
                ext = Path(file_row.original_name or stored_name).suffix.lower() or ".bin"
                dt_str = (receipt.receipt_date or receipt.created_at.date()).isoformat()
                card_name = sanitize_export_token(cards.get(receipt.card_id, f"card{receipt.card_id}"), max_len=24)
                comment = sanitize_export_token(receipt.comment, max_len=24)
                amount_token = sanitize_export_token(str(receipt.amount or ""), max_len=12)
                arcname = f"{dt_str}_{card_name}_{comment}_{amount_token}_r{receipt.id}_f{file_row.id}{ext}"
                archive.writestr(arcname, payload)
        output.seek(0)
        filename = f"receipts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return StreamingResponse(output, media_type="application/zip", headers=headers)
