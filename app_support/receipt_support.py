from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
import re


class ReceiptSupport:
    def __init__(
        self,
        *,
        datetime_cls,
        decimal_cls,
        invalid_operation_cls,
        path_cls,
        re_module,
        cast_fn,
        date_type,
        or_fn,
        receipt_model,
        receipt_status_enum,
        role_enum,
    ):
        self.datetime_cls = datetime_cls
        self.decimal_cls = decimal_cls
        self.invalid_operation_cls = invalid_operation_cls
        self.path_cls = path_cls
        self.re_module = re_module
        self.cast_fn = cast_fn
        self.date_type = date_type
        self.or_fn = or_fn
        self.receipt_model = receipt_model
        self.receipt_status_enum = receipt_status_enum
        self.role_enum = role_enum

    def parse_receipt_date(self, raw: str | None):
        value = (raw or "").strip()
        if not value:
            return None
        try:
            return self.datetime_cls.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return None

    def parse_receipt_amount(self, raw: str | None):
        value = (raw or "").strip().replace(",", ".")
        if not value:
            return None
        try:
            amount = self.decimal_cls(value)
        except self.invalid_operation_cls:
            return None
        if amount < 0:
            return None
        return amount.quantize(self.decimal_cls("0.01"))

    def normalize_bk_last4(self, raw: str | None) -> str | None:
        digits = self.re_module.sub(r"\D+", "", (raw or "").strip())
        if not digits:
            return None
        if len(digits) != 4:
            return None
        return digits

    def sanitize_export_token(self, raw: str | None, max_len: int = 40) -> str:
        value = self.re_module.sub(r"[^0-9A-Za-z._-]+", "_", (raw or "").strip())
        value = value.strip("._-")
        if not value:
            return "item"
        return value[:max_len]

    def sanitize_filename_part(self, raw: str | None, max_len: int = 80) -> str:
        value = (raw or "").strip()
        value = self.re_module.sub(r'[\\/:*?"<>|\r\n\t]+', "_", value)
        value = self.re_module.sub(r"\s+", " ", value).strip(" ._-")
        if not value:
            return "Объект"
        return value[:max_len]

    def build_receipt_original_name(
        self,
        *,
        receipt_date_value,
        card_name: str | None,
        project_name: str | None,
        source_filename: str | None,
        fallback_card_id: int,
    ) -> str:
        ext = self.path_cls(source_filename or "").suffix.lower()[:10] or ".bin"
        dt_token = (receipt_date_value or self.datetime_cls.utcnow().date()).isoformat()
        digits = self.re_module.sub(r"\D+", "", (card_name or "").strip())
        card_last4 = digits[-4:] if len(digits) >= 4 else f"{int(fallback_card_id):04d}"[-4:]
        project_token = self.sanitize_filename_part(project_name, max_len=80)
        return f"{dt_token}_БК{card_last4}_{project_token}{ext}"

    def build_receipts_query(
        self,
        db,
        user,
        *,
        status_filter: str | None = None,
        project_id: int | None = None,
        card_id: int | None = None,
        employee_id: int | None = None,
        date_from_value=None,
        date_to_value=None,
        q: str | None = None,
    ):
        query = db.query(self.receipt_model).filter(self.receipt_model.company_id == user.company_id)
        if user.role == self.role_enum.executor:
            query = query.filter(self.receipt_model.created_by == user.id)

        if status_filter:
            try:
                query = query.filter(self.receipt_model.status == self.receipt_status_enum(status_filter))
            except ValueError:
                pass
        if project_id is not None:
            query = query.filter(self.receipt_model.project_id == project_id)
        if card_id is not None:
            query = query.filter(self.receipt_model.card_id == card_id)
        if employee_id is not None:
            query = query.filter(self.receipt_model.created_by == employee_id)
        if date_from_value is not None:
            query = query.filter(self.cast_fn(self.receipt_model.created_at, self.date_type) >= date_from_value)
        if date_to_value is not None:
            query = query.filter(self.cast_fn(self.receipt_model.created_at, self.date_type) <= date_to_value)
        if q:
            like = f"%{q}%"
            query = query.filter(
                self.or_fn(
                    self.receipt_model.comment.ilike(like),
                    self.receipt_model.category.ilike(like),
                    self.receipt_model.supplier.ilike(like),
                )
            )

        return query.order_by(self.receipt_model.id.desc())

    def resolve_preferred_card_id(self, cards, bk_last4: str | None) -> int | None:
        digits = self.normalize_bk_last4(bk_last4)
        if not digits:
            return None
        fallback_match_id: int | None = None
        for card in cards:
            if not getattr(card, "is_active", True):
                continue
            card_name_digits = self.re_module.sub(r"\D+", "", str(getattr(card, "name", "")))
            if not card_name_digits:
                continue
            if card_name_digits.endswith(digits):
                return int(getattr(card, "id"))
            if fallback_match_id is None and digits in card_name_digits:
                fallback_match_id = int(getattr(card, "id"))
        return fallback_match_id
