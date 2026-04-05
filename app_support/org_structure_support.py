class OrgStructureSupport:
    def __init__(
        self,
        *,
        func_module,
        user_model,
        role_enum,
        unit_type_model,
        org_unit_model,
    ):
        self.func_module = func_module
        self.user_model = user_model
        self.role_enum = role_enum
        self.unit_type_model = unit_type_model
        self.org_unit_model = org_unit_model

    def get_or_create_unit_type(self, db, company_id: int, type_name: str):
        normalized = (type_name or "").strip() or "Узел"
        existing = (
            db.query(self.unit_type_model)
            .filter(
                self.unit_type_model.company_id == company_id,
                self.func_module.lower(self.unit_type_model.name) == normalized.lower(),
            )
            .first()
        )
        if existing:
            if not existing.is_active:
                existing.is_active = True
            return existing

        base_code = normalized.lower().replace(" ", "_")[:40] or "unit"
        code = base_code
        suffix = 2
        while (
            db.query(self.unit_type_model.id)
            .filter(self.unit_type_model.company_id == company_id, self.unit_type_model.code == code)
            .first()
            is not None
        ):
            code = f"{base_code}_{suffix}"
            suffix += 1

        item = self.unit_type_model(
            company_id=company_id,
            name=normalized,
            code=code,
            is_active=True,
        )
        db.add(item)
        db.flush()
        return item

    def parse_bool_text(self, raw: str | None, default: bool = True) -> bool:
        value = (raw or "").strip().lower()
        if not value:
            return default
        if value in {"1", "true", "yes", "y", "on", "да"}:
            return True
        if value in {"0", "false", "no", "n", "off", "нет"}:
            return False
        return default

    def parse_optional_int(self, raw_value: str | int | None) -> int | None:
        if raw_value is None:
            return None
        if isinstance(raw_value, int):
            return raw_value
        value = str(raw_value).strip()
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    def query_assignable_company_users(self, db, company_id: int):
        return (
            db.query(
                self.user_model.id,
                self.user_model.name,
                self.user_model.email,
                self.user_model.role,
                self.user_model.role_label,
            )
            .filter(
                self.user_model.company_id == company_id,
                self.user_model.role != self.role_enum.platform_admin,
                self.user_model.is_assignable_executor.is_(True),
            )
        )

    def get_assignable_company_user_ids(self, db, company_id: int) -> set[int]:
        return {int(row[0]) for row in self.query_assignable_company_users(db, company_id).with_entities(self.user_model.id).all()}

    def build_unit_parent_map(self, db, company_id: int) -> dict[int, int | None]:
        rows = db.query(self.org_unit_model.id, self.org_unit_model.parent_id).filter(self.org_unit_model.company_id == company_id).all()
        return {int(row[0]): (int(row[1]) if row[1] is not None else None) for row in rows}

    def would_create_unit_cycle(self, parent_map: dict[int, int | None], unit_id: int, new_parent_id: int | None) -> bool:
        current = new_parent_id
        visited: set[int] = set()
        while current is not None and current not in visited:
            if current == unit_id:
                return True
            visited.add(current)
            current = parent_map.get(current)
        return False
