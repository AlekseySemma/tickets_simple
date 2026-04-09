class RoleFlagsSupport:
    def __init__(
        self,
        *,
        max_role_label_len: int,
        max_role_template_name_len: int,
        manager_roles,
        role_enum,
    ):
        self.max_role_label_len = int(max_role_label_len)
        self.max_role_template_name_len = int(max_role_template_name_len)
        self.manager_roles = manager_roles
        self.role_enum = role_enum

    def normalize_role_label(self, raw_value: str | None) -> str | None:
        value = " ".join(str(raw_value or "").split()).strip()
        if not value:
            return None
        return value[: self.max_role_label_len]

    def normalize_role_template_name(self, raw_value: str | None) -> str | None:
        value = " ".join(str(raw_value or "").split()).strip()
        if not value:
            return None
        return value[: self.max_role_template_name_len]

    def default_is_assignable_executor(self, role) -> bool:
        return role in (self.role_enum.admin, self.role_enum.executor)

    def default_show_receipts_accounting_mode(self, role) -> bool:
        return role != self.role_enum.executor

    def normalize_capability_flags(
        self,
        access_level,
        *,
        show_receipts_accounting_mode: bool | None = None,
        is_assignable_executor: bool | None = None,
        can_view_all_tickets: bool | None = None,
        can_create_tickets: bool | None = None,
        can_close_tickets: bool | None = None,
    ) -> dict[str, bool]:
        normalized = {
            "show_receipts_accounting_mode": (
                self.default_show_receipts_accounting_mode(access_level)
                if show_receipts_accounting_mode is None
                else bool(show_receipts_accounting_mode)
            ),
            "is_assignable_executor": (
                self.default_is_assignable_executor(access_level)
                if is_assignable_executor is None
                else bool(is_assignable_executor)
            ),
            "can_view_all_tickets": bool(can_view_all_tickets),
            "can_create_tickets": True if can_create_tickets is None else bool(can_create_tickets),
            "can_close_tickets": True if can_close_tickets is None else bool(can_close_tickets),
        }
        if access_level in self.manager_roles:
            normalized["can_view_all_tickets"] = True
            normalized["can_create_tickets"] = True
            normalized["can_close_tickets"] = True
        if access_level == self.role_enum.platform_admin:
            normalized["show_receipts_accounting_mode"] = True
            normalized["is_assignable_executor"] = False
            normalized["can_view_all_tickets"] = False
            normalized["can_create_tickets"] = False
            normalized["can_close_tickets"] = False
        return normalized
