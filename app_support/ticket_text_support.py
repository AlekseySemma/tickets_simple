class TicketTextSupport:
    def __init__(
        self,
        *,
        fix_mojibake_text_func,
        format_deadline_func,
        re_module,
        ticket_log_model,
        notification_model,
        user_model,
        project_model,
        ticket_type_model,
        department_model,
        log_action_changed: str,
        log_action_created_from_template: str,
        log_action_created: str,
        log_action_deadline_changed: str,
        log_action_executor_changed: str,
        log_action_project_changed: str,
        log_action_ticket_type_changed: str,
        log_action_target_unit_changed: str,
        log_action_template_changed: str,
        log_action_template_period_changed: str,
        log_action_file_added: str,
        log_action_file_deleted: str,
        notification_ticket_title_preview_len: int,
    ):
        self.fix_mojibake_text_func = fix_mojibake_text_func
        self.format_deadline_func = format_deadline_func
        self.re_module = re_module
        self.ticket_log_model = ticket_log_model
        self.notification_model = notification_model
        self.user_model = user_model
        self.project_model = project_model
        self.ticket_type_model = ticket_type_model
        self.department_model = department_model
        self.log_action_changed = log_action_changed
        self.log_action_created_from_template = log_action_created_from_template
        self.log_action_created = log_action_created
        self.log_action_deadline_changed = log_action_deadline_changed
        self.log_action_executor_changed = log_action_executor_changed
        self.log_action_project_changed = log_action_project_changed
        self.log_action_ticket_type_changed = log_action_ticket_type_changed
        self.log_action_target_unit_changed = log_action_target_unit_changed
        self.log_action_template_changed = log_action_template_changed
        self.log_action_template_period_changed = log_action_template_period_changed
        self.log_action_file_added = log_action_file_added
        self.log_action_file_deleted = log_action_file_deleted
        self.notification_ticket_title_preview_len = int(notification_ticket_title_preview_len)

    def ticket_field_change_log_action(self, field_label: str, old_value: str | None, new_value: str | None) -> str:
        old_text = (old_value or "").strip() or "-"
        new_text = (new_value or "").strip() or "-"
        return f"Изменение {field_label}: {old_text} -> {new_text}"

    def ticket_user_name(self, db, user_id: int | None) -> str | None:
        if not user_id:
            return None
        row = db.get(self.user_model, user_id)
        if row and (row.name or "").strip():
            return row.name
        return f"#{user_id}"

    def ticket_project_name(self, db, project_id: int | None) -> str | None:
        if not project_id:
            return None
        row = db.get(self.project_model, project_id)
        if row and (row.name or "").strip():
            return row.name
        return f"#{project_id}"

    def ticket_type_name(self, db, ticket_type_id: int | None) -> str | None:
        if not ticket_type_id:
            return None
        row = db.get(self.ticket_type_model, ticket_type_id)
        if row and (row.name or "").strip():
            return row.name
        return f"#{ticket_type_id}"

    def department_name(self, db, department_id: int | None) -> str | None:
        if not department_id:
            return None
        row = db.get(self.department_model, department_id)
        if row and (row.name or "").strip():
            return row.name
        return f"#{department_id}"

    def ticket_deadline_text(self, value) -> str | None:
        return self.format_deadline_func(value) if value else None

    def ticket_title_notification_preview(
        self,
        ticket_title: str | None,
        *,
        ticket_id: int | None = None,
        max_len: int | None = None,
    ) -> str:
        effective_max_len = self.notification_ticket_title_preview_len if max_len is None else int(max_len)
        preview = self.fix_mojibake_text_func((ticket_title or "").strip())
        if preview:
            if effective_max_len > 3 and len(preview) > effective_max_len:
                preview = preview[: effective_max_len - 3].rstrip() + "..."
            return preview
        if ticket_id is not None:
            return f"заявка #{ticket_id}"
        return "заявка"

    def ticket_notification_title(self, prefix: str, ticket_title: str | None, *, ticket_id: int | None = None) -> str:
        return f"{prefix}: {self.ticket_title_notification_preview(ticket_title, ticket_id=ticket_id)}"

    def is_placeholder_log_action(self, value: str | None) -> bool:
        text = (value or "").strip()
        if not text:
            return True
        meaningful = self.re_module.sub(r"[\s\?\!\.,:;\'\"`\-_/\\|()\[\]{}<>+=*#%&~@]+", "", text)
        return not meaningful

    def normalize_log_action(self, action: str | None) -> str:
        raw = (action or "").strip()
        fixed_raw = self.fix_mojibake_text_func(raw).strip()
        text = fixed_raw.lower()
        if not raw:
            return self.log_action_changed
        merged = f"{raw.lower()} {text}"
        escaped = raw.encode("unicode_escape").decode("ascii").lower()

        escaped_map = {
            "\\u0421\\u0403\\u0420\\u0455\\u0420\\xb7\\u0420\\u0491\\u0420\\xb0\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0420\\u0455 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0421\\u0453": self.log_action_created_from_template,
            "\\u0421\\u0403\\u0420\\u0455\\u0420\\xb7\\u0420\\u0491\\u0420\\xb0\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5": self.log_action_created,
            "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u0403\\u0421\\u0402\\u0420\\u0455\\u0420\\u0454\\u0420\\xb0": self.log_action_deadline_changed,
            "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0451\\u0421\\u0403\\u0420\\u0457\\u0420\\u0455\\u0420\\xbb\\u0420\\u0405\\u0420\\u0451\\u0421\\u201a\\u0420\\xb5\\u0420\\xbb\\u0421\\u040f": self.log_action_executor_changed,
            "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0421\\u0402\\u0420\\u0455\\u0420\\xb5\\u0420\\u0454\\u0421\\u201a\\u0420\\xb0": self.log_action_project_changed,
            "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u201a\\u0420\\u0451\\u0420\\u0457\\u0420\\xb0 \\u0420\\xb7\\u0420\\xb0\\u0421\\u040f\\u0420\\u0406\\u0420\\u0454\\u0420\\u0451": self.log_action_ticket_type_changed,
            "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u2020\\u0420\\xb5\\u0420\\xbb\\u0420\\xb5\\u0420\\u0406\\u0420\\u0455\\u0420\\u0456\\u0420\\u0455 \\u0421\\u0453\\u0420\\xb7\\u0420\\xbb\\u0420\\xb0": self.log_action_target_unit_changed,
            "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0420\\xb0 \\u0420\\xb7\\u0420\\xb0\\u0421\\u040f\\u0420\\u0406\\u0420\\u0454\\u0420\\u0451": self.log_action_template_changed,
            "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0420\\xb5\\u0421\\u0402\\u0420\\u0451\\u0420\\u0455\\u0420\\u0491\\u0420\\xb0 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0420\\xb0": self.log_action_template_period_changed,
            "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5": self.log_action_changed,
            "\\u0420\\u0491\\u0420\\u0455\\u0420\\xb1\\u0420\\xb0\\u0420\\u0406\\u0420\\xbb\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u201e\\u0420\\xb0\\u0420\\u2116\\u0420\\xbb\\u0420\\xb0": self.log_action_file_added,
            "\\u0423\\u0434\\u0430\\u043b\\u0435\\u043d\\u0438\\u0435 \\u0444\\u0430\\u0439\\u043b\\u0430": self.log_action_file_deleted,
        }
        if escaped in escaped_map:
            return escaped_map[escaped]
        if fixed_raw and ("->" in fixed_raw or "\u2192" in fixed_raw):
            return fixed_raw

        if self.is_placeholder_log_action(raw) or self.is_placeholder_log_action(text):
            return self.log_action_changed

        k_create = "созд"
        k_template = "шабл"
        k_deadline = "срок"
        k_executor = "исполн"
        k_project = "проект"
        k_type = "тип"
        k_ticket = "заяв"
        k_unit = "узл"
        k_period = "период"
        k_file = "файл"
        k_delete = "удал"
        k_status = "статус"
        k_change = "измен"

        if k_create in merged:
            if k_template in merged:
                return self.log_action_created_from_template
            return self.log_action_created
        if k_deadline in merged:
            return self.log_action_deadline_changed
        if k_executor in merged:
            return self.log_action_executor_changed
        if k_project in merged:
            return self.log_action_project_changed
        if k_type in merged and k_ticket in merged:
            return self.log_action_ticket_type_changed
        if k_unit in merged:
            return self.log_action_target_unit_changed
        if k_period in merged and k_template in merged:
            return self.log_action_template_period_changed
        if k_template in merged:
            return self.log_action_template_changed
        if k_delete in merged and k_file in merged:
            return self.log_action_file_deleted
        if k_file in merged or "file" in merged:
            return self.log_action_file_added
        if k_status in merged:
            if "->" in fixed_raw or "\u2192" in fixed_raw:
                return fixed_raw
            return "изменение статуса"
        if k_change in merged:
            return self.log_action_changed
        return text if not self.is_placeholder_log_action(text) else self.log_action_changed

    def add_ticket_log(self, db, ticket_id: int, actor_id: int, action: str) -> None:
        db.add(
            self.ticket_log_model(
                ticket_id=ticket_id,
                actor_id=actor_id,
                action=self.normalize_log_action(action),
            )
        )

    def repair_mojibake_data(self, db) -> int:
        fixed = 0

        notifications = db.query(self.notification_model).all()
        for item in notifications:
            new_title = self.fix_mojibake_text_func(item.title or "")
            new_body = self.fix_mojibake_text_func(item.body or "") if item.body else None
            if new_title != (item.title or ""):
                item.title = new_title
                fixed += 1
            if new_body != item.body:
                item.body = new_body
                fixed += 1

        logs = db.query(self.ticket_log_model).all()
        for row in logs:
            new_action = self.normalize_log_action(row.action or "")
            if new_action != (row.action or ""):
                row.action = new_action
                fixed += 1

        if fixed:
            db.commit()
        return fixed
