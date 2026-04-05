class TicketSupport:
    def __init__(
        self,
        *,
        local_now,
        delete_stored_file_func,
        ensure_company_user_func,
        is_platform_admin_func,
        is_assignable_executor_user_func,
        max_ticket_title_len: int,
        http_exception_cls,
        re_module,
        datetime_cls,
        timedelta_cls,
        monthrange_func,
        user_model,
        ticket_model,
        ticket_watcher_model,
        project_model,
        ticket_type_model,
        department_model,
        org_unit_model,
        ticket_template_model,
        attachment_model,
        comment_model,
        comment_media_model,
        ticket_log_model,
        deadline_reminder_log_model,
        ticket_generation_key_model,
        unit_assignment_model,
        role_enum,
    ):
        self.local_now = local_now
        self.delete_stored_file_func = delete_stored_file_func
        self.ensure_company_user_func = ensure_company_user_func
        self.is_platform_admin_func = is_platform_admin_func
        self.is_assignable_executor_user_func = is_assignable_executor_user_func
        self.max_ticket_title_len = int(max_ticket_title_len)
        self.http_exception_cls = http_exception_cls
        self.re_module = re_module
        self.datetime_cls = datetime_cls
        self.timedelta_cls = timedelta_cls
        self.monthrange_func = monthrange_func
        self.user_model = user_model
        self.ticket_model = ticket_model
        self.ticket_watcher_model = ticket_watcher_model
        self.project_model = project_model
        self.ticket_type_model = ticket_type_model
        self.department_model = department_model
        self.org_unit_model = org_unit_model
        self.ticket_template_model = ticket_template_model
        self.attachment_model = attachment_model
        self.comment_model = comment_model
        self.comment_media_model = comment_media_model
        self.ticket_log_model = ticket_log_model
        self.deadline_reminder_log_model = deadline_reminder_log_model
        self.ticket_generation_key_model = ticket_generation_key_model
        self.unit_assignment_model = unit_assignment_model
        self.role_enum = role_enum

    def department_match_filter(self, column, department_id: int | None):
        if department_id is None:
            return column.is_(None)
        return column == department_id

    def add_ticket_watcher(self, db, ticket, *, watcher_user_id: int | None, added_by: int | None = None) -> bool:
        if watcher_user_id is None or ticket.id is None:
            return False
        watcher_user = db.get(self.user_model, watcher_user_id)
        if not watcher_user:
            return False
        if ticket.company_id is not None and watcher_user.company_id != ticket.company_id:
            return False
        exists = (
            db.query(self.ticket_watcher_model.id)
            .filter(
                self.ticket_watcher_model.ticket_id == ticket.id,
                self.ticket_watcher_model.user_id == watcher_user_id,
            )
            .first()
        )
        if exists is not None:
            return False
        db.add(
            self.ticket_watcher_model(
                ticket_id=ticket.id,
                user_id=watcher_user_id,
                added_by=added_by,
            )
        )
        return True

    def ensure_default_ticket_watchers(self, db, ticket) -> bool:
        changed = False
        default_watcher_ids: list[int] = []
        for watcher_user_id in (ticket.created_by, ticket.executor_id):
            if watcher_user_id is None or watcher_user_id in default_watcher_ids:
                continue
            default_watcher_ids.append(watcher_user_id)
        for watcher_user_id in default_watcher_ids:
            changed = self.add_ticket_watcher(
                db,
                ticket,
                watcher_user_id=watcher_user_id,
                added_by=ticket.created_by,
            ) or changed
        return changed

    def get_api_ticket_or_404(self, db, user, ticket_id: int):
        ticket = db.get(self.ticket_model, ticket_id)
        if not ticket:
            raise self.http_exception_cls(404, "Ticket not found")
        if not self.is_platform_admin_func(user):
            self.ensure_company_user_func(user)
            if ticket.company_id != user.company_id:
                raise self.http_exception_cls(403, "Forbidden")
        return ticket

    def delete_ticket_with_related_data(self, db, ticket, remove_files: bool = True) -> None:
        attachments = db.query(self.attachment_model).filter(self.attachment_model.ticket_id == ticket.id).all()
        comment_media_items = (
            db.query(self.comment_media_model)
            .join(self.comment_model, self.comment_model.id == self.comment_media_model.comment_id)
            .filter(self.comment_model.ticket_id == ticket.id)
            .all()
        )
        if remove_files:
            for attachment in attachments:
                self.delete_stored_file_func(attachment.file_path)
            for item in comment_media_items:
                self.delete_stored_file_func(item.file_path)
        comment_ids_subquery = db.query(self.comment_model.id).filter(self.comment_model.ticket_id == ticket.id)
        db.query(self.comment_media_model).filter(
            self.comment_media_model.comment_id.in_(comment_ids_subquery)
        ).delete(synchronize_session=False)
        db.query(self.comment_model).filter(self.comment_model.ticket_id == ticket.id).delete(synchronize_session=False)
        db.query(self.attachment_model).filter(self.attachment_model.ticket_id == ticket.id).delete(synchronize_session=False)
        db.query(self.ticket_log_model).filter(self.ticket_log_model.ticket_id == ticket.id).delete(synchronize_session=False)
        db.query(self.ticket_watcher_model).filter(
            self.ticket_watcher_model.ticket_id == ticket.id
        ).delete(synchronize_session=False)
        db.query(self.deadline_reminder_log_model).filter(
            self.deadline_reminder_log_model.ticket_id == ticket.id
        ).delete(synchronize_session=False)
        db.query(self.ticket_generation_key_model).filter(
            self.ticket_generation_key_model.ticket_id == ticket.id
        ).update({"ticket_id": None}, synchronize_session=False)
        db.delete(ticket)

    def validate_ticket_links(
        self,
        db,
        company_id: int | None,
        project_id: int | None,
        executor_id: int | None,
        ticket_type_id: int | None = None,
        target_unit_id: int | None = None,
        ticket_template_id: int | None = None,
        department_id: int | None = None,
    ) -> None:
        if project_id is not None:
            project = db.get(self.project_model, project_id)
            if not project or (company_id is not None and project.company_id != company_id):
                raise self.http_exception_cls(400, "Project not found")

        if executor_id is not None:
            executor = db.get(self.user_model, executor_id)
            if not executor or not self.is_assignable_executor_user_func(executor):
                raise self.http_exception_cls(400, "Executor not found")
            if company_id is not None and executor.company_id != company_id:
                raise self.http_exception_cls(400, "Executor not found")

        if ticket_type_id is not None:
            ticket_type = db.get(self.ticket_type_model, ticket_type_id)
            if not ticket_type or (company_id is not None and ticket_type.company_id != company_id):
                raise self.http_exception_cls(400, "Ticket type not found")
            if not ticket_type.is_active:
                raise self.http_exception_cls(400, "Ticket type is inactive")

        if department_id is not None:
            department = db.get(self.department_model, department_id)
            if not department or (company_id is not None and department.company_id != company_id):
                raise self.http_exception_cls(400, "Department not found")
            if not department.is_active:
                raise self.http_exception_cls(400, "Department is inactive")

        if target_unit_id is not None:
            target_unit = db.get(self.org_unit_model, target_unit_id)
            if not target_unit or (company_id is not None and target_unit.company_id != company_id):
                raise self.http_exception_cls(400, "Target unit not found")
            if not target_unit.is_active:
                raise self.http_exception_cls(400, "Target unit is inactive")

        if ticket_template_id is not None:
            template = db.get(self.ticket_template_model, ticket_template_id)
            if not template or (company_id is not None and template.company_id != company_id):
                raise self.http_exception_cls(400, "Ticket template not found")

    def resolve_ticket_department_id(
        self,
        db,
        *,
        company_id: int,
        ticket_type_id: int | None,
        department_id: int | None,
    ) -> int | None:
        resolved_department_id = department_id
        ticket_type_department_id: int | None = None

        if ticket_type_id is not None:
            ticket_type = db.get(self.ticket_type_model, ticket_type_id)
            if not ticket_type or ticket_type.company_id != company_id:
                raise self.http_exception_cls(400, "Ticket type not found")
            ticket_type_department_id = (
                int(ticket_type.department_id) if ticket_type.department_id is not None else None
            )

        if resolved_department_id is not None:
            department = db.get(self.department_model, resolved_department_id)
            if not department or department.company_id != company_id:
                raise self.http_exception_cls(400, "Department not found")
            if not department.is_active:
                raise self.http_exception_cls(400, "Department is inactive")

        if ticket_type_department_id is not None:
            if resolved_department_id is not None and resolved_department_id != ticket_type_department_id:
                raise self.http_exception_cls(400, "Department does not match ticket type")
            return ticket_type_department_id

        return resolved_department_id

    def _active_unit_children_map(self, db, company_id: int) -> tuple[dict[int, list[int]], set[int]]:
        rows = (
            db.query(self.org_unit_model.id, self.org_unit_model.parent_id, self.org_unit_model.is_active)
            .filter(self.org_unit_model.company_id == company_id)
            .all()
        )
        active_ids = {int(row[0]) for row in rows if bool(row[2])}
        children_by_parent: dict[int, list[int]] = {}
        for unit_id, parent_id, is_active in rows:
            if not bool(is_active) or parent_id is None:
                continue
            children_by_parent.setdefault(int(parent_id), []).append(int(unit_id))
        return children_by_parent, active_ids

    def resolve_scope_leaf_units(self, db, company_id: int, scope_unit_id: int) -> list[int]:
        children_by_parent, active_ids = self._active_unit_children_map(db, company_id)
        if scope_unit_id not in active_ids:
            return []
        stack = [scope_unit_id]
        visited: set[int] = set()
        leaf_ids: list[int] = []
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            children = children_by_parent.get(current, [])
            if not children:
                leaf_ids.append(current)
                continue
            stack.extend(children)
        return leaf_ids

    def resolve_scope_descendant_units(self, db, company_id: int, scope_unit_id: int) -> list[int]:
        children_by_parent, active_ids = self._active_unit_children_map(db, company_id)
        if scope_unit_id not in active_ids:
            return []
        stack = [scope_unit_id]
        visited: set[int] = set()
        result: list[int] = []
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            result.append(current)
            for child in children_by_parent.get(current, []):
                stack.append(child)
        return result

    def resolve_target_unit_id_from_form_input(self, db, company_id: int, raw_value: str | None) -> int | None:
        value = " ".join(str(raw_value or "").split()).strip()
        if not value:
            return None

        id_match = self.re_module.search(r"#(\d+)\)?\s*$", value)
        if id_match:
            unit_id = int(id_match.group(1))
            row = (
                db.query(self.org_unit_model.id)
                .filter(
                    self.org_unit_model.company_id == company_id,
                    self.org_unit_model.id == unit_id,
                    self.org_unit_model.is_active.is_(True),
                )
                .first()
            )
            if row:
                return int(row[0])

        rows = (
            db.query(self.org_unit_model.id, self.org_unit_model.name)
            .filter(self.org_unit_model.company_id == company_id, self.org_unit_model.is_active.is_(True))
            .all()
        )
        normalized_value = value.casefold()
        matched_ids = [
            int(unit_id)
            for unit_id, unit_name in rows
            if " ".join(str(unit_name or "").split()).strip().casefold() == normalized_value
        ]
        if len(matched_ids) == 1:
            return matched_ids[0]
        return None

    def resolve_executor_id_from_form_input(self, db, company_id: int, raw_value: str | None) -> int | None:
        value = " ".join(str(raw_value or "").split()).strip()
        if not value:
            return None

        id_match = self.re_module.search(r"#(\d+)\)?\s*$", value)
        if id_match:
            user_id = int(id_match.group(1))
            row = (
                db.query(self.user_model.id)
                .filter(
                    self.user_model.company_id == company_id,
                    self.user_model.id == user_id,
                    self.user_model.role != self.role_enum.platform_admin,
                    self.user_model.is_assignable_executor.is_(True),
                )
                .first()
            )
            if row:
                return int(row[0])

        rows = (
            db.query(self.user_model.id, self.user_model.name, self.user_model.email)
            .filter(
                self.user_model.company_id == company_id,
                self.user_model.role != self.role_enum.platform_admin,
                self.user_model.is_assignable_executor.is_(True),
            )
            .all()
        )
        normalized_value = value.casefold()
        matched_ids = [
            int(user_id)
            for user_id, user_name, user_email in rows
            if " ".join(str(user_name or "").split()).strip().casefold() == normalized_value
            or str(user_email or "").strip().casefold() == normalized_value
        ]
        if len(matched_ids) == 1:
            return matched_ids[0]
        return None

    def validate_template_links(
        self,
        db,
        company_id: int,
        ticket_type_id: int | None,
        department_id: int | None,
        default_executor_id: int | None,
        scope_unit_id: int | None,
    ) -> None:
        if ticket_type_id is not None:
            ticket_type = db.get(self.ticket_type_model, ticket_type_id)
            if not ticket_type or ticket_type.company_id != company_id:
                raise self.http_exception_cls(400, "Ticket type not found")
        if department_id is not None:
            department = db.get(self.department_model, department_id)
            if not department or department.company_id != company_id:
                raise self.http_exception_cls(400, "Department not found")
            if not department.is_active:
                raise self.http_exception_cls(400, "Department is inactive")
        if default_executor_id is not None:
            user = db.get(self.user_model, default_executor_id)
            if not user or user.company_id != company_id or not self.is_assignable_executor_user_func(user):
                raise self.http_exception_cls(400, "Executor not found")
        if scope_unit_id is not None:
            unit = db.get(self.org_unit_model, scope_unit_id)
            if not unit or unit.company_id != company_id:
                raise self.http_exception_cls(400, "Scope unit not found")

    def get_or_create_project_for_org_unit(self, db, company_id: int, unit_id: int) -> int:
        rows = (
            db.query(self.org_unit_model.id, self.org_unit_model.parent_id, self.org_unit_model.name)
            .filter(self.org_unit_model.company_id == company_id)
            .all()
        )
        by_id = {int(row[0]): (row[1], str(row[2] or "").strip()) for row in rows}
        if unit_id not in by_id:
            raise self.http_exception_cls(400, "Target unit not found")

        parts: list[str] = []
        current: int | None = unit_id
        visited: set[int] = set()
        while current is not None and current in by_id and current not in visited:
            visited.add(current)
            parent_id, name = by_id[current]
            if name:
                parts.append(name)
            current = int(parent_id) if parent_id is not None else None

        base_name = " / ".join(reversed(parts)).strip() or f"Org unit #{unit_id}"
        candidate_names = [base_name]
        if len(base_name) > 240:
            candidate_names = [f"{base_name[:220]} #{unit_id}", f"Org unit #{unit_id}"]
        else:
            candidate_names.append(f"{base_name} #{unit_id}")

        for project_name in candidate_names:
            existing = (
                db.query(self.project_model.id)
                .filter(self.project_model.company_id == company_id, self.project_model.name == project_name)
                .first()
            )
            if existing:
                return int(existing[0])

            item = self.project_model(
                company_id=company_id,
                name=project_name,
                description="Auto-created from org structure",
            )
            db.add(item)
            db.flush()
            return int(item.id)

        raise self.http_exception_cls(400, "Cannot resolve project for target unit")

    def get_preferred_executor_for_unit(self, db, company_id: int, unit_id: int, department_id: int | None = None) -> int | None:
        query = (
            db.query(self.unit_assignment_model.user_id)
            .join(self.user_model, self.user_model.id == self.unit_assignment_model.user_id)
            .filter(
                self.unit_assignment_model.company_id == company_id,
                self.unit_assignment_model.unit_id == unit_id,
                self.unit_assignment_model.role_code == "EXECUTOR",
                self.user_model.company_id == company_id,
                self.user_model.role != self.role_enum.platform_admin,
                self.user_model.is_assignable_executor.is_(True),
                self.department_match_filter(self.unit_assignment_model.department_id, department_id),
            )
            .order_by(self.unit_assignment_model.is_primary.desc(), self.unit_assignment_model.id.asc())
        )
        row = query.first()
        return int(row[0]) if row else None

    def month_period_key(self, dt=None) -> str:
        base = dt or self.local_now()
        return base.strftime("%Y-%m")

    def normalize_period_key(self, raw_value: str | None) -> str | None:
        raw = (raw_value or "").strip()
        if not raw or len(raw) != 7 or raw[4] != "-":
            return None
        yyyy = raw[:4]
        mm = raw[5:]
        if not (yyyy.isdigit() and mm.isdigit()):
            return None
        month_value = int(mm)
        if month_value < 1 or month_value > 12:
            return None
        return f"{yyyy}-{mm}"

    def resolve_deadline_by_rule(self, rule: str | None, now_dt=None):
        raw = (rule or "").strip().lower()
        if not raw:
            return None
        base = now_dt or self.local_now()
        if raw.startswith("dom:"):
            try:
                day = int(raw.split(":", 1)[1])
            except ValueError:
                return None
            if day < 1:
                return None
            last_day = self.monthrange_func(base.year, base.month)[1]
            clamped_day = min(day, last_day)
            return base.replace(day=clamped_day, hour=23, minute=59, second=0, microsecond=0)
        try:
            exact_date = self.datetime_cls.strptime(raw, "%Y-%m-%d")
            return exact_date.replace(hour=23, minute=59, second=0, microsecond=0)
        except ValueError:
            pass
        if raw.startswith("+") and raw.endswith("h"):
            try:
                return base + self.timedelta_cls(hours=max(1, int(raw[1:-1])))
            except ValueError:
                return None
        if raw.startswith("+") and raw.endswith("d"):
            try:
                return base + self.timedelta_cls(days=max(1, int(raw[1:-1])))
            except ValueError:
                return None
        return None

    def template_deadline_date_value(self, rule: str | None) -> str:
        raw = (rule or "").strip()
        if not raw:
            return ""
        try:
            return self.datetime_cls.strptime(raw, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            return ""

    def template_deadline_mode(self, rule: str | None) -> str:
        raw = (rule or "").strip().lower()
        if raw.startswith("dom:"):
            return "dom"
        if self.template_deadline_date_value(raw):
            return "date"
        return "none"

    def template_deadline_dom_value(self, rule: str | None) -> str:
        raw = (rule or "").strip().lower()
        if not raw.startswith("dom:"):
            return ""
        try:
            day = int(raw.split(":", 1)[1])
        except ValueError:
            return ""
        if day < 1 or day > 31:
            return ""
        return str(day)

    def parse_template_deadline_rule_from_form(self, form) -> str | None:
        mode = (form.get("deadline_mode") or "").strip().lower()
        if mode == "date":
            date_value = (form.get("deadline_date") or "").strip()
            if not date_value:
                return None
            try:
                return self.datetime_cls.strptime(date_value, "%Y-%m-%d").strftime("%Y-%m-%d")
            except ValueError:
                return None
        if mode == "dom":
            dom_raw = (form.get("deadline_dom") or "").strip()
            if not dom_raw:
                return None
            try:
                day = int(dom_raw)
            except ValueError:
                return None
            if day < 1 or day > 31:
                return None
            return f"dom:{day}"
        legacy_raw = (form.get("default_deadline_rule") or "").strip().lower()
        if not legacy_raw:
            return None
        if legacy_raw.startswith("dom:"):
            return legacy_raw
        try:
            return self.datetime_cls.strptime(legacy_raw, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            return legacy_raw

    def normalize_ticket_title(self, raw_title: str | None) -> str:
        return (raw_title or "").strip()

    def is_ticket_title_too_long(self, title: str | None) -> bool:
        return len(title or "") > self.max_ticket_title_len

    def truncate_ticket_title(self, title: str | None) -> str:
        normalized = self.normalize_ticket_title(title)
        if len(normalized) <= self.max_ticket_title_len:
            return normalized
        return normalized[: self.max_ticket_title_len].rstrip()
