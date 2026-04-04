class TicketRuntimeService:
    def __init__(
        self,
        *,
        clamp_archive_retention_days,
        get_company_archive_retention_days,
        local_now,
        move_attachment_to_archive,
        move_comment_media_to_archive,
        move_attachment_to_active_storage,
        move_comment_media_to_active_storage,
        format_deadline,
        add_ticket_log,
        delete_ticket_with_related_data,
        resolve_ticket_department_id,
        resolve_scope_leaf_units,
        truncate_ticket_title,
        get_or_create_project_for_org_unit,
        get_preferred_executor_for_unit,
        resolve_deadline_by_rule,
        month_period_key,
        ensure_default_ticket_watchers,
        send_push_to_user,
        ticket_notification_title,
        session_factory,
        archive_cleanup_poll_seconds: int,
        template_autogen_poll_seconds: int,
        time_module,
        timedelta_cls,
        uuid_module,
        ticket_model,
        ticket_type_model,
        attachment_model,
        comment_model,
        comment_media_model,
        archive_cleanup_log_model,
        ticket_template_model,
        ticket_generation_key_model,
        user_model,
        org_unit_model,
        role_enum,
        ticket_status_enum,
        archive_source_statuses,
        created_from_template_log_action: str,
        sqlalchemy_error_cls,
        http_exception_cls,
    ):
        self.clamp_archive_retention_days = clamp_archive_retention_days
        self.get_company_archive_retention_days = get_company_archive_retention_days
        self.local_now = local_now
        self.move_attachment_to_archive = move_attachment_to_archive
        self.move_comment_media_to_archive = move_comment_media_to_archive
        self.move_attachment_to_active_storage = move_attachment_to_active_storage
        self.move_comment_media_to_active_storage = move_comment_media_to_active_storage
        self.format_deadline = format_deadline
        self.add_ticket_log = add_ticket_log
        self.delete_ticket_with_related_data = delete_ticket_with_related_data
        self.resolve_ticket_department_id = resolve_ticket_department_id
        self.resolve_scope_leaf_units = resolve_scope_leaf_units
        self.truncate_ticket_title = truncate_ticket_title
        self.get_or_create_project_for_org_unit = get_or_create_project_for_org_unit
        self.get_preferred_executor_for_unit = get_preferred_executor_for_unit
        self.resolve_deadline_by_rule = resolve_deadline_by_rule
        self.month_period_key = month_period_key
        self.ensure_default_ticket_watchers = ensure_default_ticket_watchers
        self.send_push_to_user = send_push_to_user
        self.ticket_notification_title = ticket_notification_title
        self.session_factory = session_factory
        self.archive_cleanup_poll_seconds = int(archive_cleanup_poll_seconds)
        self.template_autogen_poll_seconds = int(template_autogen_poll_seconds)
        self.time_module = time_module
        self.timedelta_cls = timedelta_cls
        self.uuid_module = uuid_module
        self.ticket_model = ticket_model
        self.ticket_type_model = ticket_type_model
        self.attachment_model = attachment_model
        self.comment_model = comment_model
        self.comment_media_model = comment_media_model
        self.archive_cleanup_log_model = archive_cleanup_log_model
        self.ticket_template_model = ticket_template_model
        self.ticket_generation_key_model = ticket_generation_key_model
        self.user_model = user_model
        self.org_unit_model = org_unit_model
        self.role_enum = role_enum
        self.ticket_status_enum = ticket_status_enum
        self.archive_source_statuses = set(archive_source_statuses)
        self.created_from_template_log_action = created_from_template_log_action
        self.sqlalchemy_error_cls = sqlalchemy_error_cls
        self.http_exception_cls = http_exception_cls

    def resolve_ticket_archive_retention_days(self, db, ticket, company) -> int:
        if ticket.ticket_type_id is not None:
            ticket_type = db.get(self.ticket_type_model, ticket.ticket_type_id)
            if (
                ticket_type
                and ticket_type.company_id == ticket.company_id
                and ticket_type.archive_retention_days is not None
            ):
                return self.clamp_archive_retention_days(ticket_type.archive_retention_days)
        return self.get_company_archive_retention_days(company)

    def is_ticket_archived(self, ticket) -> bool:
        return ticket.status == self.ticket_status_enum.archived

    def archive_ticket(self, db, ticket, actor_id: int, company) -> None:
        if ticket.status not in self.archive_source_statuses:
            raise self.http_exception_cls(400, "Only done or canceled tickets can be archived")
        if self.is_ticket_archived(ticket):
            return
        archived_at = self.local_now()
        retention_days = self.resolve_ticket_archive_retention_days(db, ticket, company)
        ticket.status = self.ticket_status_enum.archived
        ticket.archived_at = archived_at
        ticket.archived_by = actor_id
        ticket.retention_days = retention_days
        ticket.delete_at = archived_at + self.timedelta_cls(days=retention_days)
        ticket.is_legal_hold = False
        attachments = db.query(self.attachment_model).filter(self.attachment_model.ticket_id == ticket.id).all()
        for attachment in attachments:
            self.move_attachment_to_archive(attachment, ticket.id, archived_at)
        comment_media_items = (
            db.query(self.comment_media_model)
            .join(self.comment_model, self.comment_model.id == self.comment_media_model.comment_id)
            .filter(self.comment_model.ticket_id == ticket.id)
            .all()
        )
        for item in comment_media_items:
            self.move_comment_media_to_archive(item, ticket.id, archived_at)
        self.add_ticket_log(
            db,
            ticket_id=ticket.id,
            actor_id=actor_id,
            action=f"архивирование (удаление после {self.format_deadline(ticket.delete_at)})",
        )

    def restore_ticket_from_archive(self, db, ticket, actor_id: int) -> None:
        if not self.is_ticket_archived(ticket):
            raise self.http_exception_cls(400, "Ticket is not archived")
        ticket.status = self.ticket_status_enum.done
        ticket.archived_at = None
        ticket.archived_by = None
        ticket.retention_days = None
        ticket.delete_at = None
        ticket.is_legal_hold = False
        attachments = db.query(self.attachment_model).filter(self.attachment_model.ticket_id == ticket.id).all()
        for attachment in attachments:
            self.move_attachment_to_active_storage(attachment, ticket.id)
        comment_media_items = (
            db.query(self.comment_media_model)
            .join(self.comment_model, self.comment_model.id == self.comment_media_model.comment_id)
            .filter(self.comment_model.ticket_id == ticket.id)
            .all()
        )
        for item in comment_media_items:
            self.move_comment_media_to_active_storage(item, ticket.id)
        self.add_ticket_log(db, ticket_id=ticket.id, actor_id=actor_id, action="восстановление из архива")

    def run_archive_cleanup_once(self) -> None:
        with self.session_factory() as db:
            candidates = (
                db.query(self.ticket_model)
                .filter(
                    self.ticket_model.status == self.ticket_status_enum.archived,
                    self.ticket_model.delete_at.is_not(None),
                    self.ticket_model.delete_at <= self.local_now(),
                    self.ticket_model.is_legal_hold.is_(False),
                )
                .order_by(self.ticket_model.delete_at.asc(), self.ticket_model.id.asc())
                .all()
            )
            for ticket in candidates:
                try:
                    deleted_at = self.local_now()
                    db.add(
                        self.archive_cleanup_log_model(
                            company_id=ticket.company_id,
                            ticket_id=ticket.id,
                            archived_by=ticket.archived_by,
                            ticket_title=(ticket.title or "")[:255] or None,
                            archived_at=ticket.archived_at,
                            retention_days=ticket.retention_days,
                            delete_at=ticket.delete_at,
                            deleted_at=deleted_at,
                        )
                    )
                    self.delete_ticket_with_related_data(db, ticket, remove_files=True)
                    db.commit()
                except Exception:
                    db.rollback()

    def run_archive_cleanup_forever(self) -> None:
        while True:
            try:
                self.run_archive_cleanup_once()
            except Exception:
                pass
            self.time_module.sleep(self.archive_cleanup_poll_seconds)

    def render_template_value(self, raw_value: str | None, period_key: str, unit_name: str) -> str | None:
        text = (raw_value or "").strip()
        if not text:
            return None
        return text.replace("{period}", period_key).replace("{unit_name}", unit_name).replace("{month}", period_key)

    def ticket_exists_for_template_period(self, db, company_id: int, template_id: int, target_unit_id: int, period_key: str) -> bool:
        row = (
            db.query(self.ticket_generation_key_model.id)
            .filter(
                self.ticket_generation_key_model.company_id == company_id,
                self.ticket_generation_key_model.ticket_template_id == template_id,
                self.ticket_generation_key_model.target_unit_id == target_unit_id,
                self.ticket_generation_key_model.period_key == period_key,
            )
            .first()
        )
        return row is not None

    def create_tickets_from_template(self, db, *, template, actor_id: int, period_key: str | None = None):
        effective_period = (period_key or "").strip() or self.month_period_key()
        if template.scope_unit_id is None:
            return 0, 0, effective_period
        template_department_id = self.resolve_ticket_department_id(
            db,
            company_id=template.company_id,
            ticket_type_id=template.ticket_type_id,
            department_id=template.department_id,
        )

        leaf_unit_ids = self.resolve_scope_leaf_units(db, template.company_id, template.scope_unit_id)
        if not leaf_unit_ids:
            return 0, 0, effective_period

        batch_id = self.uuid_module.uuid4().hex
        created_count = 0
        skipped_count = 0
        for leaf_unit_id in leaf_unit_ids:
            if self.ticket_exists_for_template_period(
                db=db,
                company_id=template.company_id,
                template_id=template.id,
                target_unit_id=leaf_unit_id,
                period_key=effective_period,
            ):
                skipped_count += 1
                continue

            unit_name_row = (
                db.query(self.org_unit_model.name)
                .filter(self.org_unit_model.id == leaf_unit_id)
                .first()
            )
            unit_name = str(unit_name_row[0]).strip() if unit_name_row and unit_name_row[0] else f"Unit #{leaf_unit_id}"
            title = self.truncate_ticket_title(
                self.render_template_value(template.title_template, effective_period, unit_name)
                or f"{template.name} {effective_period}"
            )
            description = self.render_template_value(template.description_template, effective_period, unit_name)
            project_id = self.get_or_create_project_for_org_unit(db, template.company_id, leaf_unit_id)
            resolved_executor_id = (
                template.default_executor_id
                if template.default_executor_id is not None
                else self.get_preferred_executor_for_unit(
                    db,
                    template.company_id,
                    leaf_unit_id,
                    department_id=template_department_id,
                )
            )

            try:
                with db.begin_nested():
                    generation_key = self.ticket_generation_key_model(
                        company_id=template.company_id,
                        ticket_template_id=template.id,
                        target_unit_id=leaf_unit_id,
                        period_key=effective_period,
                    )
                    db.add(generation_key)
                    db.flush()
                    ticket = self.ticket_model(
                        title=title,
                        description=description,
                        deadline=self.resolve_deadline_by_rule(template.default_deadline_rule),
                        status=self.ticket_status_enum.new,
                        company_id=template.company_id,
                        project_id=project_id,
                        executor_id=resolved_executor_id,
                        ticket_type_id=template.ticket_type_id,
                        department_id=template_department_id,
                        target_unit_id=leaf_unit_id,
                        ticket_template_id=template.id,
                        period_key=effective_period,
                        batch_id=batch_id,
                        created_by=actor_id,
                    )
                    db.add(ticket)
                    db.flush()
                    self.ensure_default_ticket_watchers(db, ticket)
                    generation_key.ticket_id = ticket.id
                    self.add_ticket_log(
                        db,
                        ticket_id=ticket.id,
                        actor_id=actor_id,
                        action=self.created_from_template_log_action,
                    )
                    if ticket.executor_id and ticket.executor_id != actor_id:
                        self.send_push_to_user(
                            db=db,
                            user_id=ticket.executor_id,
                            title=self.ticket_notification_title("Новая заявка", ticket.title, ticket_id=ticket.id),
                            body=ticket.title or "Вам назначена новая заявка",
                            url=f"/web/tickets/{ticket.id}",
                        )
                created_count += 1
            except self.sqlalchemy_error_cls:
                skipped_count += 1

        return created_count, skipped_count, effective_period

    def resolve_company_actor_id(self, db, company_id: int) -> int | None:
        manager_row = (
            db.query(self.user_model.id)
            .filter(
                self.user_model.company_id == company_id,
                self.user_model.role.in_([self.role_enum.admin, self.role_enum.curator]),
            )
            .order_by(self.user_model.id.asc())
            .first()
        )
        if manager_row:
            return int(manager_row[0])
        any_row = (
            db.query(self.user_model.id)
            .filter(self.user_model.company_id == company_id)
            .order_by(self.user_model.id.asc())
            .first()
        )
        return int(any_row[0]) if any_row else None

    def run_template_autogen_once(self) -> None:
        with self.session_factory() as db:
            templates_to_run = (
                db.query(self.ticket_template_model)
                .filter(
                    self.ticket_template_model.is_active.is_(True),
                    self.ticket_template_model.scope_unit_id.is_not(None),
                )
                .order_by(self.ticket_template_model.id.asc())
                .all()
            )
            if not templates_to_run:
                return

            for item in templates_to_run:
                actor_id = self.resolve_company_actor_id(db, item.company_id)
                if actor_id is None:
                    continue
                created_count, _, _ = self.create_tickets_from_template(
                    db=db,
                    template=item,
                    actor_id=actor_id,
                    period_key=self.month_period_key(),
                )
                if created_count > 0:
                    db.commit()
                else:
                    db.rollback()

    def run_template_autogen_forever(self) -> None:
        while True:
            try:
                self.run_template_autogen_once()
            except Exception:
                pass
            self.time_module.sleep(self.template_autogen_poll_seconds)
