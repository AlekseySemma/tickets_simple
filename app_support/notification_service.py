class NotificationService:
    def __init__(
        self,
        *,
        fix_mojibake_text,
        ticket_notification_title,
        summarize_comment_media,
        status_label_ru,
        send_push_to_user_report_func,
        send_mobile_push_to_user_report_func,
        user_model,
        notification_model,
        role_enum,
        ticket_watcher_model,
        project_model,
        payment_card_model,
    ):
        self.fix_mojibake_text = fix_mojibake_text
        self.ticket_notification_title = ticket_notification_title
        self.summarize_comment_media = summarize_comment_media
        self.status_label_ru = status_label_ru
        self.send_push_to_user_report_func = send_push_to_user_report_func
        self.send_mobile_push_to_user_report_func = send_mobile_push_to_user_report_func
        self.user_model = user_model
        self.notification_model = notification_model
        self.role_enum = role_enum
        self.ticket_watcher_model = ticket_watcher_model
        self.project_model = project_model
        self.payment_card_model = payment_card_model

    def create_inapp_notification(self, db, user_id: int, title: str, body: str, url: str) -> None:
        user = db.get(self.user_model, user_id)
        if not user:
            return
        item = self.notification_model(
            company_id=user.company_id,
            user_id=user_id,
            title=self.fix_mojibake_text((title or "").strip())[:255] or "Уведомление",
            body=(self.fix_mojibake_text((body or "").strip())[:2000] or None),
            url=(url or "").strip()[:500] or "/web",
            is_read=False,
        )
        db.add(item)

    def send_push_to_user(self, db, user_id: int, title: str, body: str, url: str) -> None:
        safe_title = self.fix_mojibake_text((title or "").strip()) or "Уведомление"
        safe_body = self.fix_mojibake_text((body or "").strip())
        safe_url = (url or "").strip() or "/web"
        self.create_inapp_notification(db=db, user_id=user_id, title=safe_title, body=safe_body, url=safe_url)
        _ = self.send_push_to_user_report_func(
            db=db,
            user_id=user_id,
            title=safe_title,
            body=safe_body,
            url=safe_url,
        )
        _ = self.send_mobile_push_to_user_report_func(
            db=db,
            user_id=user_id,
            title=safe_title,
            body=safe_body,
            url=safe_url,
        )

    def notify_executor_new_ticket(self, db, ticket, actor) -> None:
        if not ticket.executor_id or ticket.executor_id == actor.id:
            return
        self.send_push_to_user(
            db=db,
            user_id=ticket.executor_id,
            title=self.ticket_notification_title("Новая заявка", ticket.title, ticket_id=ticket.id),
            body=ticket.title or "Вам назначена новая заявка",
            url=f"/web/tickets/{ticket.id}",
        )

    def notify_executor_reassigned(self, db, ticket, old_executor_id: int | None, actor) -> None:
        if not ticket.executor_id or ticket.executor_id == old_executor_id or ticket.executor_id == actor.id:
            return
        self.send_push_to_user(
            db=db,
            user_id=ticket.executor_id,
            title=self.ticket_notification_title("Вам назначена заявка", ticket.title, ticket_id=ticket.id),
            body=ticket.title or "Заявка назначена на вас",
            url=f"/web/tickets/{ticket.id}",
        )

    def notify_curators_status_changed(self, db, ticket, actor, old_status) -> None:
        if old_status == ticket.status:
            return
        curator_ids = [
            user.id
            for user in db.query(self.user_model)
            .filter(
                self.user_model.role == self.role_enum.curator,
                self.user_model.company_id == ticket.company_id,
            )
            .all()
            if user.id != actor.id
        ]
        for curator_id in curator_ids:
            self.send_push_to_user(
                db=db,
                user_id=curator_id,
                title=self.ticket_notification_title("Изменен статус заявки", ticket.title, ticket_id=ticket.id),
                body=f"{actor.name}: {self.status_label_ru(old_status)} -> {self.status_label_ru(ticket.status)}",
                url=f"/web/tickets/{ticket.id}",
            )

    def notify_comment_added(
        self,
        db,
        ticket,
        author,
        comment_text: str,
        photo_count: int = 0,
        voice_count: int = 0,
        file_count: int = 0,
    ) -> None:
        short_text = (comment_text or "").strip()
        if len(short_text) > 80:
            short_text = short_text[:77] + "..."

        recipient_ids: set[int] = set()
        if ticket.executor_id:
            recipient_ids.add(int(ticket.executor_id))

        curator_ids = [
            user.id
            for user in db.query(self.user_model)
            .filter(
                self.user_model.role == self.role_enum.curator,
                self.user_model.company_id == ticket.company_id,
            )
            .all()
        ]
        recipient_ids.update(int(curator_id) for curator_id in curator_ids)

        watcher_rows = (
            db.query(self.ticket_watcher_model.user_id)
            .join(self.user_model, self.user_model.id == self.ticket_watcher_model.user_id)
            .filter(
                self.ticket_watcher_model.ticket_id == ticket.id,
                self.user_model.notify_comments_as_watcher.is_(True),
            )
            .all()
        )
        recipient_ids.update(int(row[0]) for row in watcher_rows if row and row[0] is not None)
        recipient_ids.discard(author.id)

        for recipient_id in recipient_ids:
            self.send_push_to_user(
                db=db,
                user_id=recipient_id,
                title=self.ticket_notification_title("Новый комментарий", ticket.title, ticket_id=ticket.id),
                body=short_text
                or self.summarize_comment_media(photo_count, voice_count, file_count, author.name),
                url=f"/web/tickets/{ticket.id}",
            )

    def notify_curators_executor_act(self, db, ticket, uploader, original_name: str | None) -> None:
        if uploader.role != self.role_enum.executor:
            return
        file_name = self.fix_mojibake_text((original_name or "").lower())
        if "акт" not in file_name and "act" not in file_name:
            return
        curator_ids = [
            user.id
            for user in db.query(self.user_model)
            .filter(
                self.user_model.role == self.role_enum.curator,
                self.user_model.company_id == ticket.company_id,
            )
            .all()
            if user.id != uploader.id
        ]
        for curator_id in curator_ids:
            self.send_push_to_user(
                db=db,
                user_id=curator_id,
                title=self.ticket_notification_title("Исполнитель прикрепил акт", ticket.title, ticket_id=ticket.id),
                body=original_name or "Добавлен файл акта",
                url=f"/web/tickets/{ticket.id}",
            )

    def notify_receipt_created(self, db, receipt, actor) -> None:
        recipient_rows = (
            db.query(self.user_model.id)
            .filter(
                self.user_model.company_id == receipt.company_id,
                self.user_model.id != actor.id,
                self.user_model.show_receipts_accounting_mode.is_(True),
                self.user_model.notify_receipt_created.is_(True),
                self.user_model.role != self.role_enum.platform_admin,
            )
            .all()
        )
        if not recipient_rows:
            return

        project_name = (
            db.query(self.project_model.name)
            .filter(
                self.project_model.id == receipt.project_id,
                self.project_model.company_id == receipt.company_id,
            )
            .scalar()
        )
        card_name = (
            db.query(self.payment_card_model.name)
            .filter(
                self.payment_card_model.id == receipt.card_id,
                self.payment_card_model.company_id == receipt.company_id,
            )
            .scalar()
        )
        body_parts: list[str] = []
        if project_name:
            body_parts.append(str(project_name))
        if card_name:
            body_parts.append(str(card_name))
        if receipt.comment:
            body_parts.append(str(receipt.comment))
        body = " | ".join(part for part in body_parts if part)[:400] or f"Добавлен чек #{receipt.id}"
        title = f"Новый чек #{receipt.id}"
        for row in recipient_rows:
            recipient_id = int(row[0])
            self.send_push_to_user(
                db=db,
                user_id=recipient_id,
                title=title,
                body=body,
                url="/web/receipts?mode=accounting",
            )
