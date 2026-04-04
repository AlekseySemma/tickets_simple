class DeadlineReminderService:
    def __init__(
        self,
        *,
        session_factory,
        local_now,
        send_push_to_user_func,
        ticket_notification_title,
        push_reminder_minutes_getter,
        push_reminder_poll_seconds_getter,
        final_ticket_statuses_getter,
        time_module,
        timedelta_cls,
        ticket_model,
        deadline_reminder_log_model,
    ):
        self.session_factory = session_factory
        self.local_now = local_now
        self.send_push_to_user_func = send_push_to_user_func
        self.ticket_notification_title = ticket_notification_title
        self.push_reminder_minutes_getter = push_reminder_minutes_getter
        self.push_reminder_poll_seconds_getter = push_reminder_poll_seconds_getter
        self.final_ticket_statuses_getter = final_ticket_statuses_getter
        self.time_module = time_module
        self.timedelta_cls = timedelta_cls
        self.ticket_model = ticket_model
        self.deadline_reminder_log_model = deadline_reminder_log_model

    def _push_reminder_minutes(self) -> int:
        return int(self.push_reminder_minutes_getter())

    def _push_reminder_poll_seconds(self) -> int:
        return int(self.push_reminder_poll_seconds_getter())

    def build_reminder_key(self, ticket_id: int, user_id: int, deadline_ts: int, minutes: int) -> str:
        return f"{ticket_id}:{user_id}:{deadline_ts}:{minutes}"

    def run_deadline_reminders_once(self) -> None:
        with self.session_factory() as db:
            now = self.local_now()
            reminder_minutes = self._push_reminder_minutes()
            poll_seconds = self._push_reminder_poll_seconds()
            horizon = now + self.timedelta_cls(seconds=poll_seconds)
            deadline_from = now + self.timedelta_cls(minutes=reminder_minutes)
            deadline_to = horizon + self.timedelta_cls(minutes=reminder_minutes)
            final_statuses = list(self.final_ticket_statuses_getter())
            candidates = (
                db.query(
                    self.ticket_model.id,
                    self.ticket_model.title,
                    self.ticket_model.executor_id,
                    self.ticket_model.deadline,
                )
                .filter(
                    self.ticket_model.executor_id.is_not(None),
                    self.ticket_model.deadline.is_not(None),
                    self.ticket_model.status.notin_(final_statuses),
                    self.ticket_model.deadline >= deadline_from,
                    self.ticket_model.deadline <= deadline_to,
                )
                .all()
            )

            reminder_keys = [
                self.build_reminder_key(t.id, t.executor_id, int(t.deadline.timestamp()), reminder_minutes)
                for t in candidates
            ]
            existing_keys = set()
            if reminder_keys:
                existing_rows = (
                    db.query(self.deadline_reminder_log_model.reminder_key)
                    .filter(self.deadline_reminder_log_model.reminder_key.in_(reminder_keys))
                    .all()
                )
                existing_keys = {row[0] for row in existing_rows}

            for ticket_row in candidates:
                reminder_key = self.build_reminder_key(
                    ticket_row.id,
                    ticket_row.executor_id,
                    int(ticket_row.deadline.timestamp()),
                    reminder_minutes,
                )
                if reminder_key in existing_keys:
                    continue
                existing_keys.add(reminder_key)
                db.add(
                    self.deadline_reminder_log_model(
                        ticket_id=ticket_row.id,
                        user_id=ticket_row.executor_id,
                        reminder_key=reminder_key,
                    )
                )
                self.send_push_to_user_func(
                    db=db,
                    user_id=ticket_row.executor_id,
                    title=self.ticket_notification_title(
                        "Срок заявки скоро истечет",
                        ticket_row.title,
                        ticket_id=ticket_row.id,
                    ),
                    body=f"До дедлайна осталось {reminder_minutes} минут",
                    url=f"/web/tickets/{ticket_row.id}",
                )
            db.commit()

    def run_deadline_reminders_forever(self) -> None:
        while True:
            try:
                self.run_deadline_reminders_once()
            except Exception:
                pass
            self.time_module.sleep(max(5, self._push_reminder_poll_seconds()))
