class CompanyCleanupService:
    def __init__(
        self,
        *,
        delete_stored_file_func,
        ticket_model,
        receipt_model,
        user_model,
        attachment_model,
        comment_model,
        ticket_log_model,
        ticket_watcher_model,
        deadline_reminder_log_model,
        receipt_file_model,
        ticket_generation_key_model,
        unit_assignment_model,
        ticket_template_model,
        ticket_type_model,
        org_unit_model,
        unit_type_model,
        department_model,
        payment_card_model,
        project_model,
        registration_invite_model,
        notification_model,
        archive_cleanup_log_model,
        push_subscription_model,
        mobile_device_model,
        company_model,
    ):
        self.delete_stored_file_func = delete_stored_file_func
        self.ticket_model = ticket_model
        self.receipt_model = receipt_model
        self.user_model = user_model
        self.attachment_model = attachment_model
        self.comment_model = comment_model
        self.ticket_log_model = ticket_log_model
        self.ticket_watcher_model = ticket_watcher_model
        self.deadline_reminder_log_model = deadline_reminder_log_model
        self.receipt_file_model = receipt_file_model
        self.ticket_generation_key_model = ticket_generation_key_model
        self.unit_assignment_model = unit_assignment_model
        self.ticket_template_model = ticket_template_model
        self.ticket_type_model = ticket_type_model
        self.org_unit_model = org_unit_model
        self.unit_type_model = unit_type_model
        self.department_model = department_model
        self.payment_card_model = payment_card_model
        self.project_model = project_model
        self.registration_invite_model = registration_invite_model
        self.notification_model = notification_model
        self.archive_cleanup_log_model = archive_cleanup_log_model
        self.push_subscription_model = push_subscription_model
        self.mobile_device_model = mobile_device_model
        self.company_model = company_model

    def delete_company_with_data(self, db, company_id: int) -> None:
        ticket_ids = [row[0] for row in db.query(self.ticket_model.id).filter(self.ticket_model.company_id == company_id).all()]
        receipt_ids = [row[0] for row in db.query(self.receipt_model.id).filter(self.receipt_model.company_id == company_id).all()]
        user_ids = [row[0] for row in db.query(self.user_model.id).filter(self.user_model.company_id == company_id).all()]

        if ticket_ids:
            attachments = db.query(self.attachment_model).filter(self.attachment_model.ticket_id.in_(ticket_ids)).all()
            for attachment in attachments:
                self.delete_stored_file_func(attachment.file_path)

            db.query(self.comment_model).filter(self.comment_model.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
            db.query(self.attachment_model).filter(self.attachment_model.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
            db.query(self.ticket_log_model).filter(self.ticket_log_model.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
            db.query(self.ticket_watcher_model).filter(self.ticket_watcher_model.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
            db.query(self.deadline_reminder_log_model).filter(self.deadline_reminder_log_model.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        if receipt_ids:
            receipt_files = db.query(self.receipt_file_model).filter(self.receipt_file_model.receipt_id.in_(receipt_ids)).all()
            for file_row in receipt_files:
                self.delete_stored_file_func(file_row.file_path)
            db.query(self.receipt_file_model).filter(self.receipt_file_model.receipt_id.in_(receipt_ids)).delete(synchronize_session=False)
            db.query(self.receipt_model).filter(self.receipt_model.id.in_(receipt_ids)).delete(synchronize_session=False)

        db.query(self.ticket_generation_key_model).filter(self.ticket_generation_key_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.unit_assignment_model).filter(self.unit_assignment_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.ticket_template_model).filter(self.ticket_template_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.ticket_model).filter(self.ticket_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.ticket_type_model).filter(self.ticket_type_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.org_unit_model).filter(self.org_unit_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.unit_type_model).filter(self.unit_type_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.department_model).filter(self.department_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.payment_card_model).filter(self.payment_card_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.project_model).filter(self.project_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.registration_invite_model).filter(self.registration_invite_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.notification_model).filter(self.notification_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.archive_cleanup_log_model).filter(self.archive_cleanup_log_model.company_id == company_id).delete(synchronize_session=False)
        if user_ids:
            db.query(self.push_subscription_model).filter(self.push_subscription_model.user_id.in_(user_ids)).delete(synchronize_session=False)
            db.query(self.mobile_device_model).filter(self.mobile_device_model.user_id.in_(user_ids)).delete(synchronize_session=False)
            db.query(self.deadline_reminder_log_model).filter(self.deadline_reminder_log_model.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(self.user_model).filter(self.user_model.company_id == company_id).delete(synchronize_session=False)
        db.query(self.company_model).filter(self.company_model.id == company_id).delete(synchronize_session=False)
