class EmailAuthSupport:
    def __init__(
        self,
        *,
        email_message_cls,
        smtplib_module,
        logger,
        email_delivery_error_cls,
        format_sender_email_getter,
        format_sender_name_getter,
        smtp_host_getter,
        smtp_port_getter,
        smtp_username_getter,
        smtp_password_getter,
        smtp_use_tls_getter,
        smtp_use_ssl_getter,
        smtp_timeout_sec_getter,
        email_verification_expire_hours_getter,
        password_reset_expire_hours_getter,
        access_token_cookie_max_age_getter,
        auth_cookie_domain_getter,
        now_utc_fn,
        is_email_verification_required_func,
        prepare_user_email_verification_func,
        prepare_user_password_reset_func,
        build_email_verification_url_func,
        build_password_reset_url_func,
        core_get_auth_cookie_params_func,
        core_delete_auth_cookie_func,
    ):
        self.email_message_cls = email_message_cls
        self.smtplib_module = smtplib_module
        self.logger = logger
        self.email_delivery_error_cls = email_delivery_error_cls
        self.format_sender_email_getter = format_sender_email_getter
        self.format_sender_name_getter = format_sender_name_getter
        self.smtp_host_getter = smtp_host_getter
        self.smtp_port_getter = smtp_port_getter
        self.smtp_username_getter = smtp_username_getter
        self.smtp_password_getter = smtp_password_getter
        self.smtp_use_tls_getter = smtp_use_tls_getter
        self.smtp_use_ssl_getter = smtp_use_ssl_getter
        self.smtp_timeout_sec_getter = smtp_timeout_sec_getter
        self.email_verification_expire_hours_getter = email_verification_expire_hours_getter
        self.password_reset_expire_hours_getter = password_reset_expire_hours_getter
        self.access_token_cookie_max_age_getter = access_token_cookie_max_age_getter
        self.auth_cookie_domain_getter = auth_cookie_domain_getter
        self.now_utc_fn = now_utc_fn
        self.is_email_verification_required_func = is_email_verification_required_func
        self.prepare_user_email_verification_func = prepare_user_email_verification_func
        self.prepare_user_password_reset_func = prepare_user_password_reset_func
        self.build_email_verification_url_func = build_email_verification_url_func
        self.build_password_reset_url_func = build_password_reset_url_func
        self.core_get_auth_cookie_params_func = core_get_auth_cookie_params_func
        self.core_delete_auth_cookie_func = core_delete_auth_cookie_func

    def format_email_sender(self) -> str:
        sender_email = self.format_sender_email_getter() or self.smtp_username_getter() or "no-reply@localhost"
        sender_name = self.format_sender_name_getter()
        if sender_name:
            return f"{sender_name} <{sender_email}>"
        return sender_email

    def send_email_message(self, recipient: str, subject: str, text_body: str, html_body: str | None = None) -> bool:
        msg = self.email_message_cls()
        msg["Subject"] = subject
        msg["From"] = self.format_email_sender()
        msg["To"] = recipient
        if html_body:
            msg.set_content(text_body)
            msg.add_alternative(html_body, subtype="html")
        else:
            msg.set_content(text_body)

        smtp_host = self.smtp_host_getter()
        if not smtp_host:
            self.logger.info("SMTP_HOST is not configured. Email to %s was not sent.", recipient)
            return False

        smtp = None
        try:
            smtp_port = self.smtp_port_getter()
            smtp_timeout_sec = self.smtp_timeout_sec_getter()
            if self.smtp_use_ssl_getter():
                smtp = self.smtplib_module.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout_sec)
            else:
                smtp = self.smtplib_module.SMTP(smtp_host, smtp_port, timeout=smtp_timeout_sec)
                if self.smtp_use_tls_getter():
                    smtp.starttls()
            smtp_username = self.smtp_username_getter()
            if smtp_username:
                smtp.login(smtp_username, self.smtp_password_getter())
            smtp.send_message(msg)
            return True
        except Exception as exc:
            raise self.email_delivery_error_cls("Could not send email") from exc
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass

    def send_user_verification_email(self, request, db, user, *, force_new_token: bool = False) -> str:
        if not self.is_email_verification_required_func(user):
            return ""
        token_value = self.prepare_user_email_verification_func(user, force_new_token=force_new_token)
        verification_url = self.build_email_verification_url_func(request, token_value)
        ttl_hours_text = str(self.email_verification_expire_hours_getter())
        subject = "Подтвердите email в servora"
        text_body = (
            f"Здравствуйте, {user.name}!\n\n"
            "Подтвердите ваш email, чтобы завершить регистрацию и войти в servora:\n"
            f"{verification_url}\n\n"
            f"Ссылка действует {ttl_hours_text} ч."
        )
        html_body = (
            f"<p>Здравствуйте, {user.name}!</p>"
            "<p>Подтвердите ваш email, чтобы завершить регистрацию и войти в servora:</p>"
            f'<p><a href="{verification_url}">{verification_url}</a></p>'
            f"<p>Ссылка действует {ttl_hours_text} ч.</p>"
        )
        sent = self.send_email_message(user.email, subject, text_body, html_body=html_body)
        if not sent:
            self.logger.info("Verification link for %s: %s", user.email, verification_url)
        user.email_verification_sent_at = self.now_utc_fn()
        db.commit()
        db.refresh(user)
        return verification_url

    def send_user_password_reset_email(self, request, db, user, *, force_new_token: bool = False) -> str:
        token_value = self.prepare_user_password_reset_func(user, force_new_token=force_new_token)
        reset_url = self.build_password_reset_url_func(request, token_value)
        ttl_hours_text = str(self.password_reset_expire_hours_getter())
        subject = "Сброс пароля в servora"
        text_body = (
            f"Здравствуйте, {user.name}!\n\n"
            "Чтобы задать новый пароль для аккаунта servora, перейдите по ссылке:\n"
            f"{reset_url}\n\n"
            f"Ссылка действует {ttl_hours_text} ч."
        )
        html_body = (
            f"<p>Здравствуйте, {user.name}!</p>"
            "<p>Чтобы задать новый пароль для аккаунта servora, перейдите по ссылке:</p>"
            f'<p><a href="{reset_url}">{reset_url}</a></p>'
            f"<p>Ссылка действует {ttl_hours_text} ч.</p>"
        )
        sent = self.send_email_message(user.email, subject, text_body, html_body=html_body)
        if not sent:
            self.logger.info("Password reset link for %s: %s", user.email, reset_url)
        user.password_reset_sent_at = self.now_utc_fn()
        db.commit()
        db.refresh(user)
        return reset_url

    def get_auth_cookie_params(self, request):
        return self.core_get_auth_cookie_params_func(
            request,
            access_token_cookie_max_age=self.access_token_cookie_max_age_getter(),
            auth_cookie_domain=self.auth_cookie_domain_getter(),
        )

    def delete_auth_cookie(self, response, request) -> None:
        self.core_delete_auth_cookie_func(
            response,
            request,
            access_token_cookie_max_age=self.access_token_cookie_max_age_getter(),
            auth_cookie_domain=self.auth_cookie_domain_getter(),
        )
