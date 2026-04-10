import json


class PushSupport:
    def __init__(
        self,
        *,
        android_app_user_agent_token: str,
        pywebpush_available_getter,
        vapid_private_key_getter,
        vapid_public_key_getter,
        vapid_subject_getter,
        firebase_admin_available_getter,
        firebase_credentials_file_getter,
        firebase_app_getter,
        firebase_app_setter,
        firebase_app_lock,
        firebase_admin_module,
        firebase_credentials_module,
        firebase_messaging_module,
        logger,
        webpush_func,
        webpush_exception_cls,
        now_utc_fn,
        path_cls,
        push_subscription_model,
        mobile_device_model,
    ):
        self.android_app_user_agent_token = android_app_user_agent_token
        self.pywebpush_available_getter = pywebpush_available_getter
        self.vapid_private_key_getter = vapid_private_key_getter
        self.vapid_public_key_getter = vapid_public_key_getter
        self.vapid_subject_getter = vapid_subject_getter
        self.firebase_admin_available_getter = firebase_admin_available_getter
        self.firebase_credentials_file_getter = firebase_credentials_file_getter
        self.firebase_app_getter = firebase_app_getter
        self.firebase_app_setter = firebase_app_setter
        self.firebase_app_lock = firebase_app_lock
        self.firebase_admin_module = firebase_admin_module
        self.firebase_credentials_module = firebase_credentials_module
        self.firebase_messaging_module = firebase_messaging_module
        self.logger = logger
        self.webpush_func = webpush_func
        self.webpush_exception_cls = webpush_exception_cls
        self.now_utc_fn = now_utc_fn
        self.path_cls = path_cls
        self.push_subscription_model = push_subscription_model
        self.mobile_device_model = mobile_device_model

    def is_native_android_app_request(self, request) -> bool:
        user_agent = (request.headers.get("user-agent") or "").strip().lower()
        return self.android_app_user_agent_token in user_agent

    def normalize_mobile_platform(self, value: str | None) -> str:
        platform = (value or "android").strip().lower()
        return platform if platform in {"android"} else ""

    def push_is_configured(self) -> bool:
        return bool(
            self.pywebpush_available_getter()
            and self.vapid_private_key_getter()
            and self.vapid_public_key_getter()
            and self.vapid_subject_getter()
        )

    def mobile_push_is_configured(self) -> bool:
        credentials_file = self.firebase_credentials_file_getter()
        return bool(
            self.firebase_admin_available_getter()
            and credentials_file
            and self.path_cls(credentials_file).is_file()
        )

    def get_firebase_app(self):
        if not self.mobile_push_is_configured():
            return None
        with self.firebase_app_lock:
            app = self.firebase_app_getter()
            if app is None:
                try:
                    app = self.firebase_admin_module.initialize_app(
                        self.firebase_credentials_module.Certificate(
                            self.firebase_credentials_file_getter()
                        )
                    )
                except Exception as exc:
                    self.logger.warning("Firebase app init failed: %s", exc)
                    return None
                self.firebase_app_setter(app)
            return app

    def should_drop_mobile_token(self, exc: Exception) -> bool:
        name = exc.__class__.__name__
        details = str(exc).lower()
        if name in {"UnregisteredError", "SenderIdMismatchError", "InvalidArgumentError"}:
            return True
        return any(
            marker in details
            for marker in (
                "registration token is not a valid",
                "requested entity was not found",
                "unregistered",
                "sender id mismatch",
            )
        )

    def send_push_to_user_report(self, db, user_id: int, title: str, body: str, url: str) -> list[dict]:
        if not self.push_is_configured():
            return []

        subs = db.query(self.push_subscription_model).filter(self.push_subscription_model.user_id == user_id).all()
        if not subs:
            return []

        payload = json.dumps({"title": title, "body": body, "url": url})
        vapid_claims = {"sub": self.vapid_subject_getter()}
        results: list[dict] = []
        for sub in subs:
            subscription_info = {
                "endpoint": sub.endpoint,
                "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
            }
            try:
                self.webpush_func(
                    subscription_info=subscription_info,
                    data=payload,
                    vapid_private_key=self.vapid_private_key_getter(),
                    vapid_claims=vapid_claims,
                    ttl=60 * 60,
                )
                sub.updated_at = self.now_utc_fn()
                results.append({"id": sub.id, "ok": True})
            except self.webpush_exception_cls as exc:
                status_code = getattr(getattr(exc, "response", None), "status_code", None)
                results.append({"id": sub.id, "ok": False, "status_code": status_code})
                if status_code in {401, 404, 410}:
                    db.delete(sub)
            except Exception:
                results.append({"id": sub.id, "ok": False, "status_code": "error"})
        return results

    def send_mobile_push_to_user_report(self, db, user_id: int, title: str, body: str, url: str) -> list[dict]:
        if not self.mobile_push_is_configured():
            return []

        app = self.get_firebase_app()
        if app is None:
            return []

        devices = (
            db.query(self.mobile_device_model)
            .filter(self.mobile_device_model.user_id == user_id, self.mobile_device_model.platform == "android")
            .all()
        )
        if not devices:
            return []

        safe_url = (url or "").strip() or "/web"
        results: list[dict] = []
        for device in devices:
            message = self.firebase_messaging_module.Message(
                token=device.token,
                data={
                    "title": title,
                    "body": body or "",
                    "url": safe_url,
                },
                android=self.firebase_messaging_module.AndroidConfig(priority="high"),
            )
            try:
                self.firebase_messaging_module.send(message, app=app)
                now = self.now_utc_fn()
                device.last_seen_at = now
                device.updated_at = now
                results.append({"id": device.id, "ok": True, "channel": "android"})
            except Exception as exc:
                self.logger.warning(
                    "Android push send failed for mobile device %s: %s",
                    device.id,
                    exc,
                )
                results.append(
                    {
                        "id": device.id,
                        "ok": False,
                        "channel": "android",
                        "error_type": exc.__class__.__name__,
                    }
                )
                if self.should_drop_mobile_token(exc):
                    db.delete(device)
        return results
