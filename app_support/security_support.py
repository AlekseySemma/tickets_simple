class SecuritySupport:
    def __init__(
        self,
        *,
        rate_limit_lock,
        rate_limit_buckets: dict[str, list[float]],
        session_local_factory,
        security_event_model,
        get_client_ip_func,
        time_module,
    ):
        self.rate_limit_lock = rate_limit_lock
        self.rate_limit_buckets = rate_limit_buckets
        self.session_local_factory = session_local_factory
        self.security_event_model = security_event_model
        self.get_client_ip_func = get_client_ip_func
        self.time_module = time_module

    def normalize_email(self, value: str | None) -> str | None:
        normalized = (value or "").strip().lower()
        return normalized or None

    def normalize_department_name(self, value: str | None) -> str:
        return " ".join((value or "").split()).strip()

    def hit_rate_limit(self, bucket: str, max_calls: int, window_seconds: int) -> tuple[bool, int]:
        now = self.time_module.time()
        cutoff = now - max(1, window_seconds)
        with self.rate_limit_lock:
            hits = [ts for ts in self.rate_limit_buckets.get(bucket, []) if ts >= cutoff]
            if len(hits) >= max_calls:
                self.rate_limit_buckets[bucket] = hits
                retry_after = max(1, int(window_seconds - (now - hits[0])) + 1)
                return True, retry_after
            hits.append(now)
            self.rate_limit_buckets[bucket] = hits
        return False, 0

    def audit_security_event(
        self,
        event_type: str,
        request=None,
        *,
        success: bool,
        email: str | None = None,
        user_id: int | None = None,
        detail: str | None = None,
    ) -> None:
        db = self.session_local_factory()
        try:
            db.add(
                self.security_event_model(
                    event_type=(event_type or "").strip()[:80] or "security_event",
                    endpoint=(request.url.path if request else "")[:255] or None,
                    ip_address=self.get_client_ip_func(request)[:64],
                    email=self.normalize_email(email),
                    user_id=user_id,
                    success=bool(success),
                    detail=((detail or "").strip()[:1000] or None),
                )
            )
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
