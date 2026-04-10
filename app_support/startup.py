import os
import threading
from typing import Callable
from app_support.time_support import utc_now_naive


def maybe_repair_text_on_start(*, enabled: bool, session_factory, repair_fn: Callable) -> None:
    if not enabled:
        return
    db = session_factory()
    try:
        repair_fn(db)
    finally:
        db.close()


def ensure_platform_admin_user(
    *,
    session_factory,
    user_model,
    role_enum,
    hash_password: Callable[[str], str],
    normalize_capability_flags: Callable,
) -> None:
    platform_email = (os.getenv("PLATFORM_ADMIN_EMAIL", "") or "").strip()
    platform_password = (os.getenv("PLATFORM_ADMIN_PASSWORD", "") or "").strip()
    if not platform_email or not platform_password:
        return

    db = session_factory()
    try:
        existing = db.query(user_model).filter(user_model.email == platform_email).first()
        if existing:
            return
        platform_name = (os.getenv("PLATFORM_ADMIN_NAME", "") or "").strip() or "Platform Admin"
        user = user_model(
            email=platform_email,
            name=platform_name,
            password_hash=hash_password(platform_password),
            role=role_enum.platform_admin,
            company_id=None,
            email_verified=True,
            email_verified_at=utc_now_naive(),
            **normalize_capability_flags(role_enum.platform_admin),
        )
        db.add(user)
        db.commit()
    finally:
        db.close()


def start_background_threads(
    *,
    push_enabled: bool,
    template_autogen_enabled: bool,
    deadline_runner: Callable[[], None],
    template_runner: Callable[[], None],
    archive_runner: Callable[[], None],
) -> None:
    if push_enabled:
        threading.Thread(target=deadline_runner, daemon=True).start()
    if template_autogen_enabled:
        threading.Thread(target=template_runner, daemon=True).start()
    threading.Thread(target=archive_runner, daemon=True).start()
