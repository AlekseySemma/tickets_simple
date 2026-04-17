from datetime import timedelta
import secrets
from urllib.parse import quote

from fastapi import HTTPException
from app_support.time_support import utc_now_naive


def hash_password(password: str, *, pwd_context) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str, *, pwd_context) -> bool:
    return pwd_context.verify(password, password_hash)


def get_user_auth_token_version(user: object | None) -> int:
    if not user:
        return 0
    return int(getattr(user, "auth_token_version", 0) or 0)


def bump_user_auth_token_version(user: object) -> int:
    next_value = get_user_auth_token_version(user) + 1
    user.auth_token_version = next_value
    return next_value


def create_access_token(
    subject: str,
    token_version: int = 0,
    *,
    jwt_module,
    jwt_secret: str,
    algorithm: str,
    access_token_expire_minutes: int,
    now_utc_fn=utc_now_naive,
) -> str:
    exp = now_utc_fn() + timedelta(minutes=access_token_expire_minutes)
    return jwt_module.encode(
        {"sub": subject, "exp": exp, "tv": int(token_version)},
        jwt_secret,
        algorithm=algorithm,
    )


class EmailDeliveryError(RuntimeError):
    pass


def is_email_verification_required(user: object | None, *, platform_admin_role) -> bool:
    return bool(user and getattr(user, "role", None) != platform_admin_role)


def is_user_email_verified(user: object | None, *, platform_admin_role) -> bool:
    if not user:
        return False
    if not is_email_verification_required(user, platform_admin_role=platform_admin_role):
        return True
    return bool(getattr(user, "email_verified", False))


def ensure_user_can_authenticate(
    user: object,
    *,
    platform_admin_role,
    http_exception_cls=HTTPException,
) -> None:
    if not is_user_email_verified(user, platform_admin_role=platform_admin_role):
        raise http_exception_cls(status_code=403, detail="Email address is not verified")


def mark_user_email_verified(user: object, *, now_utc_fn=utc_now_naive) -> None:
    now = now_utc_fn()
    user.email_verified = True
    user.email_verified_at = now
    user.email_verification_token = None
    user.email_verification_expires_at = None
    user.email_verification_sent_at = None


def prepare_user_email_verification(
    user: object,
    *,
    email_verification_expire_hours: int,
    force_new_token: bool = False,
    now_utc_fn=utc_now_naive,
    token_factory=secrets.token_urlsafe,
) -> str:
    now = now_utc_fn()
    token_value = (getattr(user, "email_verification_token", None) or "").strip()
    token_expired = bool(
        getattr(user, "email_verification_expires_at", None)
        and getattr(user, "email_verification_expires_at") <= now
    )
    if force_new_token or not token_value or token_expired:
        token_value = token_factory(32)
        user.email_verification_token = token_value
        user.email_verification_expires_at = now + timedelta(hours=email_verification_expire_hours)
    user.email_verified = False
    user.email_verified_at = None
    return token_value


def clear_password_reset_state(user: object) -> None:
    user.password_reset_token = None
    user.password_reset_expires_at = None
    user.password_reset_sent_at = None


def prepare_user_password_reset(
    user: object,
    *,
    password_reset_expire_hours: int,
    force_new_token: bool = False,
    now_utc_fn=utc_now_naive,
    token_factory=secrets.token_urlsafe,
) -> str:
    now = now_utc_fn()
    token_value = (getattr(user, "password_reset_token", None) or "").strip()
    token_expired = bool(
        getattr(user, "password_reset_expires_at", None)
        and getattr(user, "password_reset_expires_at") <= now
    )
    if force_new_token or not token_value or token_expired:
        token_value = token_factory(32)
        user.password_reset_token = token_value
        user.password_reset_expires_at = now + timedelta(hours=password_reset_expire_hours)
    return token_value


def build_email_verification_url(request, token: str, *, quote_fn=quote) -> str:
    return f"{str(request.base_url).rstrip('/')}/web/verify-email?token={quote_fn(token)}"


def build_password_reset_url(request, token: str, *, quote_fn=quote) -> str:
    return f"{str(request.base_url).rstrip('/')}/web/password-reset/confirm?token={quote_fn(token)}"


def normalize_auth_cookie_host(raw_host: str | None) -> str:
    host = (raw_host or "").split(",")[0].strip().lower()
    if not host:
        return ""
    if host.startswith("["):
        return host
    if ":" in host:
        host = host.split(":", 1)[0].strip()
    return host


def normalize_auth_cookie_domain(raw_domain: str | None) -> str | None:
    value = (raw_domain or "").strip().lower()
    if not value:
        return None
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split(":", 1)[0].strip().strip(".")
    if not value:
        return None
    return f".{value}"


def host_matches_auth_cookie_domain(host: str, cookie_domain: str | None) -> bool:
    normalized_host = normalize_auth_cookie_host(host)
    normalized_domain = normalize_auth_cookie_domain(cookie_domain)
    if not normalized_host or not normalized_domain:
        return False
    bare_domain = normalized_domain.lstrip(".")
    return normalized_host == bare_domain or normalized_host.endswith(f".{bare_domain}")


def get_auth_cookie_params(
    request,
    *,
    access_token_cookie_max_age: int,
    auth_cookie_domain: str | None = None,
) -> dict[str, object]:
    host = normalize_auth_cookie_host(request.headers.get("x-forwarded-host") or request.headers.get("host") or "")
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    scheme = forwarded_proto or request.url.scheme

    cookie_domain = None
    configured_cookie_domain = normalize_auth_cookie_domain(auth_cookie_domain)
    if configured_cookie_domain and host_matches_auth_cookie_domain(host, configured_cookie_domain):
        cookie_domain = configured_cookie_domain
    elif host.endswith(".servora.ru") or host == "servora.ru":
        cookie_domain = ".servora.ru"

    return {
        "httponly": True,
        "samesite": "lax",
        "secure": (scheme == "https"),
        "domain": cookie_domain,
        "path": "/",
        "max_age": access_token_cookie_max_age,
        "expires": access_token_cookie_max_age,
    }


def delete_auth_cookie(
    response,
    request,
    *,
    access_token_cookie_max_age: int,
    auth_cookie_domain: str | None = None,
) -> None:
    cookie_params = get_auth_cookie_params(
        request,
        access_token_cookie_max_age=access_token_cookie_max_age,
        auth_cookie_domain=auth_cookie_domain,
    )
    response.delete_cookie(
        "access_token",
        domain=cookie_params.get("domain"),
        path=str(cookie_params.get("path") or "/"),
    )


def resolve_current_user(
    request,
    token: str | None,
    db,
    *,
    user_model,
    jwt_module,
    jwt_secret: str,
    algorithm: str,
    get_user_auth_token_version_func,
    ensure_user_can_authenticate_func,
    http_exception_cls=HTTPException,
):
    final_token = (token or "") or (request.cookies.get("access_token") or "")
    if not final_token:
        raise http_exception_cls(status_code=401, detail="Not authenticated")

    try:
        payload = jwt_module.decode(final_token, jwt_secret, algorithms=[algorithm])
        user_id = int(payload.get("sub"))
        token_version = int(payload.get("tv", 0) or 0)
    except Exception as exc:
        if exc.__class__.__name__ in {"JWTError", "ExpiredSignatureError"} or isinstance(
            exc, (ValueError, TypeError)
        ):
            raise http_exception_cls(status_code=401, detail="Invalid token")
        raise

    user = db.get(user_model, user_id)
    if not user:
        raise http_exception_cls(status_code=401, detail="User not found")
    if token_version != get_user_auth_token_version_func(user):
        raise http_exception_cls(status_code=401, detail="Token is no longer valid")
    ensure_user_can_authenticate_func(user)
    return user


def get_active_invite(
    db,
    token: str | None,
    *,
    registration_invite_model,
    now_utc_fn=utc_now_naive,
):
    token_value = (token or "").strip()
    if not token_value:
        return None
    invite = db.query(registration_invite_model).filter(registration_invite_model.token == token_value).first()
    if not invite:
        return None
    if invite.used_by is not None:
        return None
    if invite.expires_at and invite.expires_at < now_utc_fn():
        return None
    if invite.company_id is None:
        return None
    return invite
