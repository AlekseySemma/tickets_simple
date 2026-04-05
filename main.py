from calendar import monthrange
from datetime import datetime, timedelta, date
import csv
from decimal import Decimal, InvalidOperation
from email.message import EmailMessage
from functools import partial
import io
import json
import logging
import os
from pathlib import Path
import re
import smtplib
import threading
import time
import zipfile
from typing import Optional
import uuid
from urllib.parse import quote, urlencode
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.responses import RedirectResponse, FileResponse, Response, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, String, Text, DateTime, Date, ForeignKey, Enum as SAEnum, Integer, Boolean, Numeric, UniqueConstraint, func, or_, cast, text, inspect as sa_inspect
from sqlalchemy.exc import SQLAlchemyError, OperationalError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from starlette.templating import Jinja2Templates
from starlette.status import HTTP_303_SEE_OTHER
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse
from app_routes.admin_companies import register_admin_company_routes
from app_routes.auth import register_auth_routes, register_company_owner
from app_routes.notifications import register_notification_routes
from app_routes.org_structure import register_org_structure_routes
from app_routes.payment_cards import register_payment_card_routes
from app_routes.public import register_public_routes
from app_routes.push_mobile import register_push_mobile_routes
from app_routes.reference_data_api import register_reference_data_api_routes
from app_routes.receipt_actions import register_receipt_action_routes
from app_routes.receipt_exports import register_receipt_export_routes
from app_routes.receipts import register_receipt_routes
from app_routes.settings import register_settings_routes
from app_routes.ticket_create import register_ticket_create_routes
from app_routes.ticket_detail import register_ticket_detail_routes
from app_routes.ticket_templates import register_ticket_template_routes
from app_routes.ticket_types import register_ticket_type_routes
from app_routes.ticket_actions import register_ticket_action_routes
from app_routes.ticket_catalog_api import register_ticket_catalog_api_routes
from app_routes.tickets_overview import register_ticket_overview_routes
from app_routes.tickets_api import register_tickets_api_routes
from app_routes.users import register_user_management_routes
from app_routes.users_api import register_users_api_routes
from app_routes.web_auth import register_web_auth_routes
from app_support.access import (
    can_access_receipt,
    can_access_ticket,
    can_archive_ticket,
    can_close_ticket,
    can_create_company_ticket,
    can_delete_comment,
    can_delete_ticket,
    can_edit_ticket,
    can_manage_ticket_legal_hold,
    can_restore_ticket,
    can_take_ticket_in_work,
    can_view_all_company_tickets,
    ensure_company_user,
    is_admin,
    is_assignable_executor_user,
    is_manager,
    is_platform_admin,
)
from app_support.auth_core import (
    EmailDeliveryError,
    build_email_verification_url as core_build_email_verification_url,
    build_password_reset_url as core_build_password_reset_url,
    bump_user_auth_token_version as core_bump_user_auth_token_version,
    clear_password_reset_state,
    create_access_token as core_create_access_token,
    delete_auth_cookie as core_delete_auth_cookie,
    ensure_user_can_authenticate as core_ensure_user_can_authenticate,
    get_active_invite as core_get_active_invite,
    get_auth_cookie_params as core_get_auth_cookie_params,
    get_user_auth_token_version as core_get_user_auth_token_version,
    hash_password as core_hash_password,
    is_email_verification_required as core_is_email_verification_required,
    is_user_email_verified as core_is_user_email_verified,
    mark_user_email_verified as core_mark_user_email_verified,
    prepare_user_email_verification as core_prepare_user_email_verification,
    prepare_user_password_reset as core_prepare_user_password_reset,
    resolve_current_user,
    verify_password as core_verify_password,
)
from app_support.comment_service import CommentService
from app_support.company_cleanup import CompanyCleanupService
from app_support.deadline_reminder_service import DeadlineReminderService
from app_support.email_auth_support import EmailAuthSupport
from app_support.enums import (
    ARCHIVE_SOURCE_STATUSES,
    COMPANY_ACCESS_LEVELS,
    DEFAULT_ROLE_TEMPLATE_PRESETS,
    FINAL_TICKET_STATUSES,
    MANAGER_ROLES,
    MAX_ROLE_LABEL_LEN,
    MAX_ROLE_TEMPLATE_NAME_LEN,
    ReceiptStatus,
    Role,
    TicketStatus,
    access_level_label_ru,
    receipt_status_label_ru,
    status_label_ru,
    ticket_status_change_log_action,
)
from app_support.notification_service import NotificationService
from app_support.receipt_support import ReceiptSupport
from app_support.startup import (
    ensure_platform_admin_user,
    maybe_repair_text_on_start,
    start_background_threads,
)
from app_support.storage import StorageService
from app_support.ticket_runtime_service import TicketRuntimeService
from app_support.user_management import can_manage_company_user, manageable_roles_for_web_user_management
from app_support.web import (
    append_query_params,
    first_header_value,
    get_client_ip,
    normalize_origin,
    request_origin,
    safe_next,
)
from app_support.web_tickets import render_web_tickets_page
try:
    from pywebpush import webpush, WebPushException
    PYWEBPUSH_AVAILABLE = True
except Exception:
    webpush = None
    class WebPushException(Exception):
        pass
    PYWEBPUSH_AVAILABLE = False
try:
    import boto3
    from botocore.client import Config as BotoConfig
    from botocore.exceptions import BotoCoreError, ClientError
    BOTO3_AVAILABLE = True
except Exception:
    boto3 = None
    BotoConfig = None
    class BotoCoreError(Exception):
        pass
    class ClientError(Exception):
        pass
    BOTO3_AVAILABLE = False
try:
    import firebase_admin
    from firebase_admin import credentials as firebase_credentials
    from firebase_admin import messaging as firebase_messaging
    FIREBASE_ADMIN_AVAILABLE = True
except Exception:
    firebase_admin = None
    firebase_credentials = None
    firebase_messaging = None
    FIREBASE_ADMIN_AVAILABLE = False

logger = logging.getLogger(__name__)


# =========================
# РќР°СЃС‚СЂРѕР№РєРё (РїСЂРѕСЃС‚С‹Рµ)
# =========================
JWT_SECRET = (os.getenv("JWT_SECRET") or "").strip()
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be set and contain at least 32 characters")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 РґРЅРµР№
ACCESS_TOKEN_COOKIE_MAX_AGE = ACCESS_TOKEN_EXPIRE_MINUTES * 60
PUBLIC_WEB_PATHS = {
    "/web/login",
    "/web/register",
    "/web/register-company",
    "/web/logout",
    "/web/verify-email",
    "/web/verify-email/resend",
    "/web/password-reset",
    "/web/password-reset/confirm",
}
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
ARCHIVE_UPLOAD_SUBDIR = "_archive"
ARCHIVE_UPLOAD_DIR = UPLOAD_DIR / ARCHIVE_UPLOAD_SUBDIR
STORAGE_BACKEND = (os.getenv("STORAGE_BACKEND", "local") or "local").strip().lower()
if STORAGE_BACKEND not in {"local", "s3"}:
    raise RuntimeError("STORAGE_BACKEND must be either 'local' or 's3'")
S3_ENDPOINT_URL = (os.getenv("S3_ENDPOINT_URL") or "").strip()
S3_BUCKET = (os.getenv("S3_BUCKET") or "").strip()
S3_ACCESS_KEY = (os.getenv("S3_ACCESS_KEY") or "").strip()
S3_SECRET_KEY = (os.getenv("S3_SECRET_KEY") or "").strip()
S3_REGION = (os.getenv("S3_REGION") or "").strip()
S3_PRESIGNED_TTL_SECONDS = max(60, int(os.getenv("S3_PRESIGNED_TTL_SECONDS", "3600")))
S3_ADDRESSING_STYLE = (os.getenv("S3_ADDRESSING_STYLE", "path") or "path").strip().lower()
ATTACHMENTS_STORAGE_PREFIX = "attachments"
COMMENT_MEDIA_STORAGE_PREFIX = "comment-media"
RECEIPTS_STORAGE_PREFIX = "receipts"
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", 10 * 1024 * 1024))
ALLOWED_UPLOAD_EXTENSIONS = {
    ext.strip().lower()
    for ext in os.getenv(
        "ALLOWED_UPLOAD_EXTENSIONS",
        ".png,.jpg,.jpeg,.gif,.webp,.pdf,.txt,.doc,.docx,.xls,.xlsx,.zip,.rar,.mp3,.ogg,.oga,.wav,.m4a,.aac,.webm,.opus",
    ).split(",")
    if ext.strip()
}
COMMENT_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
COMMENT_AUDIO_EXTENSIONS = {".mp3", ".ogg", ".oga", ".wav", ".m4a", ".aac", ".webm", ".opus"}
COMMENT_MEDIA_EXTENSIONS = set(ALLOWED_UPLOAD_EXTENSIONS)
PWA_STATIC_DIR = Path(os.getenv("PWA_STATIC_DIR", "./static"))
PUSH_REMINDER_MINUTES = int(os.getenv("PUSH_REMINDER_MINUTES", "60"))
PUSH_REMINDER_POLL_SECONDS = int(os.getenv("PUSH_REMINDER_POLL_SECONDS", "30"))
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "").strip()
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "").strip()
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:admin@example.com").strip()
FIREBASE_CREDENTIALS_FILE = (os.getenv("FIREBASE_CREDENTIALS_FILE") or "").strip()
MAX_TICKET_TITLE_LEN = 255
NOTIFICATION_TICKET_TITLE_PREVIEW_LEN = 30
MIN_ARCHIVE_RETENTION_DAYS = 1
MAX_ARCHIVE_RETENTION_DAYS = 3650
DEFAULT_ARCHIVE_RETENTION_DAYS = max(
    MIN_ARCHIVE_RETENTION_DAYS,
    min(
        MAX_ARCHIVE_RETENTION_DAYS,
        int(os.getenv("DEFAULT_ARCHIVE_RETENTION_DAYS", "180")),
    ),
)
ARCHIVE_CLEANUP_POLL_SECONDS = max(3600, int(os.getenv("ARCHIVE_CLEANUP_POLL_SECONDS", "86400")))
MIN_DEADLINE_SOON_WARNING_MINUTES = 5
MAX_DEADLINE_SOON_WARNING_MINUTES = 10080
DEFAULT_DEADLINE_SOON_WARNING_MINUTES = max(
    MIN_DEADLINE_SOON_WARNING_MINUTES,
    min(
        MAX_DEADLINE_SOON_WARNING_MINUTES,
        int(os.getenv("DEFAULT_DEADLINE_SOON_WARNING_MINUTES", "1440")),
    ),
)
SETTINGS_SECTIONS = {
    "general": {
        "id": "general",
        "title": "Общие",
        "description": "Базовые параметры работы заявок и подсветки сроков.",
    },
    "notifications": {
        "id": "notifications",
        "title": "Уведомления",
        "description": "Комментарии, чеки и push-уведомления.",
    },
    "receipts": {
        "id": "receipts",
        "title": "Чеки",
        "description": "Карта по умолчанию и справочник карт для загрузки чеков.",
    },
    "archive": {
        "id": "archive",
        "title": "Архив",
        "description": "Срок хранения архивных заявок и связанных данных.",
    },
    "system": {
        "id": "system",
        "title": "Система",
        "description": "Безопасность аккаунта и служебная диагностика.",
    },
    "directories": {
        "id": "directories",
        "title": "Справочники",
        "description": "Административные разделы и справочники компании.",
    },
}
ORG_STRUCTURE_SECTIONS = {
    "nodes": {
        "id": "nodes",
        "title": "Узлы и отделы",
        "description": "Дерево структуры, отделы и редактирование узлов.",
    },
    "executors": {
        "id": "executors",
        "title": "Исполнители",
        "description": "Назначение исполнителей и управление закреплениями.",
    },
    "import": {
        "id": "import",
        "title": "Импорт",
        "description": "Загрузка оргструктуры из CSV и шаблон для выгрузки.",
    },
}
ANDROID_APP_USER_AGENT_TOKEN = "servoraandroidapp"
_FIREBASE_APP = None
_FIREBASE_APP_LOCK = threading.Lock()
TICKET_BULK_ACTION_LABELS = {
    "archive": "перенос в архив",
    "delete": "удаление",
    "restore": "восстановление",
    "legal_hold_on": "включение Legal hold",
    "legal_hold_off": "снятие Legal hold",
}
ORG_STRUCTURE_NODE_ERRORS = {
    "empty_name",
    "bad_parent",
    "parent_not_found",
    "create_failed",
    "department_empty_name",
    "department_exists",
    "department_not_found",
    "department_in_use",
    "department_save_failed",
    "edit_not_found",
    "edit_empty_name",
    "edit_bad_parent",
    "edit_parent_not_found",
    "edit_cycle",
    "edit_failed",
    "delete_not_found",
    "delete_has_children",
    "delete_has_assignments",
    "delete_has_templates",
    "delete_has_tickets",
    "delete_has_generation_keys",
    "delete_failed",
}
ORG_STRUCTURE_EXECUTOR_ERRORS = {
    "assign_bad_input",
    "assign_unit_not_found",
    "assign_executor_not_found",
    "assign_department_not_found",
    "assign_failed",
}
ORG_STRUCTURE_IMPORT_ERRORS = {
    "import_empty",
    "import_read_failed",
    "import_encoding",
    "import_headers",
    "import_need_path",
    "import_failed",
}
LOCAL_TIME_OFFSET_HOURS = int(os.getenv("LOCAL_TIME_OFFSET_HOURS", "3"))
RL_LOGIN_LIMIT = int(os.getenv("RL_LOGIN_LIMIT", "10"))
RL_LOGIN_WINDOW_SEC = int(os.getenv("RL_LOGIN_WINDOW_SEC", "300"))
RL_REGISTER_LIMIT = int(os.getenv("RL_REGISTER_LIMIT", "8"))
RL_REGISTER_WINDOW_SEC = int(os.getenv("RL_REGISTER_WINDOW_SEC", "3600"))
RL_EMAIL_VERIFICATION_LIMIT = int(os.getenv("RL_EMAIL_VERIFICATION_LIMIT", "6"))
RL_EMAIL_VERIFICATION_WINDOW_SEC = int(os.getenv("RL_EMAIL_VERIFICATION_WINDOW_SEC", "3600"))
RL_PASSWORD_RESET_LIMIT = int(os.getenv("RL_PASSWORD_RESET_LIMIT", "6"))
RL_PASSWORD_RESET_WINDOW_SEC = int(os.getenv("RL_PASSWORD_RESET_WINDOW_SEC", "3600"))
RL_PUSH_TEST_LIMIT = int(os.getenv("RL_PUSH_TEST_LIMIT", "10"))
RL_PUSH_TEST_WINDOW_SEC = int(os.getenv("RL_PUSH_TEST_WINDOW_SEC", "3600"))
SMTP_HOST = (os.getenv("SMTP_HOST") or "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = (os.getenv("SMTP_USERNAME") or "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = (os.getenv("SMTP_FROM_EMAIL") or SMTP_USERNAME or "").strip()
SMTP_FROM_NAME = (os.getenv("SMTP_FROM_NAME") or "servora").strip()
SMTP_USE_TLS = (os.getenv("SMTP_USE_TLS", "1").strip().lower() in {"1", "true", "yes", "on"})
SMTP_USE_SSL = (os.getenv("SMTP_USE_SSL", "0").strip().lower() in {"1", "true", "yes", "on"})
SMTP_TIMEOUT_SEC = max(5, int(os.getenv("SMTP_TIMEOUT_SEC", "20")))
EMAIL_VERIFICATION_EXPIRE_HOURS = max(1, int(os.getenv("EMAIL_VERIFICATION_EXPIRE_HOURS", "24")))
PASSWORD_RESET_EXPIRE_HOURS = max(1, int(os.getenv("PASSWORD_RESET_EXPIRE_HOURS", "2")))
ORG_STRUCTURE_V2_ENABLED = (os.getenv("ORG_STRUCTURE_V2_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"})
TEMPLATE_AUTOGEN_ENABLED = (os.getenv("TEMPLATE_AUTOGEN_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"})
TEMPLATE_AUTOGEN_POLL_SECONDS = max(30, int(os.getenv("TEMPLATE_AUTOGEN_POLL_SECONDS", "300")))
TEXT_REPAIR_ON_START = (os.getenv("TEXT_REPAIR_ON_START", "1").strip().lower() in {"1", "true", "yes", "on"})
if STORAGE_BACKEND == "s3":
    if not BOTO3_AVAILABLE:
        raise RuntimeError("boto3 must be installed when STORAGE_BACKEND=s3")
    missing_s3 = [
        name
        for name, value in (
            ("S3_ENDPOINT_URL", S3_ENDPOINT_URL),
            ("S3_BUCKET", S3_BUCKET),
            ("S3_ACCESS_KEY", S3_ACCESS_KEY),
            ("S3_SECRET_KEY", S3_SECRET_KEY),
        )
        if not value
    ]
    if missing_s3:
        raise RuntimeError(f"Missing S3 settings: {', '.join(missing_s3)}")

# =========================
# Р‘Р°Р·Р° РґР°РЅРЅС‹С… (SQLite)
# =========================
engine_kwargs = {}
if DB_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DB_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class Base(DeclarativeBase):
    pass

# =========================
# РњРѕРґРµР»Рё
# =========================
def ticket_field_change_log_action(field_label: str, old_value: str | None, new_value: str | None) -> str:
    old_text = (old_value or "").strip() or "\u2014"
    new_text = (new_value or "").strip() or "\u2014"
    return f"\u0418\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 {field_label}: {old_text} -> {new_text}"


def _ticket_user_name(db: Session, user_id: int | None) -> str | None:
    if not user_id:
        return None
    row = db.get(User, user_id)
    if row and (row.name or "").strip():
        return row.name
    return f"#{user_id}"


def _ticket_project_name(db: Session, project_id: int | None) -> str | None:
    if not project_id:
        return None
    row = db.get(Project, project_id)
    if row and (row.name or "").strip():
        return row.name
    return f"#{project_id}"


def _ticket_type_name(db: Session, ticket_type_id: int | None) -> str | None:
    if not ticket_type_id:
        return None
    row = db.get(TicketType, ticket_type_id)
    if row and (row.name or "").strip():
        return row.name
    return f"#{ticket_type_id}"


def _department_name(db: Session, department_id: int | None) -> str | None:
    if not department_id:
        return None
    row = db.get(Department, department_id)
    if row and (row.name or "").strip():
        return row.name
    return f"#{department_id}"


def _ticket_deadline_text(value: datetime | None) -> str | None:
    return format_deadline(value) if value else None


def normalize_role_label(raw_value: str | None) -> str | None:
    value = " ".join(str(raw_value or "").split()).strip()
    if not value:
        return None
    return value[:MAX_ROLE_LABEL_LEN]


def normalize_role_template_name(raw_value: str | None) -> str | None:
    value = " ".join(str(raw_value or "").split()).strip()
    if not value:
        return None
    return value[:MAX_ROLE_TEMPLATE_NAME_LEN]


def default_is_assignable_executor(role: Role) -> bool:
    return role in (Role.admin, Role.executor)


def default_show_receipts_accounting_mode(role: Role) -> bool:
    return role != Role.executor


def normalize_capability_flags(
    access_level: Role,
    *,
    show_receipts_accounting_mode: bool | None = None,
    is_assignable_executor: bool | None = None,
    can_view_all_tickets: bool | None = None,
    can_create_tickets: bool | None = None,
    can_close_tickets: bool | None = None,
) -> dict[str, bool]:
    normalized = {
        "show_receipts_accounting_mode": (
            default_show_receipts_accounting_mode(access_level)
            if show_receipts_accounting_mode is None
            else bool(show_receipts_accounting_mode)
        ),
        "is_assignable_executor": (
            default_is_assignable_executor(access_level)
            if is_assignable_executor is None
            else bool(is_assignable_executor)
        ),
        "can_view_all_tickets": bool(can_view_all_tickets),
        "can_create_tickets": True if can_create_tickets is None else bool(can_create_tickets),
        "can_close_tickets": True if can_close_tickets is None else bool(can_close_tickets),
    }
    if access_level in MANAGER_ROLES:
        normalized["can_view_all_tickets"] = True
        normalized["can_create_tickets"] = True
        normalized["can_close_tickets"] = True
    if access_level == Role.platform_admin:
        normalized["show_receipts_accounting_mode"] = True
        normalized["is_assignable_executor"] = False
        normalized["can_view_all_tickets"] = False
        normalized["can_create_tickets"] = False
        normalized["can_close_tickets"] = False
    return normalized


def is_assignable_executor_user(user: object | None) -> bool:
    if not user:
        return False
    role_value = getattr(user, "role", None)
    if role_value == Role.platform_admin:
        return False
    return bool(getattr(user, "is_assignable_executor", False))

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    email_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false"),
    )
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    email_verification_token: Mapped[Optional[str]] = mapped_column(String(255), unique=True, index=True, default=None)
    email_verification_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    email_verification_sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    password_reset_token: Mapped[Optional[str]] = mapped_column(String(255), unique=True, index=True, default=None)
    password_reset_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    password_reset_sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    auth_token_version: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default=text("0"),
    )
    role: Mapped[Role] = mapped_column(SAEnum(Role), index=True)
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"), index=True, default=None)
    preferred_payment_card_id: Mapped[Optional[int]] = mapped_column(ForeignKey("payment_cards.id"), index=True, default=None)
    bk_last4: Mapped[Optional[str]] = mapped_column(String(4), default=None)
    notify_comments_as_watcher: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )
    notify_receipt_created: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )
    role_label: Mapped[Optional[str]] = mapped_column(String(MAX_ROLE_LABEL_LEN), default=None)
    show_receipts_accounting_mode: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )
    is_assignable_executor: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false"),
    )
    can_view_all_tickets: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false"),
    )
    can_create_tickets: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )
    can_close_tickets: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )

class Company(Base):
    __tablename__ = "companies"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    deadline_soon_warning_minutes: Mapped[int] = mapped_column(
        Integer,
        default=DEFAULT_DEADLINE_SOON_WARNING_MINUTES,
        server_default=str(DEFAULT_DEADLINE_SOON_WARNING_MINUTES),
    )
    archive_retention_days_default: Mapped[int] = mapped_column(
        Integer,
        default=DEFAULT_ARCHIVE_RETENTION_DAYS,
        server_default=str(DEFAULT_ARCHIVE_RETENTION_DAYS),
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RoleTemplate(Base):
    __tablename__ = "role_templates"
    __table_args__ = (UniqueConstraint("company_id", "name", name="uq_role_templates_company_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(MAX_ROLE_TEMPLATE_NAME_LEN))
    access_level: Mapped[Role] = mapped_column(SAEnum(Role), index=True)
    is_assignable_executor: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false"),
    )
    show_receipts_accounting_mode: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )
    can_view_all_tickets: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false"),
    )
    can_create_tickets: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )
    can_close_tickets: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )

    def __init__(self, **kwargs):
        role = kwargs.get("role")
        if isinstance(role, Role):
            normalized = normalize_capability_flags(
                role,
                show_receipts_accounting_mode=kwargs.get("show_receipts_accounting_mode"),
                is_assignable_executor=kwargs.get("is_assignable_executor"),
                can_view_all_tickets=kwargs.get("can_view_all_tickets"),
                can_create_tickets=kwargs.get("can_create_tickets"),
                can_close_tickets=kwargs.get("can_close_tickets"),
            )
            for key, value in normalized.items():
                kwargs.setdefault(key, value)
        super().__init__(**kwargs)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class RegistrationInvite(Base):
    __tablename__ = "registration_invites"
    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[Role] = mapped_column(SAEnum(Role), index=True)
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"), index=True, default=None)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    used_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)

class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("company_id", "name", name="uq_projects_company_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"), index=True, default=None)


class Department(Base):
    __tablename__ = "departments"
    __table_args__ = (UniqueConstraint("company_id", "name", name="uq_departments_company_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PaymentCard(Base):
    __tablename__ = "payment_cards"
    __table_args__ = (UniqueConstraint("company_id", "owner_user_id", "name", name="uq_payment_cards_company_owner_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Receipt(Base):
    __tablename__ = "receipts"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    card_id: Mapped[int] = mapped_column(ForeignKey("payment_cards.id"), index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[ReceiptStatus] = mapped_column(SAEnum(ReceiptStatus), default=ReceiptStatus.new, index=True)
    comment: Mapped[str] = mapped_column(Text)
    amount: Mapped[Optional[Decimal]] = mapped_column(Numeric(12, 2), default=None)
    receipt_date: Mapped[Optional[date]] = mapped_column(Date, default=None)
    category: Mapped[Optional[str]] = mapped_column(String(255), default=None)
    supplier: Mapped[Optional[str]] = mapped_column(String(255), default=None)
    processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    processed_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ReceiptFile(Base):
    __tablename__ = "receipt_files"
    id: Mapped[int] = mapped_column(primary_key=True)
    receipt_id: Mapped[int] = mapped_column(ForeignKey("receipts.id"), index=True)
    uploader_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    file_path: Mapped[str] = mapped_column(String(500))
    original_name: Mapped[Optional[str]] = mapped_column(String(255), default=None)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    file_sha256: Mapped[Optional[str]] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UnitType(Base):
    __tablename__ = "unit_types"
    __table_args__ = (
        UniqueConstraint("company_id", "name", name="uq_unit_types_company_name"),
        UniqueConstraint("company_id", "code", name="uq_unit_types_company_code"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    code: Mapped[Optional[str]] = mapped_column(String(80), default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class OrgUnit(Base):
    __tablename__ = "org_units"
    __table_args__ = (UniqueConstraint("company_id", "parent_id", "name", name="uq_org_units_company_parent_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    unit_type_id: Mapped[int] = mapped_column(ForeignKey("unit_types.id"), index=True)
    parent_id: Mapped[Optional[int]] = mapped_column(ForeignKey("org_units.id"), index=True, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UnitAssignment(Base):
    __tablename__ = "unit_assignments"
    __table_args__ = (
        UniqueConstraint(
            "company_id",
            "unit_id",
            "user_id",
            "role_code",
            "department_id",
            name="uq_unit_assignments_company_unit_user_role_department",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    unit_id: Mapped[int] = mapped_column(ForeignKey("org_units.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    role_code: Mapped[str] = mapped_column(String(64), index=True)
    department_id: Mapped[Optional[int]] = mapped_column(ForeignKey("departments.id"), index=True, default=None)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TicketType(Base):
    __tablename__ = "ticket_types"
    __table_args__ = (UniqueConstraint("company_id", "name", name="uq_ticket_types_company_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    department_id: Mapped[Optional[int]] = mapped_column(ForeignKey("departments.id"), index=True, default=None)
    archive_retention_days: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TicketTemplate(Base):
    __tablename__ = "ticket_templates"
    __table_args__ = (UniqueConstraint("company_id", "name", name="uq_ticket_templates_company_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    ticket_type_id: Mapped[int] = mapped_column(ForeignKey("ticket_types.id"), index=True)
    department_id: Mapped[Optional[int]] = mapped_column(ForeignKey("departments.id"), index=True, default=None)
    name: Mapped[str] = mapped_column(String(255), index=True)
    title_template: Mapped[Optional[str]] = mapped_column(Text, default=None)
    description_template: Mapped[Optional[str]] = mapped_column(Text, default=None)
    default_deadline_rule: Mapped[Optional[str]] = mapped_column(String(64), default=None)
    default_executor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, default=None)
    scope_unit_id: Mapped[Optional[int]] = mapped_column(ForeignKey("org_units.id"), index=True, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    deadline: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    status: Mapped[TicketStatus] = mapped_column(SAEnum(TicketStatus), default=TicketStatus.new, index=True)
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"), index=True, default=None)

    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    executor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, default=None)
    ticket_type_id: Mapped[Optional[int]] = mapped_column(ForeignKey("ticket_types.id"), index=True, default=None)
    department_id: Mapped[Optional[int]] = mapped_column(ForeignKey("departments.id"), index=True, default=None)
    target_unit_id: Mapped[Optional[int]] = mapped_column(ForeignKey("org_units.id"), index=True, default=None)
    ticket_template_id: Mapped[Optional[int]] = mapped_column(ForeignKey("ticket_templates.id"), index=True, default=None)
    period_key: Mapped[Optional[str]] = mapped_column(String(16), index=True, default=None)
    batch_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, default=None)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None, index=True)
    archived_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, default=None)
    retention_days: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    delete_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None, index=True)
    is_legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TicketWatcher(Base):
    __tablename__ = "ticket_watchers"
    __table_args__ = (UniqueConstraint("ticket_id", "user_id", name="uq_ticket_watchers_ticket_user"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    added_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class TicketGenerationKey(Base):
    __tablename__ = "ticket_generation_keys"
    __table_args__ = (
        UniqueConstraint(
            "company_id",
            "ticket_template_id",
            "target_unit_id",
            "period_key",
            name="uq_ticket_generation_keys_scope",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    ticket_template_id: Mapped[int] = mapped_column(ForeignKey("ticket_templates.id"), index=True)
    target_unit_id: Mapped[int] = mapped_column(ForeignKey("org_units.id"), index=True)
    period_key: Mapped[str] = mapped_column(String(16), index=True)
    ticket_id: Mapped[Optional[int]] = mapped_column(Integer, default=None, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class Comment(Base):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"), index=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class CommentMedia(Base):
    __tablename__ = "comment_media"
    id: Mapped[int] = mapped_column(primary_key=True)
    comment_id: Mapped[int] = mapped_column(ForeignKey("comments.id"), index=True)
    file_path: Mapped[str] = mapped_column(String(500))
    original_name: Mapped[Optional[str]] = mapped_column(String(255), default=None)
    media_kind: Mapped[str] = mapped_column(String(16))
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    file_sha256: Mapped[Optional[str]] = mapped_column(String(64), default=None)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Attachment(Base):
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"), index=True)
    uploader_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    file_path: Mapped[str] = mapped_column(String(500))
    original_name: Mapped[Optional[str]] = mapped_column(String(255), default=None)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    file_sha256: Mapped[Optional[str]] = mapped_column(String(64), default=None)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class TicketLog(Base):
    __tablename__ = "ticket_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class PushSubscription(Base):
    __tablename__ = "push_subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    endpoint: Mapped[str] = mapped_column(String(1000), unique=True, index=True)
    p256dh: Mapped[str] = mapped_column(String(255))
    auth: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class MobileDevice(Base):
    __tablename__ = "mobile_devices"
    __table_args__ = (
        UniqueConstraint("platform", "device_id", name="uq_mobile_devices_platform_device"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    platform: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(128))
    token: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    app_version: Mapped[Optional[str]] = mapped_column(String(64), default=None)
    device_name: Mapped[Optional[str]] = mapped_column(String(255), default=None)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class DeadlineReminderLog(Base):
    __tablename__ = "deadline_reminder_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    reminder_key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ArchiveCleanupLog(Base):
    __tablename__ = "archive_cleanup_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"), index=True, default=None)
    ticket_id: Mapped[int] = mapped_column(Integer, index=True)
    archived_by: Mapped[Optional[int]] = mapped_column(Integer, index=True, default=None)
    ticket_title: Mapped[Optional[str]] = mapped_column(String(255), default=None)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    retention_days: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    delete_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    deleted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"), index=True, default=None)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[Optional[str]] = mapped_column(Text, default=None)
    url: Mapped[Optional[str]] = mapped_column(String(500), default=None)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(255), default=None)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), index=True, default=None)
    email: Mapped[Optional[str]] = mapped_column(String(255), index=True, default=None)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, default=None)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

def ensure_migrations_ready() -> None:
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT version_num FROM alembic_version LIMIT 1")
    except Exception as exc:
        raise RuntimeError("Database schema is not initialized. Run 'alembic upgrade head'.") from exc
    try:
        with engine.connect() as conn:
            inspector = sa_inspect(conn)
            required_tables = {"tickets", "projects", "users", "ticket_logs", "ticket_watchers", "role_templates"}
            if ORG_STRUCTURE_V2_ENABLED:
                required_tables.update(
                    {
                        "departments",
                        "org_units",
                        "ticket_types",
                        "ticket_templates",
                        "unit_assignments",
                    }
                )
            missing_tables = sorted(table_name for table_name in required_tables if not inspector.has_table(table_name))
            if missing_tables:
                raise RuntimeError(
                    "Database schema is outdated. Run 'alembic upgrade head'. Missing tables: "
                    + ", ".join(missing_tables)
                )

            ticket_columns = {col["name"] for col in inspector.get_columns("tickets")}
            required_ticket_columns = {
                "company_id",
                "project_id",
                "executor_id",
                "ticket_type_id",
                "department_id",
                "target_unit_id",
                "ticket_template_id",
                "period_key",
                "batch_id",
                "created_by",
                "archived_at",
            }
            missing_ticket_columns = sorted(required_ticket_columns - ticket_columns)
            if missing_ticket_columns:
                raise RuntimeError(
                    "Database schema is outdated. Run 'alembic upgrade head'. Missing tickets columns: "
                    + ", ".join(missing_ticket_columns)
                )
            if ORG_STRUCTURE_V2_ENABLED:
                template_columns = {col["name"] for col in inspector.get_columns("ticket_templates")}
                missing_template_columns = sorted({"department_id"} - template_columns)
                if missing_template_columns:
                    raise RuntimeError(
                        "Database schema is outdated. Run 'alembic upgrade head'. Missing ticket_templates columns: "
                        + ", ".join(missing_template_columns)
                    )
            user_columns = {col["name"] for col in inspector.get_columns("users")}
            required_user_columns = {
                "email_verified",
                "email_verified_at",
                "email_verification_token",
                "email_verification_expires_at",
                "email_verification_sent_at",
                "password_reset_token",
                "password_reset_expires_at",
                "password_reset_sent_at",
                "auth_token_version",
                "role_label",
                "show_receipts_accounting_mode",
                "notify_receipt_created",
                "is_assignable_executor",
                "can_view_all_tickets",
                "can_create_tickets",
                "can_close_tickets",
            }
            missing_user_columns = sorted(required_user_columns - user_columns)
            if missing_user_columns:
                raise RuntimeError(
                    "Database schema is outdated. Run 'alembic upgrade head'. Missing users columns: "
                    + ", ".join(missing_user_columns)
                )
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError("Database schema check failed. Run 'alembic upgrade head'.") from exc


if (os.getenv("SKIP_MIGRATION_CHECK", "0").strip().lower() not in {"1", "true", "yes", "on"}):
    ensure_migrations_ready()

# =========================
# РЎС…РµРјС‹ API
# =========================
class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: Role
    bk_last4: Optional[str] = None
    preferred_payment_card_id: Optional[int] = None
    notify_receipt_created: Optional[bool] = None
    role_label: Optional[str] = None
    show_receipts_accounting_mode: Optional[bool] = None
    is_assignable_executor: Optional[bool] = None
    can_view_all_tickets: Optional[bool] = None
    can_create_tickets: Optional[bool] = None
    can_close_tickets: Optional[bool] = None

class UserOut(BaseModel):
    id: int
    email: EmailStr
    name: str
    role: Role
    company_id: Optional[int] = None
    email_verified: bool = False
    bk_last4: Optional[str] = None
    preferred_payment_card_id: Optional[int] = None
    notify_receipt_created: bool = True
    role_label: Optional[str] = None
    show_receipts_accounting_mode: bool = True
    is_assignable_executor: bool = False
    can_view_all_tickets: bool = False
    can_create_tickets: bool = True
    can_close_tickets: bool = True
    class Config:
        from_attributes = True

class CompanyOut(BaseModel):
    id: int
    name: str
    deadline_soon_warning_minutes: int
    archive_retention_days_default: int
    created_at: datetime
    class Config:
        from_attributes = True

class BootstrapSetupIn(BaseModel):
    company_name: str
    admin_email: EmailStr
    admin_name: str
    admin_password: str

class BootstrapSetupOut(BaseModel):
    company: CompanyOut
    admin: UserOut

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    class Config:
        from_attributes = True


class DepartmentCreate(BaseModel):
    name: str
    is_active: bool = True


class DepartmentUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None


class DepartmentOut(BaseModel):
    id: int
    name: str
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True

class UnitTypeCreate(BaseModel):
    name: str
    code: Optional[str] = None
    is_active: bool = True

class UnitTypeUpdate(BaseModel):
    name: Optional[str] = None
    code: Optional[str] = None
    is_active: Optional[bool] = None

class UnitTypeOut(BaseModel):
    id: int
    name: str
    code: Optional[str]
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True

class TicketTypeCreate(BaseModel):
    name: str
    description: Optional[str] = None
    department_id: Optional[int] = None
    archive_retention_days: Optional[int] = None
    is_active: bool = True

class TicketTypeUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    department_id: Optional[int] = None
    archive_retention_days: Optional[int] = None
    is_active: Optional[bool] = None

class TicketTypeOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    department_id: Optional[int]
    archive_retention_days: Optional[int]
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True

class TicketTemplateCreate(BaseModel):
    ticket_type_id: int
    department_id: Optional[int] = None
    name: str
    title_template: Optional[str] = None
    description_template: Optional[str] = None
    default_deadline_rule: Optional[str] = None
    default_executor_id: Optional[int] = None
    scope_unit_id: Optional[int] = None
    is_active: bool = True

class TicketTemplateUpdate(BaseModel):
    ticket_type_id: Optional[int] = None
    department_id: Optional[int] = None
    name: Optional[str] = None
    title_template: Optional[str] = None
    description_template: Optional[str] = None
    default_deadline_rule: Optional[str] = None
    default_executor_id: Optional[int] = None
    scope_unit_id: Optional[int] = None
    is_active: Optional[bool] = None

class TicketTemplateOut(BaseModel):
    id: int
    ticket_type_id: int
    department_id: Optional[int]
    name: str
    title_template: Optional[str]
    description_template: Optional[str]
    default_deadline_rule: Optional[str]
    default_executor_id: Optional[int]
    scope_unit_id: Optional[int]
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True


class TicketTemplateRunIn(BaseModel):
    period_key: Optional[str] = None

class TicketCreate(BaseModel):
    title: str
    description: Optional[str] = None
    deadline: Optional[datetime] = None
    executor_id: Optional[int] = None
    ticket_type_id: Optional[int] = None
    department_id: Optional[int] = None
    target_unit_id: Optional[int] = None
    ticket_template_id: Optional[int] = None
    period_key: Optional[str] = None
    project_id: int

class TicketUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    deadline: Optional[datetime] = None
    executor_id: Optional[int] = None
    ticket_type_id: Optional[int] = None
    department_id: Optional[int] = None
    target_unit_id: Optional[int] = None
    ticket_template_id: Optional[int] = None
    period_key: Optional[str] = None
    status: Optional[TicketStatus] = None
    project_id: Optional[int] = None

class TicketOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    deadline: Optional[datetime]
    status: TicketStatus
    project_id: int
    executor_id: Optional[int]
    ticket_type_id: Optional[int]
    department_id: Optional[int]
    target_unit_id: Optional[int]
    ticket_template_id: Optional[int]
    period_key: Optional[str]
    batch_id: Optional[str]
    created_by: int
    archived_at: Optional[datetime]
    archived_by: Optional[int]
    retention_days: Optional[int]
    delete_at: Optional[datetime]
    is_legal_hold: bool
    created_at: datetime
    class Config:
        from_attributes = True

class CommentCreate(BaseModel):
    text: str

class CommentMediaOut(BaseModel):
    id: int
    comment_id: int
    file_path: str
    original_name: Optional[str]
    media_kind: str
    file_size_bytes: Optional[int]
    file_sha256: Optional[str]
    archived_at: Optional[datetime]
    created_at: datetime
    class Config:
        from_attributes = True

class CommentOut(BaseModel):
    id: int
    ticket_id: int
    author_id: int
    text: str
    created_at: datetime
    media: list[CommentMediaOut] = Field(default_factory=list)
    class Config:
        from_attributes = True

class AttachmentOut(BaseModel):
    id: int
    ticket_id: int
    uploader_id: int
    file_path: str
    file_size_bytes: Optional[int]
    file_sha256: Optional[str]
    archived_at: Optional[datetime]
    created_at: datetime
    class Config:
        from_attributes = True

class PushSubscriptionIn(BaseModel):
    endpoint: str
    keys: dict[str, str]

class PushUnsubscribeIn(BaseModel):
    endpoint: str


class MobileDeviceRegisterIn(BaseModel):
    token: str = Field(min_length=16, max_length=2048)
    device_id: str = Field(min_length=8, max_length=128)
    platform: str = Field(default="android", max_length=32)
    app_version: Optional[str] = Field(default=None, max_length=64)
    device_name: Optional[str] = Field(default=None, max_length=255)


class MobileDeviceUnregisterIn(BaseModel):
    token: Optional[str] = Field(default=None, max_length=2048)
    device_id: Optional[str] = Field(default=None, max_length=128)
    platform: str = Field(default="android", max_length=32)

# =========================
# Р‘РµР·РѕРїР°СЃРЅРѕСЃС‚СЊ
# =========================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_BUCKETS: dict[str, list[float]] = {}

# Р’РђР–РќРћ: auto_error=False С‡С‚РѕР±С‹ cookie-Р»РѕРіРёРЅ РґР»СЏ РІРµР±Р° СЂР°Р±РѕС‚Р°Р» Р±РµР· Bearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def is_native_android_app_request(request: Request) -> bool:
    user_agent = (request.headers.get("user-agent") or "").strip().lower()
    return ANDROID_APP_USER_AGENT_TOKEN in user_agent


def normalize_mobile_platform(value: str | None) -> str:
    platform = (value or "android").strip().lower()
    return platform if platform in {"android"} else ""


def normalize_email(value: str | None) -> str | None:
    v = (value or "").strip().lower()
    return v or None


def normalize_department_name(value: str | None) -> str:
    return " ".join((value or "").split()).strip()


def hit_rate_limit(bucket: str, max_calls: int, window_seconds: int) -> tuple[bool, int]:
    now = time.time()
    cutoff = now - max(1, window_seconds)
    with RATE_LIMIT_LOCK:
        hits = [ts for ts in RATE_LIMIT_BUCKETS.get(bucket, []) if ts >= cutoff]
        if len(hits) >= max_calls:
            RATE_LIMIT_BUCKETS[bucket] = hits
            retry_after = max(1, int(window_seconds - (now - hits[0])) + 1)
            return True, retry_after
        hits.append(now)
        RATE_LIMIT_BUCKETS[bucket] = hits
    return False, 0


def audit_security_event(
    event_type: str,
    request: Request | None = None,
    *,
    success: bool,
    email: str | None = None,
    user_id: int | None = None,
    detail: str | None = None,
) -> None:
    db = SessionLocal()
    try:
        db.add(
            SecurityEvent(
                event_type=(event_type or "").strip()[:80] or "security_event",
                endpoint=(request.url.path if request else "")[:255] or None,
                ip_address=get_client_ip(request)[:64],
                email=normalize_email(email),
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


def department_match_filter(column, department_id: int | None):
    if department_id is None:
        return column.is_(None)
    return column == department_id


def add_ticket_watcher(
    db: Session,
    ticket: Ticket,
    *,
    watcher_user_id: int | None,
    added_by: int | None = None,
) -> bool:
    if watcher_user_id is None or ticket.id is None:
        return False
    watcher_user = db.get(User, watcher_user_id)
    if not watcher_user:
        return False
    if ticket.company_id is not None and watcher_user.company_id != ticket.company_id:
        return False
    exists = (
        db.query(TicketWatcher.id)
        .filter(TicketWatcher.ticket_id == ticket.id, TicketWatcher.user_id == watcher_user_id)
        .first()
    )
    if exists is not None:
        return False
    db.add(
        TicketWatcher(
            ticket_id=ticket.id,
            user_id=watcher_user_id,
            added_by=added_by,
        )
    )
    return True


def ensure_default_ticket_watchers(db: Session, ticket: Ticket) -> bool:
    changed = False
    default_watcher_ids: list[int] = []
    for watcher_user_id in (ticket.created_by, ticket.executor_id):
        if watcher_user_id is None or watcher_user_id in default_watcher_ids:
            continue
        default_watcher_ids.append(watcher_user_id)
    for watcher_user_id in default_watcher_ids:
        changed = add_ticket_watcher(
            db,
            ticket,
            watcher_user_id=watcher_user_id,
            added_by=ticket.created_by,
        ) or changed
    return changed


def get_api_ticket_or_404(db: Session, user: User, ticket_id: int) -> Ticket:
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if not is_platform_admin(user):
        ensure_company_user(user)
        if ticket.company_id != user.company_id:
            raise HTTPException(403, "Forbidden")
    return ticket

def delete_ticket_with_related_data(
    db: Session,
    ticket: Ticket,
    remove_files: bool = True,
) -> None:
    attachments = db.query(Attachment).filter(Attachment.ticket_id == ticket.id).all()
    comment_media_items = (
        db.query(CommentMedia)
        .join(Comment, Comment.id == CommentMedia.comment_id)
        .filter(Comment.ticket_id == ticket.id)
        .all()
    )
    if remove_files:
        for attachment in attachments:
            delete_stored_file(attachment.file_path)
        for item in comment_media_items:
            delete_stored_file(item.file_path)
    comment_ids_subquery = db.query(Comment.id).filter(Comment.ticket_id == ticket.id)
    db.query(CommentMedia).filter(CommentMedia.comment_id.in_(comment_ids_subquery)).delete(synchronize_session=False)
    db.query(Comment).filter(Comment.ticket_id == ticket.id).delete(synchronize_session=False)
    db.query(Attachment).filter(Attachment.ticket_id == ticket.id).delete(synchronize_session=False)
    db.query(TicketLog).filter(TicketLog.ticket_id == ticket.id).delete(synchronize_session=False)
    db.query(TicketWatcher).filter(TicketWatcher.ticket_id == ticket.id).delete(synchronize_session=False)
    db.query(DeadlineReminderLog).filter(DeadlineReminderLog.ticket_id == ticket.id).delete(synchronize_session=False)
    db.query(TicketGenerationKey).filter(TicketGenerationKey.ticket_id == ticket.id).update(
        {"ticket_id": None},
        synchronize_session=False,
    )
    db.delete(ticket)


def validate_ticket_links(
    db: Session,
    company_id: int | None,
    project_id: int | None,
    executor_id: int | None,
    ticket_type_id: int | None = None,
    target_unit_id: int | None = None,
    ticket_template_id: int | None = None,
    department_id: int | None = None,
) -> None:
    if project_id is not None:
        project = db.get(Project, project_id)
        if not project or (company_id is not None and project.company_id != company_id):
            raise HTTPException(400, "Project not found")

    if executor_id is not None:
        executor = db.get(User, executor_id)
        if not executor or not is_assignable_executor_user(executor):
            raise HTTPException(400, "Executor not found")
        if company_id is not None and executor.company_id != company_id:
            raise HTTPException(400, "Executor not found")

    if ticket_type_id is not None:
        ticket_type = db.get(TicketType, ticket_type_id)
        if not ticket_type or (company_id is not None and ticket_type.company_id != company_id):
            raise HTTPException(400, "Ticket type not found")
        if not ticket_type.is_active:
            raise HTTPException(400, "Ticket type is inactive")

    if department_id is not None:
        department = db.get(Department, department_id)
        if not department or (company_id is not None and department.company_id != company_id):
            raise HTTPException(400, "Department not found")
        if not department.is_active:
            raise HTTPException(400, "Department is inactive")

    if target_unit_id is not None:
        target_unit = db.get(OrgUnit, target_unit_id)
        if not target_unit or (company_id is not None and target_unit.company_id != company_id):
            raise HTTPException(400, "Target unit not found")
        if not target_unit.is_active:
            raise HTTPException(400, "Target unit is inactive")

    if ticket_template_id is not None:
        template = db.get(TicketTemplate, ticket_template_id)
        if not template or (company_id is not None and template.company_id != company_id):
            raise HTTPException(400, "Ticket template not found")


def resolve_ticket_department_id(
    db: Session,
    *,
    company_id: int,
    ticket_type_id: int | None,
    department_id: int | None,
) -> int | None:
    resolved_department_id = department_id
    ticket_type_department_id: int | None = None

    if ticket_type_id is not None:
        ticket_type = db.get(TicketType, ticket_type_id)
        if not ticket_type or ticket_type.company_id != company_id:
            raise HTTPException(400, "Ticket type not found")
        ticket_type_department_id = int(ticket_type.department_id) if ticket_type.department_id is not None else None

    if resolved_department_id is not None:
        department = db.get(Department, resolved_department_id)
        if not department or department.company_id != company_id:
            raise HTTPException(400, "Department not found")
        if not department.is_active:
            raise HTTPException(400, "Department is inactive")

    if ticket_type_department_id is not None:
        if resolved_department_id is not None and resolved_department_id != ticket_type_department_id:
            raise HTTPException(400, "Department does not match ticket type")
        return ticket_type_department_id

    return resolved_department_id


def resolve_scope_leaf_units(db: Session, company_id: int, scope_unit_id: int) -> list[int]:
    rows = (
        db.query(OrgUnit.id, OrgUnit.parent_id, OrgUnit.is_active)
        .filter(OrgUnit.company_id == company_id)
        .all()
    )
    active_ids = {int(row[0]) for row in rows if bool(row[2])}
    if scope_unit_id not in active_ids:
        return []

    children_by_parent: dict[int, list[int]] = {}
    for unit_id, parent_id, is_active in rows:
        if not bool(is_active):
            continue
        if parent_id is None:
            continue
        children_by_parent.setdefault(int(parent_id), []).append(int(unit_id))

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


def resolve_scope_descendant_units(db: Session, company_id: int, scope_unit_id: int) -> list[int]:
    rows = (
        db.query(OrgUnit.id, OrgUnit.parent_id, OrgUnit.is_active)
        .filter(OrgUnit.company_id == company_id)
        .all()
    )
    active_ids = {int(row[0]) for row in rows if bool(row[2])}
    if scope_unit_id not in active_ids:
        return []

    children_by_parent: dict[int, list[int]] = {}
    for unit_id, parent_id, is_active in rows:
        if not bool(is_active):
            continue
        if parent_id is None:
            continue
        children_by_parent.setdefault(int(parent_id), []).append(int(unit_id))

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



def resolve_target_unit_id_from_form_input(db: Session, company_id: int, raw_value: str | None) -> int | None:
    value = " ".join(str(raw_value or "").split()).strip()
    if not value:
        return None

    id_match = re.search(r"#(\d+)\)?\s*$", value)
    if id_match:
        unit_id = int(id_match.group(1))
        row = (
            db.query(OrgUnit.id)
            .filter(
                OrgUnit.company_id == company_id,
                OrgUnit.id == unit_id,
                OrgUnit.is_active.is_(True),
            )
            .first()
        )
        if row:
            return int(row[0])

    rows = (
        db.query(OrgUnit.id, OrgUnit.name)
        .filter(OrgUnit.company_id == company_id, OrgUnit.is_active.is_(True))
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


def resolve_executor_id_from_form_input(db: Session, company_id: int, raw_value: str | None) -> int | None:
    value = " ".join(str(raw_value or "").split()).strip()
    if not value:
        return None

    id_match = re.search(r"#(\d+)\)?\s*$", value)
    if id_match:
        user_id = int(id_match.group(1))
        row = (
            db.query(User.id)
            .filter(
                User.company_id == company_id,
                User.id == user_id,
                User.role != Role.platform_admin,
                User.is_assignable_executor.is_(True),
            )
            .first()
        )
        if row:
            return int(row[0])

    rows = (
        db.query(User.id, User.name, User.email)
        .filter(
            User.company_id == company_id,
            User.role != Role.platform_admin,
            User.is_assignable_executor.is_(True),
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
    db: Session,
    company_id: int,
    ticket_type_id: int | None,
    department_id: int | None,
    default_executor_id: int | None,
    scope_unit_id: int | None,
) -> None:
    if ticket_type_id is not None:
        tt = db.get(TicketType, ticket_type_id)
        if not tt or tt.company_id != company_id:
            raise HTTPException(400, "Ticket type not found")
    if department_id is not None:
        department = db.get(Department, department_id)
        if not department or department.company_id != company_id:
            raise HTTPException(400, "Department not found")
        if not department.is_active:
            raise HTTPException(400, "Department is inactive")
    if default_executor_id is not None:
        u = db.get(User, default_executor_id)
        if not u or u.company_id != company_id or not is_assignable_executor_user(u):
            raise HTTPException(400, "Executor not found")
    if scope_unit_id is not None:
        unit = db.get(OrgUnit, scope_unit_id)
        if not unit or unit.company_id != company_id:
            raise HTTPException(400, "Scope unit not found")


def get_or_create_project_for_org_unit(db: Session, company_id: int, unit_id: int) -> int:
    rows = (
        db.query(OrgUnit.id, OrgUnit.parent_id, OrgUnit.name)
        .filter(OrgUnit.company_id == company_id)
        .all()
    )
    by_id = {int(row[0]): (row[1], str(row[2] or "").strip()) for row in rows}
    if unit_id not in by_id:
        raise HTTPException(400, "Target unit not found")

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
            db.query(Project.id)
            .filter(Project.company_id == company_id, Project.name == project_name)
            .first()
        )
        if existing:
            return int(existing[0])

        item = Project(
            company_id=company_id,
            name=project_name,
            description="Auto-created from org structure",
        )
        db.add(item)
        db.flush()
        return int(item.id)

    raise HTTPException(400, "Cannot resolve project for target unit")


def get_preferred_executor_for_unit(
    db: Session,
    company_id: int,
    unit_id: int,
    department_id: int | None = None,
) -> int | None:
    query = (
        db.query(UnitAssignment.user_id)
        .join(User, User.id == UnitAssignment.user_id)
        .filter(
            UnitAssignment.company_id == company_id,
            UnitAssignment.unit_id == unit_id,
            UnitAssignment.role_code == "EXECUTOR",
            User.company_id == company_id,
            User.role != Role.platform_admin,
            User.is_assignable_executor.is_(True),
            department_match_filter(UnitAssignment.department_id, department_id),
        )
        .order_by(UnitAssignment.is_primary.desc(), UnitAssignment.id.asc())
    )
    row = query.first()
    return int(row[0]) if row else None


def month_period_key(dt: datetime | None = None) -> str:
    base = dt or local_now()
    return base.strftime("%Y-%m")


def normalize_period_key(raw_value: str | None) -> str | None:
    raw = (raw_value or "").strip()
    if not raw:
        return None
    if len(raw) != 7 or raw[4] != "-":
        return None
    yyyy = raw[:4]
    mm = raw[5:]
    if not (yyyy.isdigit() and mm.isdigit()):
        return None
    month_value = int(mm)
    if month_value < 1 or month_value > 12:
        return None
    return f"{yyyy}-{mm}"


def resolve_deadline_by_rule(rule: str | None, now_dt: datetime | None = None) -> datetime | None:
    raw = (rule or "").strip().lower()
    if not raw:
        return None
    base = now_dt or local_now()
    if raw.startswith("dom:"):
        try:
            day = int(raw.split(":", 1)[1])
        except ValueError:
            return None
        if day < 1:
            return None
        last_day = monthrange(base.year, base.month)[1]
        clamped_day = min(day, last_day)
        return base.replace(day=clamped_day, hour=23, minute=59, second=0, microsecond=0)
    try:
        exact_date = datetime.strptime(raw, "%Y-%m-%d")
        return exact_date.replace(hour=23, minute=59, second=0, microsecond=0)
    except ValueError:
        pass
    if raw.startswith("+") and raw.endswith("h"):
        try:
            return base + timedelta(hours=max(1, int(raw[1:-1])))
        except ValueError:
            return None
    if raw.startswith("+") and raw.endswith("d"):
        try:
            return base + timedelta(days=max(1, int(raw[1:-1])))
        except ValueError:
            return None
    return None


def template_deadline_date_value(rule: str | None) -> str:
    raw = (rule or "").strip()
    if not raw:
        return ""
    try:
        return datetime.strptime(raw, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return ""


def template_deadline_mode(rule: str | None) -> str:
    raw = (rule or "").strip().lower()
    if raw.startswith("dom:"):
        return "dom"
    if template_deadline_date_value(raw):
        return "date"
    return "none"


def template_deadline_dom_value(rule: str | None) -> str:
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


def parse_template_deadline_rule_from_form(form) -> str | None:
    mode = (form.get("deadline_mode") or "").strip().lower()
    if mode == "date":
        date_value = (form.get("deadline_date") or "").strip()
        if not date_value:
            return None
        try:
            return datetime.strptime(date_value, "%Y-%m-%d").strftime("%Y-%m-%d")
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
        return datetime.strptime(legacy_raw, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return legacy_raw


def normalize_ticket_title(raw_title: str | None) -> str:
    return (raw_title or "").strip()


def is_ticket_title_too_long(title: str | None) -> bool:
    return len(title or "") > MAX_TICKET_TITLE_LEN


def truncate_ticket_title(title: str | None) -> str:
    normalized = normalize_ticket_title(title)
    if len(normalized) <= MAX_TICKET_TITLE_LEN:
        return normalized
    return normalized[:MAX_TICKET_TITLE_LEN].rstrip()
_storage_service = StorageService(
    upload_dir=UPLOAD_DIR,
    upload_dir_getter=lambda: UPLOAD_DIR,
    archive_upload_subdir=ARCHIVE_UPLOAD_SUBDIR,
    storage_backend=STORAGE_BACKEND,
    storage_backend_getter=lambda: STORAGE_BACKEND,
    s3_bucket=S3_BUCKET,
    s3_endpoint_url=S3_ENDPOINT_URL,
    s3_access_key=S3_ACCESS_KEY,
    s3_secret_key=S3_SECRET_KEY,
    s3_region=S3_REGION,
    s3_addressing_style=S3_ADDRESSING_STYLE,
    s3_presigned_ttl_seconds=S3_PRESIGNED_TTL_SECONDS,
    attachments_storage_prefix=ATTACHMENTS_STORAGE_PREFIX,
    comment_media_storage_prefix=COMMENT_MEDIA_STORAGE_PREFIX,
    receipts_storage_prefix=RECEIPTS_STORAGE_PREFIX,
    allowed_upload_extensions=ALLOWED_UPLOAD_EXTENSIONS,
    comment_image_extensions=COMMENT_IMAGE_EXTENSIONS,
    comment_audio_extensions=COMMENT_AUDIO_EXTENSIONS,
    comment_media_extensions=COMMENT_MEDIA_EXTENSIONS,
    max_upload_size_bytes=MAX_UPLOAD_SIZE_BYTES,
    http_exception_cls=HTTPException,
    redirect_response_cls=RedirectResponse,
    file_response_cls=FileResponse,
    status_module=status,
    boto3_available=BOTO3_AVAILABLE,
    boto3_module=boto3,
    boto_config_cls=BotoConfig,
    boto_core_error_cls=BotoCoreError,
    client_error_cls=ClientError,
)

get_s3_client = _storage_service.get_s3_client
build_storage_key = _storage_service.build_storage_key
parse_s3_storage_path = _storage_service.parse_s3_storage_path
build_s3_storage_path = _storage_service.build_s3_storage_path
build_attachment_object_key = _storage_service.build_attachment_object_key
build_comment_media_object_key = _storage_service.build_comment_media_object_key
build_receipt_object_key = _storage_service.build_receipt_object_key
get_storage_basename = _storage_service.get_storage_basename
build_download_content_disposition = _storage_service.build_download_content_disposition
get_upload_extension = _storage_service.get_upload_extension
detect_comment_media_kind = _storage_service.detect_comment_media_kind
resolve_attachment_disk_path = _storage_service.resolve_attachment_disk_path
make_safe_upload_name = _storage_service.make_safe_upload_name
write_upload_file = _storage_service.write_upload_file
write_upload_file_async = _storage_service.write_upload_file_async
read_upload_bytes = _storage_service.read_upload_bytes
read_upload_bytes_async = _storage_service.read_upload_bytes_async
build_upload_url_from_disk_path = _storage_service.build_upload_url_from_disk_path
compute_bytes_sha256_and_size = _storage_service.compute_bytes_sha256_and_size
store_bytes_in_storage = _storage_service.store_bytes_in_storage
store_upload_file_to_storage = _storage_service.store_upload_file_to_storage
store_upload_file_to_storage_async = _storage_service.store_upload_file_to_storage_async
read_stored_file_bytes = _storage_service.read_stored_file_bytes
delete_stored_file = _storage_service.delete_stored_file
build_presigned_storage_download_url = _storage_service.build_presigned_storage_download_url
serve_stored_file_response = _storage_service.serve_stored_file_response
move_stored_file_to_key = _storage_service.move_stored_file_to_key
compute_file_sha256_and_size = _storage_service.compute_file_sha256_and_size
enrich_attachment_metadata = _storage_service.enrich_attachment_metadata
normalize_uploaded_files = _storage_service.normalize_uploaded_files
normalize_optional_uploaded_files = _storage_service.normalize_optional_uploaded_files
choose_attachment_storage_name = _storage_service.choose_attachment_storage_name
choose_comment_media_storage_name = _storage_service.choose_comment_media_storage_name
move_attachment_to_archive = _storage_service.move_attachment_to_archive
move_attachment_to_active_storage = _storage_service.move_attachment_to_active_storage
move_comment_media_to_archive = _storage_service.move_comment_media_to_archive
move_comment_media_to_active_storage = _storage_service.move_comment_media_to_active_storage


def to_local_dt(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt + timedelta(hours=LOCAL_TIME_OFFSET_HOURS)


def local_now() -> datetime:
    return datetime.utcnow() + timedelta(hours=LOCAL_TIME_OFFSET_HOURS)


def clamp_deadline_soon_warning_minutes(value: int) -> int:
    return max(
        MIN_DEADLINE_SOON_WARNING_MINUTES,
        min(MAX_DEADLINE_SOON_WARNING_MINUTES, int(value)),
    )


def parse_deadline_soon_warning_minutes(raw: str | None) -> int | None:
    raw_value = (raw or "").strip()
    if not raw_value:
        return None
    if not re.fullmatch(r"\d+", raw_value):
        return None
    parsed = int(raw_value)
    if parsed < MIN_DEADLINE_SOON_WARNING_MINUTES or parsed > MAX_DEADLINE_SOON_WARNING_MINUTES:
        return None
    return parsed


def get_company_deadline_soon_warning_minutes(company: Company | None) -> int:
    if not company:
        return DEFAULT_DEADLINE_SOON_WARNING_MINUTES
    if company.deadline_soon_warning_minutes is None:
        return DEFAULT_DEADLINE_SOON_WARNING_MINUTES
    return clamp_deadline_soon_warning_minutes(company.deadline_soon_warning_minutes)


def clamp_archive_retention_days(value: int) -> int:
    return max(
        MIN_ARCHIVE_RETENTION_DAYS,
        min(MAX_ARCHIVE_RETENTION_DAYS, int(value)),
    )


def parse_archive_retention_days(raw: str | None) -> int | None:
    raw_value = (raw or "").strip()
    if not raw_value:
        return None
    if not re.fullmatch(r"\d+", raw_value):
        return None
    parsed = int(raw_value)
    if parsed < MIN_ARCHIVE_RETENTION_DAYS or parsed > MAX_ARCHIVE_RETENTION_DAYS:
        return None
    return parsed


def get_company_archive_retention_days(company: Company | None) -> int:
    if not company:
        return DEFAULT_ARCHIVE_RETENTION_DAYS
    if company.archive_retention_days_default is None:
        return DEFAULT_ARCHIVE_RETENTION_DAYS
    return clamp_archive_retention_days(company.archive_retention_days_default)


def normalize_settings_section(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    if value in SETTINGS_SECTIONS:
        return value
    return ""


def build_settings_url(section: str | None = None, **params: object) -> str:
    items: list[tuple[str, str]] = []
    normalized_section = normalize_settings_section(section)
    if normalized_section:
        items.append(("section", normalized_section))
    for key, value in params.items():
        if value is None or value is False or value == "":
            continue
        items.append((key, "1" if value is True else str(value)))
    if not items:
        return "/web/settings"
    return f"/web/settings?{urlencode(items)}"


def normalize_org_structure_section(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    if value in ORG_STRUCTURE_SECTIONS:
        return value
    return ""


def infer_org_structure_section(
    raw: str | None = None,
    *,
    error: str | None = None,
    import_ok: str | None = None,
    edit_unit_id: str | None = None,
    assignment_unit_id: str | None = None,
    assignment_executor_id: str | None = None,
    assignment_department_id: str | None = None,
    assignment_unit_q: str | None = None,
    assignment_executor_q: str | None = None,
    assignment_primary: str | None = None,
    assignment_page: int | None = None,
) -> str:
    normalized = normalize_org_structure_section(raw)
    if normalized:
        return normalized
    error_code = (error or "").strip().lower()
    if (import_ok or "").strip() == "1" or error_code in ORG_STRUCTURE_IMPORT_ERRORS:
        return "import"
    if (
        (edit_unit_id or "").strip()
        or error_code in ORG_STRUCTURE_NODE_ERRORS
    ):
        return "nodes"
    has_assignment_context = any(
        (
            (assignment_unit_id or "").strip(),
            (assignment_executor_id or "").strip(),
            (assignment_department_id or "").strip(),
            (assignment_unit_q or "").strip(),
            (assignment_executor_q or "").strip(),
            (assignment_primary or "").strip(),
            (assignment_page or 1) > 1,
        )
    )
    if has_assignment_context or error_code in ORG_STRUCTURE_EXECUTOR_ERRORS:
        return "executors"
    return "nodes"


def build_org_structure_url(section: str | None = None, **params: object) -> str:
    items: list[tuple[str, str]] = []
    normalized_section = normalize_org_structure_section(section)
    if normalized_section:
        items.append(("section", normalized_section))
    for key, value in params.items():
        if value is None or value is False or value == "":
            continue
        items.append((key, "1" if value is True else str(value)))
    if not items:
        return "/web/org-structure"
    return f"/web/org-structure?{urlencode(items)}"


def normalize_ticket_type_archive_retention_days(value: int | None) -> int | None:
    if value is None:
        return None
    parsed = int(value)
    if parsed < MIN_ARCHIVE_RETENTION_DAYS or parsed > MAX_ARCHIVE_RETENTION_DAYS:
        raise HTTPException(
            422,
            f"archive_retention_days must be between {MIN_ARCHIVE_RETENTION_DAYS} and {MAX_ARCHIVE_RETENTION_DAYS}",
        )
    return parsed


def format_dt(dt: datetime | None) -> str:
    local_dt = to_local_dt(dt)
    if local_dt is None:
        return "\u2014"

    now_local = to_local_dt(datetime.utcnow())
    if not now_local:
        return local_dt.strftime("%d.%m.%Y %H:%M")

    date_part = local_dt.date()
    now_date = now_local.date()

    if date_part == now_date:
        return local_dt.strftime("\u0421\u0435\u0433\u043e\u0434\u043d\u044f, %H:%M")
    if date_part == (now_date - timedelta(days=1)):
        return local_dt.strftime("\u0412\u0447\u0435\u0440\u0430, %H:%M")
    if date_part == (now_date + timedelta(days=1)):
        return local_dt.strftime("\u0417\u0430\u0432\u0442\u0440\u0430, %H:%M")

    month_names = {
        1: "\u044f\u043d\u0432",
        2: "\u0444\u0435\u0432",
        3: "\u043c\u0430\u0440",
        4: "\u0430\u043f\u0440",
        5: "\u043c\u0430\u044f",
        6: "\u0438\u044e\u043d",
        7: "\u0438\u044e\u043b",
        8: "\u0430\u0432\u0433",
        9: "\u0441\u0435\u043d",
        10: "\u043e\u043a\u0442",
        11: "\u043d\u043e\u044f",
        12: "\u0434\u0435\u043a",
    }

    if local_dt.year == now_local.year:
        mon = month_names.get(local_dt.month, local_dt.strftime("%m"))
        return f"{local_dt.day} {mon}, {local_dt.strftime('%H:%M')}"

    return local_dt.strftime("%d.%m.%Y %H:%M")




def format_deadline(dt: datetime | None) -> str:
    if dt is None:
        return "\u2014"

    now_local = local_now()
    date_part = dt.date()
    now_date = now_local.date()

    if date_part == now_date:
        return dt.strftime("\u0421\u0435\u0433\u043e\u0434\u043d\u044f, %H:%M")
    if date_part == (now_date - timedelta(days=1)):
        return dt.strftime("\u0412\u0447\u0435\u0440\u0430, %H:%M")
    if date_part == (now_date + timedelta(days=1)):
        return dt.strftime("\u0417\u0430\u0432\u0442\u0440\u0430, %H:%M")

    month_names = {
        1: "\u044f\u043d\u0432",
        2: "\u0444\u0435\u0432",
        3: "\u043c\u0430\u0440",
        4: "\u0430\u043f\u0440",
        5: "\u043c\u0430\u044f",
        6: "\u0438\u044e\u043d",
        7: "\u0438\u044e\u043b",
        8: "\u0430\u0432\u0433",
        9: "\u0441\u0435\u043d",
        10: "\u043e\u043a\u0442",
        11: "\u043d\u043e\u044f",
        12: "\u0434\u0435\u043a",
    }

    if dt.year == now_local.year:
        mon = month_names.get(dt.month, dt.strftime("%m"))
        return f"{dt.day} {mon}, {dt.strftime('%H:%M')}"

    return dt.strftime("%d.%m.%Y %H:%M")


def parse_deadline_inputs(deadline_date_raw: str | None, deadline_time4_raw: str | None) -> datetime | None:
    deadline_date = (deadline_date_raw or "").strip()
    time4 = (deadline_time4_raw or "").strip()
    if not deadline_date:
        return None

    # If date is set and time is empty, use current local time.
    if not time4:
        time4 = local_now().strftime("%H%M")

    time4 = "".join(ch for ch in time4 if ch.isdigit())[:4]
    if not time4:
        return None

    if len(time4) <= 2:
        hh = min(23, int(time4))
        mm = 0
        time4_fixed = f"{hh:02d}{mm:02d}"
    else:
        time4_fixed = time4.zfill(4)

    try:
        hh = min(23, int(time4_fixed[:2]))
        mm = min(59, int(time4_fixed[2:]))
        return datetime.strptime(deadline_date, "%Y-%m-%d").replace(hour=hh, minute=mm)
    except ValueError:
        return None


def fix_mojibake_text(value: str | None) -> str:
    text = (value or "")
    if not text:
        return ""

    def _score(s: str) -> int:
        cyr = sum(1 for ch in s if "\u0400" <= ch <= "\u04FF")
        bad = len(re.findall(r"[\u00D0\u00D1\u0420\u0421\u0440\u0441](?=[^\s])", s))
        bad += len(re.findall(r"[\u201A\u201E\u2026\u2020\u2021\u2030\u2122]", s))
        bad += s.count("\uFFFD")
        return cyr * 2 - bad

    best = text
    best_score = _score(text)
    current = text

    for _ in range(3):
        candidates: list[str] = []
        try:
            candidates.append(current.encode("cp1251").decode("utf-8"))
        except Exception:
            pass
        try:
            candidates.append(current.encode("latin1").decode("utf-8"))
        except Exception:
            pass

        improved = False
        for candidate in candidates:
            score = _score(candidate)
            if score > best_score:
                best = candidate
                best_score = score
                improved = True
        if not improved:
            break
        current = best

    return best


def ticket_title_notification_preview(
    ticket_title: str | None,
    *,
    ticket_id: int | None = None,
    max_len: int = NOTIFICATION_TICKET_TITLE_PREVIEW_LEN,
) -> str:
    preview = fix_mojibake_text((ticket_title or "").strip())
    if preview:
        if max_len > 3 and len(preview) > max_len:
            preview = preview[: max_len - 3].rstrip() + "..."
        return preview
    if ticket_id is not None:
        return f"заявка #{ticket_id}"
    return "заявка"


def ticket_notification_title(prefix: str, ticket_title: str | None, *, ticket_id: int | None = None) -> str:
    return f"{prefix}: {ticket_title_notification_preview(ticket_title, ticket_id=ticket_id)}"


def repair_mojibake_data(db: Session) -> int:
    fixed = 0

    notifications = db.query(Notification).all()
    for n in notifications:
        new_title = fix_mojibake_text(n.title or "")
        new_body = fix_mojibake_text(n.body or "") if n.body else None
        if new_title != (n.title or ""):
            n.title = new_title
            fixed += 1
        if new_body != n.body:
            n.body = new_body
            fixed += 1

    logs = db.query(TicketLog).all()
    for row in logs:
        new_action = normalize_log_action(row.action or "")
        if new_action != (row.action or ""):
            row.action = new_action
            fixed += 1

    if fixed:
        db.commit()
    return fixed


LOG_ACTION_CREATED_FROM_TEMPLATE = "\u0441\u043e\u0437\u0434\u0430\u043d\u0438\u0435 \u043f\u043e \u0448\u0430\u0431\u043b\u043e\u043d\u0443"
LOG_ACTION_CREATED = "\u0441\u043e\u0437\u0434\u0430\u043d\u0438\u0435"
LOG_ACTION_DEADLINE_CHANGED = "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0441\u0440\u043e\u043a\u0430"
LOG_ACTION_EXECUTOR_CHANGED = "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0438\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044f"
LOG_ACTION_PROJECT_CHANGED = "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u043f\u0440\u043e\u0435\u043a\u0442\u0430"
LOG_ACTION_TICKET_TYPE_CHANGED = "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0442\u0438\u043f\u0430 \u0437\u0430\u044f\u0432\u043a\u0438"
LOG_ACTION_TARGET_UNIT_CHANGED = "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0446\u0435\u043b\u0435\u0432\u043e\u0433\u043e \u0443\u0437\u043b\u0430"
LOG_ACTION_TEMPLATE_CHANGED = "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0448\u0430\u0431\u043b\u043e\u043d\u0430 \u0437\u0430\u044f\u0432\u043a\u0438"
LOG_ACTION_TEMPLATE_PERIOD_CHANGED = "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u043f\u0435\u0440\u0438\u043e\u0434\u0430 \u0448\u0430\u0431\u043b\u043e\u043d\u0430"
LOG_ACTION_CHANGED = "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435"
LOG_ACTION_FILE_ADDED = "\u0434\u043e\u0431\u0430\u0432\u043b\u0435\u043d\u0438\u0435 \u0444\u0430\u0439\u043b\u0430"
LOG_ACTION_FILE_DELETED = "\u0443\u0434\u0430\u043b\u0435\u043d\u0438\u0435 \u0444\u0430\u0439\u043b\u0430"


def is_placeholder_log_action(value: str | None) -> bool:
    text = (value or "").strip()
    if not text:
        return True
    meaningful = re.sub(r"[\s\?\!\.,:;\'\"`\-_/\\|()\[\]{}<>+=*#%&~@]+", "", text)
    return not meaningful


def normalize_log_action(action: str | None) -> str:
    raw = (action or "").strip()
    fixed_raw = fix_mojibake_text(raw).strip()
    text = fixed_raw.lower()
    if not raw:
        return LOG_ACTION_CHANGED
    merged = f"{raw.lower()} {text}"
    escaped = raw.encode("unicode_escape").decode("ascii").lower()

    escaped_map = {
        "\\u0421\\u0403\\u0420\\u0455\\u0420\\xb7\\u0420\\u0491\\u0420\\xb0\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0420\\u0455 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0421\\u0453": LOG_ACTION_CREATED_FROM_TEMPLATE,
        "\\u0421\\u0403\\u0420\\u0455\\u0420\\xb7\\u0420\\u0491\\u0420\\xb0\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5": LOG_ACTION_CREATED,
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u0403\\u0421\\u0402\\u0420\\u0455\\u0420\\u0454\\u0420\\xb0": LOG_ACTION_DEADLINE_CHANGED,
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0451\\u0421\\u0403\\u0420\\u0457\\u0420\\u0455\\u0420\\xbb\\u0420\\u0405\\u0420\\u0451\\u0421\\u201a\\u0420\\xb5\\u0420\\xbb\\u0421\\u040f": LOG_ACTION_EXECUTOR_CHANGED,
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0421\\u0402\\u0420\\u0455\\u0420\\xb5\\u0420\\u0454\\u0421\\u201a\\u0420\\xb0": LOG_ACTION_PROJECT_CHANGED,
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u201a\\u0420\\u0451\\u0420\\u0457\\u0420\\xb0 \\u0420\\xb7\\u0420\\xb0\\u0421\\u040f\\u0420\\u0406\\u0420\\u0454\\u0420\\u0451": LOG_ACTION_TICKET_TYPE_CHANGED,
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u2020\\u0420\\xb5\\u0420\\xbb\\u0420\\xb5\\u0420\\u0406\\u0420\\u0455\\u0420\\u0456\\u0420\\u0455 \\u0421\\u0453\\u0420\\xb7\\u0420\\xbb\\u0420\\xb0": LOG_ACTION_TARGET_UNIT_CHANGED,
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0420\\xb0 \\u0420\\xb7\\u0420\\xb0\\u0421\\u040f\\u0420\\u0406\\u0420\\u0454\\u0420\\u0451": LOG_ACTION_TEMPLATE_CHANGED,
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0420\\xb5\\u0421\\u0402\\u0420\\u0451\\u0420\\u0455\\u0420\\u0491\\u0420\\xb0 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0420\\xb0": LOG_ACTION_TEMPLATE_PERIOD_CHANGED,
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5": LOG_ACTION_CHANGED,
        "\\u0420\\u0491\\u0420\\u0455\\u0420\\xb1\\u0420\\xb0\\u0420\\u0406\\u0420\\xbb\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u201e\\u0420\\xb0\\u0420\\u2116\\u0420\\xbb\\u0420\\xb0": LOG_ACTION_FILE_ADDED,
        "\\u0423\\u0434\\u0430\\u043b\\u0435\\u043d\\u0438\\u0435 \\u0444\\u0430\\u0439\\u043b\\u0430": LOG_ACTION_FILE_DELETED,
    }
    if escaped in escaped_map:
        return escaped_map[escaped]
    if fixed_raw and ("->" in fixed_raw or "\u2192" in fixed_raw):
        return fixed_raw

    if is_placeholder_log_action(raw) or is_placeholder_log_action(text):
        return LOG_ACTION_CHANGED

    k_create = "\u0441\u043e\u0437\u0434"
    k_template = "\u0448\u0430\u0431\u043b"
    k_deadline = "\u0441\u0440\u043e\u043a"
    k_executor = "\u0438\u0441\u043f\u043e\u043b\u043d"
    k_project = "\u043f\u0440\u043e\u0435\u043a\u0442"
    k_type = "\u0442\u0438\u043f"
    k_ticket = "\u0437\u0430\u044f\u0432"
    k_unit = "\u0443\u0437\u043b"
    k_period = "\u043f\u0435\u0440\u0438\u043e\u0434"
    k_file = "\u0444\u0430\u0439\u043b"
    k_delete = "\u0443\u0434\u0430\u043b"
    k_status = "\u0441\u0442\u0430\u0442\u0443\u0441"
    k_change = "\u0438\u0437\u043c\u0435\u043d"

    if k_create in merged:
        if k_template in merged:
            return LOG_ACTION_CREATED_FROM_TEMPLATE
        return LOG_ACTION_CREATED
    if k_deadline in merged:
        return LOG_ACTION_DEADLINE_CHANGED
    if k_executor in merged:
        return LOG_ACTION_EXECUTOR_CHANGED
    if k_project in merged:
        return LOG_ACTION_PROJECT_CHANGED
    if k_type in merged and k_ticket in merged:
        return LOG_ACTION_TICKET_TYPE_CHANGED
    if k_unit in merged:
        return LOG_ACTION_TARGET_UNIT_CHANGED
    if k_period in merged and k_template in merged:
        return LOG_ACTION_TEMPLATE_PERIOD_CHANGED
    if k_template in merged:
        return LOG_ACTION_TEMPLATE_CHANGED
    if k_delete in merged and k_file in merged:
        return LOG_ACTION_FILE_DELETED
    if k_file in merged or "file" in merged:
        return LOG_ACTION_FILE_ADDED
    if k_status in merged:
        if "->" in fixed_raw or "\u2192" in fixed_raw:
            return fixed_raw
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0441\u0442\u0430\u0442\u0443\u0441\u0430"
    if k_change in merged:
        return LOG_ACTION_CHANGED
    return text if not is_placeholder_log_action(text) else LOG_ACTION_CHANGED


def add_ticket_log(db: Session, ticket_id: int, actor_id: int, action: str) -> None:
    db.add(TicketLog(ticket_id=ticket_id, actor_id=actor_id, action=normalize_log_action(action)))


_comment_service = CommentService(
    normalize_optional_uploaded_files=normalize_optional_uploaded_files,
    detect_comment_media_kind=detect_comment_media_kind,
    make_safe_upload_name=make_safe_upload_name,
    build_comment_media_object_key=build_comment_media_object_key,
    store_upload_file_to_storage_async=store_upload_file_to_storage_async,
    delete_stored_file=delete_stored_file,
    add_ticket_log=add_ticket_log,
    log_action_file_added=LOG_ACTION_FILE_ADDED,
    attachment_model=Attachment,
    comment_model=Comment,
    comment_media_model=CommentMedia,
    comment_out_model=CommentOut,
    comment_media_out_model=CommentMediaOut,
    comment_media_extensions=COMMENT_MEDIA_EXTENSIONS,
    http_exception_cls=HTTPException,
)

create_ticket_attachment_record = _comment_service.create_ticket_attachment_record
create_comment_media_record = _comment_service.create_comment_media_record
serialize_comment_out = _comment_service.serialize_comment_out
summarize_comment_media = _comment_service.summarize_comment_media
create_comment_with_media_async = _comment_service.create_comment_with_media_async


def push_is_configured() -> bool:
    return bool(PYWEBPUSH_AVAILABLE and VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY and VAPID_SUBJECT)


def mobile_push_is_configured() -> bool:
    return bool(
        FIREBASE_ADMIN_AVAILABLE
        and FIREBASE_CREDENTIALS_FILE
        and Path(FIREBASE_CREDENTIALS_FILE).is_file()
    )


def get_firebase_app():
    global _FIREBASE_APP
    if not mobile_push_is_configured():
        return None
    with _FIREBASE_APP_LOCK:
        if _FIREBASE_APP is None:
            try:
                _FIREBASE_APP = firebase_admin.initialize_app(
                    firebase_credentials.Certificate(FIREBASE_CREDENTIALS_FILE)
                )
            except Exception as exc:
                logger.warning("Firebase app init failed: %s", exc)
                return None
        return _FIREBASE_APP


def should_drop_mobile_token(exc: Exception) -> bool:
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


def send_push_to_user_report(db: Session, user_id: int, title: str, body: str, url: str) -> list[dict]:
    if not push_is_configured():
        return []

    subs = db.query(PushSubscription).filter(PushSubscription.user_id == user_id).all()
    if not subs:
        return []

    payload = json.dumps({"title": title, "body": body, "url": url})
    vapid_claims = {"sub": VAPID_SUBJECT}
    results: list[dict] = []
    for sub in subs:
        subscription_info = {
            "endpoint": sub.endpoint,
            "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
        }
        try:
            webpush(
                subscription_info=subscription_info,
                data=payload,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=vapid_claims,
                ttl=60 * 60,
            )
            sub.updated_at = datetime.utcnow()
            results.append({"id": sub.id, "ok": True})
        except WebPushException as exc:
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
            results.append({"id": sub.id, "ok": False, "status_code": status_code})
            if status_code in {401, 404, 410}:
                db.delete(sub)
        except Exception:
            results.append({"id": sub.id, "ok": False, "status_code": "error"})
            continue
    return results


def send_mobile_push_to_user_report(db: Session, user_id: int, title: str, body: str, url: str) -> list[dict]:
    if not mobile_push_is_configured():
        return []

    app = get_firebase_app()
    if app is None:
        return []

    devices = (
        db.query(MobileDevice)
        .filter(MobileDevice.user_id == user_id, MobileDevice.platform == "android")
        .all()
    )
    if not devices:
        return []

    safe_url = (url or "").strip() or "/web"
    results: list[dict] = []
    for device in devices:
        message = firebase_messaging.Message(
            token=device.token,
            data={
                "title": title,
                "body": body or "",
                "url": safe_url,
            },
            android=firebase_messaging.AndroidConfig(priority="high"),
        )
        try:
            firebase_messaging.send(message, app=app)
            now = datetime.utcnow()
            device.last_seen_at = now
            device.updated_at = now
            results.append({"id": device.id, "ok": True, "channel": "android"})
        except Exception as exc:
            logger.warning(
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
            if should_drop_mobile_token(exc):
                db.delete(device)
    return results


_notification_service = NotificationService(
    fix_mojibake_text=fix_mojibake_text,
    ticket_notification_title=ticket_notification_title,
    summarize_comment_media=summarize_comment_media,
    status_label_ru=status_label_ru,
    send_push_to_user_report_func=lambda **kwargs: send_push_to_user_report(**kwargs),
    send_mobile_push_to_user_report_func=lambda **kwargs: send_mobile_push_to_user_report(**kwargs),
    user_model=User,
    notification_model=Notification,
    role_enum=Role,
    ticket_watcher_model=TicketWatcher,
    project_model=Project,
    payment_card_model=PaymentCard,
)

create_inapp_notification = _notification_service.create_inapp_notification
send_push_to_user = _notification_service.send_push_to_user
notify_executor_new_ticket = _notification_service.notify_executor_new_ticket
notify_executor_reassigned = _notification_service.notify_executor_reassigned
notify_curators_status_changed = _notification_service.notify_curators_status_changed
notify_comment_added = _notification_service.notify_comment_added
notify_curators_executor_act = _notification_service.notify_curators_executor_act
notify_receipt_created = _notification_service.notify_receipt_created

_ticket_runtime_service = TicketRuntimeService(
    clamp_archive_retention_days=clamp_archive_retention_days,
    get_company_archive_retention_days=get_company_archive_retention_days,
    local_now=local_now,
    move_attachment_to_archive=move_attachment_to_archive,
    move_comment_media_to_archive=move_comment_media_to_archive,
    move_attachment_to_active_storage=move_attachment_to_active_storage,
    move_comment_media_to_active_storage=move_comment_media_to_active_storage,
    format_deadline=format_deadline,
    add_ticket_log=add_ticket_log,
    delete_ticket_with_related_data=delete_ticket_with_related_data,
    resolve_ticket_department_id=resolve_ticket_department_id,
    resolve_scope_leaf_units=resolve_scope_leaf_units,
    truncate_ticket_title=truncate_ticket_title,
    get_or_create_project_for_org_unit=get_or_create_project_for_org_unit,
    get_preferred_executor_for_unit=get_preferred_executor_for_unit,
    resolve_deadline_by_rule=resolve_deadline_by_rule,
    month_period_key=month_period_key,
    ensure_default_ticket_watchers=ensure_default_ticket_watchers,
    send_push_to_user=send_push_to_user,
    ticket_notification_title=ticket_notification_title,
    session_factory=lambda: SessionLocal(),
    archive_cleanup_poll_seconds=ARCHIVE_CLEANUP_POLL_SECONDS,
    template_autogen_poll_seconds=TEMPLATE_AUTOGEN_POLL_SECONDS,
    time_module=time,
    timedelta_cls=timedelta,
    uuid_module=uuid,
    ticket_model=Ticket,
    ticket_type_model=TicketType,
    attachment_model=Attachment,
    comment_model=Comment,
    comment_media_model=CommentMedia,
    archive_cleanup_log_model=ArchiveCleanupLog,
    ticket_template_model=TicketTemplate,
    ticket_generation_key_model=TicketGenerationKey,
    user_model=User,
    org_unit_model=OrgUnit,
    role_enum=Role,
    ticket_status_enum=TicketStatus,
    archive_source_statuses=ARCHIVE_SOURCE_STATUSES,
    created_from_template_log_action=LOG_ACTION_CREATED_FROM_TEMPLATE,
    sqlalchemy_error_cls=SQLAlchemyError,
    http_exception_cls=HTTPException,
)

resolve_ticket_archive_retention_days = _ticket_runtime_service.resolve_ticket_archive_retention_days
is_ticket_archived = _ticket_runtime_service.is_ticket_archived
archive_ticket = _ticket_runtime_service.archive_ticket
restore_ticket_from_archive = _ticket_runtime_service.restore_ticket_from_archive
run_archive_cleanup_once = _ticket_runtime_service.run_archive_cleanup_once
run_archive_cleanup_forever = _ticket_runtime_service.run_archive_cleanup_forever
render_template_value = _ticket_runtime_service.render_template_value
ticket_exists_for_template_period = _ticket_runtime_service.ticket_exists_for_template_period
create_tickets_from_template = _ticket_runtime_service.create_tickets_from_template
resolve_company_actor_id = _ticket_runtime_service.resolve_company_actor_id
run_template_autogen_once = _ticket_runtime_service.run_template_autogen_once
run_template_autogen_forever = _ticket_runtime_service.run_template_autogen_forever

_deadline_reminder_service = DeadlineReminderService(
    session_factory=lambda: SessionLocal(),
    local_now=local_now,
    send_push_to_user_func=lambda **kwargs: send_push_to_user(**kwargs),
    ticket_notification_title=ticket_notification_title,
    push_reminder_minutes_getter=lambda: PUSH_REMINDER_MINUTES,
    push_reminder_poll_seconds_getter=lambda: PUSH_REMINDER_POLL_SECONDS,
    final_ticket_statuses_getter=lambda: FINAL_TICKET_STATUSES,
    time_module=time,
    timedelta_cls=timedelta,
    ticket_model=Ticket,
    deadline_reminder_log_model=DeadlineReminderLog,
)

run_deadline_reminders_once = _deadline_reminder_service.run_deadline_reminders_once
build_deadline_reminder_key = _deadline_reminder_service.build_reminder_key
run_deadline_reminders_forever = _deadline_reminder_service.run_deadline_reminders_forever


hash_password = partial(core_hash_password, pwd_context=pwd_context)
verify_password = partial(core_verify_password, pwd_context=pwd_context)
get_user_auth_token_version = core_get_user_auth_token_version
bump_user_auth_token_version = core_bump_user_auth_token_version
create_access_token = partial(
    core_create_access_token,
    jwt_module=jwt,
    jwt_secret=JWT_SECRET,
    algorithm=ALGORITHM,
    access_token_expire_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
)
is_email_verification_required = partial(
    core_is_email_verification_required,
    platform_admin_role=Role.platform_admin,
)
is_user_email_verified = partial(
    core_is_user_email_verified,
    platform_admin_role=Role.platform_admin,
)
ensure_user_can_authenticate = partial(
    core_ensure_user_can_authenticate,
    platform_admin_role=Role.platform_admin,
    http_exception_cls=HTTPException,
)
mark_user_email_verified = core_mark_user_email_verified
prepare_user_email_verification = partial(
    core_prepare_user_email_verification,
    email_verification_expire_hours=EMAIL_VERIFICATION_EXPIRE_HOURS,
)
prepare_user_password_reset = partial(
    core_prepare_user_password_reset,
    password_reset_expire_hours=PASSWORD_RESET_EXPIRE_HOURS,
)
build_email_verification_url = core_build_email_verification_url
build_password_reset_url = core_build_password_reset_url

_email_auth_support = EmailAuthSupport(
    email_message_cls=EmailMessage,
    smtplib_module=smtplib,
    logger=logger,
    email_delivery_error_cls=EmailDeliveryError,
    format_sender_email_getter=lambda: SMTP_FROM_EMAIL,
    format_sender_name_getter=lambda: SMTP_FROM_NAME,
    smtp_host_getter=lambda: SMTP_HOST,
    smtp_port_getter=lambda: SMTP_PORT,
    smtp_username_getter=lambda: SMTP_USERNAME,
    smtp_password_getter=lambda: SMTP_PASSWORD,
    smtp_use_tls_getter=lambda: SMTP_USE_TLS,
    smtp_use_ssl_getter=lambda: SMTP_USE_SSL,
    smtp_timeout_sec_getter=lambda: SMTP_TIMEOUT_SEC,
    email_verification_expire_hours_getter=lambda: EMAIL_VERIFICATION_EXPIRE_HOURS,
    password_reset_expire_hours_getter=lambda: PASSWORD_RESET_EXPIRE_HOURS,
    access_token_cookie_max_age_getter=lambda: ACCESS_TOKEN_COOKIE_MAX_AGE,
    now_utc_fn=datetime.utcnow,
    is_email_verification_required_func=is_email_verification_required,
    prepare_user_email_verification_func=prepare_user_email_verification,
    prepare_user_password_reset_func=prepare_user_password_reset,
    build_email_verification_url_func=build_email_verification_url,
    build_password_reset_url_func=build_password_reset_url,
    core_get_auth_cookie_params_func=core_get_auth_cookie_params,
    core_delete_auth_cookie_func=core_delete_auth_cookie,
)

format_email_sender = _email_auth_support.format_email_sender
send_email_message = _email_auth_support.send_email_message
send_user_verification_email = _email_auth_support.send_user_verification_email
send_user_password_reset_email = _email_auth_support.send_user_password_reset_email
get_auth_cookie_params = _email_auth_support.get_auth_cookie_params
delete_auth_cookie = _email_auth_support.delete_auth_cookie


def get_current_user(request: Request, token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    return resolve_current_user(
        request,
        token,
        db,
        user_model=User,
        jwt_module=jwt,
        jwt_secret=JWT_SECRET,
        algorithm=ALGORITHM,
        get_user_auth_token_version_func=get_user_auth_token_version,
        ensure_user_can_authenticate_func=ensure_user_can_authenticate,
        http_exception_cls=HTTPException,
    )

def require_role(*roles: Role):
    def checker(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return checker


def get_company_ticket_or_404(db: Session, user: User, ticket_id: int) -> Ticket:
    ensure_company_user(user)
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if ticket.company_id != user.company_id:
        raise HTTPException(403, "Forbidden")
    return ticket


def get_company_receipt_or_404(db: Session, user: User, receipt_id: int) -> Receipt:
    ensure_company_user(user)
    receipt = db.get(Receipt, receipt_id)
    if not receipt:
        raise HTTPException(404, "Receipt not found")
    if receipt.company_id != user.company_id:
        raise HTTPException(403, "Forbidden")
    return receipt


_receipt_support = ReceiptSupport(
    datetime_cls=datetime,
    decimal_cls=Decimal,
    invalid_operation_cls=InvalidOperation,
    path_cls=Path,
    re_module=re,
    cast_fn=cast,
    date_type=Date,
    or_fn=or_,
    receipt_model=Receipt,
    receipt_status_enum=ReceiptStatus,
    role_enum=Role,
)

parse_receipt_date = _receipt_support.parse_receipt_date
parse_receipt_amount = _receipt_support.parse_receipt_amount
normalize_bk_last4 = _receipt_support.normalize_bk_last4
sanitize_export_token = _receipt_support.sanitize_export_token
sanitize_filename_part = _receipt_support.sanitize_filename_part
build_receipt_original_name = _receipt_support.build_receipt_original_name
build_receipts_query = _receipt_support.build_receipts_query
resolve_preferred_card_id = _receipt_support.resolve_preferred_card_id


_company_cleanup_service = CompanyCleanupService(
    delete_stored_file_func=lambda stored_path: delete_stored_file(stored_path),
    ticket_model=Ticket,
    receipt_model=Receipt,
    user_model=User,
    attachment_model=Attachment,
    comment_model=Comment,
    ticket_log_model=TicketLog,
    ticket_watcher_model=TicketWatcher,
    deadline_reminder_log_model=DeadlineReminderLog,
    receipt_file_model=ReceiptFile,
    ticket_generation_key_model=TicketGenerationKey,
    unit_assignment_model=UnitAssignment,
    ticket_template_model=TicketTemplate,
    ticket_type_model=TicketType,
    org_unit_model=OrgUnit,
    unit_type_model=UnitType,
    department_model=Department,
    payment_card_model=PaymentCard,
    project_model=Project,
    registration_invite_model=RegistrationInvite,
    notification_model=Notification,
    archive_cleanup_log_model=ArchiveCleanupLog,
    push_subscription_model=PushSubscription,
    mobile_device_model=MobileDevice,
    company_model=Company,
)

delete_company_with_data = _company_cleanup_service.delete_company_with_data


def get_active_invite(db: Session, token: str | None) -> RegistrationInvite | None:
    return core_get_active_invite(
        db,
        token,
        registration_invite_model=RegistrationInvite,
    )

# =========================
# РџСЂРёР»РѕР¶РµРЅРёРµ
# =========================
app = FastAPI(title="Tickets Simple + Web UI")

@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    if request.url.path.startswith("/web") and request.method in {"POST", "PATCH", "PUT", "DELETE"}:
        if request.url.path in {
            "/web/login",
            "/web/register",
            "/web/register-company",
            "/web/verify-email/resend",
            "/web/password-reset",
            "/web/password-reset/confirm",
        }:
            return await call_next(request)
        expected_origin = request_origin(request)
        if not expected_origin:
            return JSONResponse(status_code=403, content={"detail": "CSRF blocked"})
        source = (request.headers.get("origin") or "").strip() or (request.headers.get("referer") or "").strip()
        if not source:
            return JSONResponse(status_code=403, content={"detail": "CSRF blocked"})
        source_origin = normalize_origin(source)
        if source_origin != expected_origin:
            return JSONResponse(status_code=403, content={"detail": "CSRF blocked"})
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(self), geolocation=()",
    )
    return response


@app.middleware("http")
async def sliding_session_middleware(request: Request, call_next):
    response = await call_next(request)

    if not request.url.path.startswith("/web"):
        return response
    if request.url.path in PUBLIC_WEB_PATHS:
        return response

    raw_token = (request.cookies.get("access_token") or "").strip()
    if not raw_token:
        return response
    if response.status_code >= 400:
        return response

    try:
        payload = jwt.decode(raw_token, JWT_SECRET, algorithms=[ALGORITHM])
        subject = str(payload.get("sub") or "").strip()
        token_version = int(payload.get("tv", 0) or 0)
        if not subject:
            return response
    except JWTError:
        return response

    user = None
    with SessionLocal() as db:
        try:
            user = db.get(User, int(subject))
        except (TypeError, ValueError):
            return response
    if not user or token_version != get_user_auth_token_version(user):
        return response

    refreshed_token = create_access_token(subject, get_user_auth_token_version(user))
    response.set_cookie(
        "access_token",
        refreshed_token,
        **get_auth_cookie_params(request),
    )
    return response


UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
PWA_STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(PWA_STATIC_DIR)), name="static")


templates = Jinja2Templates(directory="templates")
templates.env.globals["format_dt"] = format_dt
templates.env.globals["to_local_dt"] = to_local_dt
templates.env.globals["format_deadline"] = format_deadline
templates.env.globals["template_deadline_date_value"] = template_deadline_date_value
templates.env.globals["template_deadline_mode"] = template_deadline_mode
templates.env.globals["template_deadline_dom_value"] = template_deadline_dom_value
templates.env.globals["fix_mojibake_text"] = fix_mojibake_text
templates.env.globals["receipt_status_label_ru"] = receipt_status_label_ru
templates.env.globals["access_level_label_ru"] = access_level_label_ru


@app.on_event("startup")
def app_startup() -> None:
    maybe_repair_text_on_start(
        enabled=TEXT_REPAIR_ON_START,
        session_factory=SessionLocal,
        repair_fn=repair_mojibake_data,
    )
    ensure_platform_admin_user(
        session_factory=SessionLocal,
        user_model=User,
        role_enum=Role,
        hash_password=hash_password,
        normalize_capability_flags=normalize_capability_flags,
    )
    start_background_threads(
        push_enabled=push_is_configured(),
        template_autogen_enabled=TEMPLATE_AUTOGEN_ENABLED,
        deadline_runner=run_deadline_reminders_forever,
        template_runner=run_template_autogen_forever,
        archive_runner=run_archive_cleanup_forever,
    )


register_auth_routes(
    app,
    get_db=get_db,
    get_client_ip=get_client_ip,
    hit_rate_limit=hit_rate_limit,
    audit_security_event=audit_security_event,
    hash_password=hash_password,
    normalize_capability_flags=normalize_capability_flags,
    prepare_user_email_verification=prepare_user_email_verification,
    send_user_verification_email=send_user_verification_email,
    create_access_token=create_access_token,
    get_user_auth_token_version=get_user_auth_token_version,
    verify_password=verify_password,
    ensure_user_can_authenticate=ensure_user_can_authenticate,
    mark_user_email_verified=mark_user_email_verified,
    is_user_email_verified=is_user_email_verified,
    templates=templates,
    logger=logger,
    user_model=User,
    company_model=Company,
    role_enum=Role,
    bootstrap_setup_in_model=BootstrapSetupIn,
    bootstrap_setup_out_model=BootstrapSetupOut,
    token_out_model=TokenOut,
    email_delivery_error=EmailDeliveryError,
    sqlalchemy_error=SQLAlchemyError,
    rl_register_limit=RL_REGISTER_LIMIT,
    rl_register_window_sec=RL_REGISTER_WINDOW_SEC,
    rl_login_limit=RL_LOGIN_LIMIT,
    rl_login_window_sec=RL_LOGIN_WINDOW_SEC,
    rl_email_verification_limit=RL_EMAIL_VERIFICATION_LIMIT,
    rl_email_verification_window_sec=RL_EMAIL_VERIFICATION_WINDOW_SEC,
)

register_web_auth_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    get_client_ip=get_client_ip,
    hit_rate_limit=hit_rate_limit,
    audit_security_event=audit_security_event,
    verify_password=verify_password,
    is_user_email_verified=is_user_email_verified,
    create_access_token=create_access_token,
    get_user_auth_token_version=get_user_auth_token_version,
    get_auth_cookie_params=get_auth_cookie_params,
    delete_auth_cookie=delete_auth_cookie,
    normalize_settings_section=normalize_settings_section,
    build_settings_url=build_settings_url,
    bump_user_auth_token_version=bump_user_auth_token_version,
    clear_password_reset_state=clear_password_reset_state,
    hash_password=hash_password,
    normalize_capability_flags=normalize_capability_flags,
    prepare_user_email_verification=prepare_user_email_verification,
    send_user_verification_email=send_user_verification_email,
    send_user_password_reset_email=send_user_password_reset_email,
    get_active_invite=get_active_invite,
    register_company_owner=register_company_owner,
    templates=templates,
    logger=logger,
    user_model=User,
    company_model=Company,
    role_enum=Role,
    email_delivery_error=EmailDeliveryError,
    bootstrap_setup_in_model=BootstrapSetupIn,
    rl_login_limit=RL_LOGIN_LIMIT,
    rl_login_window_sec=RL_LOGIN_WINDOW_SEC,
    rl_register_limit=RL_REGISTER_LIMIT,
    rl_register_window_sec=RL_REGISTER_WINDOW_SEC,
    rl_password_reset_limit=RL_PASSWORD_RESET_LIMIT,
    rl_password_reset_window_sec=RL_PASSWORD_RESET_WINDOW_SEC,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_settings_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    require_role=require_role,
    ensure_company_user=ensure_company_user,
    is_platform_admin=is_platform_admin,
    normalize_settings_section=normalize_settings_section,
    build_settings_url=build_settings_url,
    get_company_deadline_soon_warning_minutes=get_company_deadline_soon_warning_minutes,
    get_company_archive_retention_days=get_company_archive_retention_days,
    parse_deadline_soon_warning_minutes=parse_deadline_soon_warning_minutes,
    parse_archive_retention_days=parse_archive_retention_days,
    is_native_android_app_request=is_native_android_app_request,
    templates=templates,
    user_model=User,
    company_model=Company,
    payment_card_model=PaymentCard,
    role_enum=Role,
    settings_sections=SETTINGS_SECTIONS,
    org_structure_v2_enabled=(lambda: ORG_STRUCTURE_V2_ENABLED),
    min_deadline_soon_warning_minutes=MIN_DEADLINE_SOON_WARNING_MINUTES,
    max_deadline_soon_warning_minutes=MAX_DEADLINE_SOON_WARNING_MINUTES,
    min_archive_retention_days=MIN_ARCHIVE_RETENTION_DAYS,
    max_archive_retention_days=MAX_ARCHIVE_RETENTION_DAYS,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_payment_card_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    ensure_company_user=ensure_company_user,
    normalize_settings_section=normalize_settings_section,
    build_settings_url=build_settings_url,
    func=func,
    payment_card_model=PaymentCard,
    receipt_model=Receipt,
    user_model=User,
    role_enum=Role,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_receipt_action_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    ensure_company_user=ensure_company_user,
    is_manager=is_manager,
    can_access_receipt=can_access_receipt,
    get_company_receipt_or_404=get_company_receipt_or_404,
    safe_next=safe_next,
    parse_receipt_amount=parse_receipt_amount,
    parse_receipt_date=parse_receipt_date,
    delete_stored_file=delete_stored_file,
    receipt_status_enum=ReceiptStatus,
    receipt_model=Receipt,
    receipt_file_model=ReceiptFile,
    project_model=Project,
    payment_card_model=PaymentCard,
    role_enum=Role,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_receipt_export_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    ensure_company_user=ensure_company_user,
    can_access_receipt=can_access_receipt,
    get_company_receipt_or_404=get_company_receipt_or_404,
    parse_receipt_date=parse_receipt_date,
    get_storage_basename=get_storage_basename,
    serve_stored_file_response=serve_stored_file_response,
    build_receipts_query=build_receipts_query,
    read_stored_file_bytes=read_stored_file_bytes,
    sanitize_export_token=sanitize_export_token,
    receipt_status_label_ru=receipt_status_label_ru,
    receipt_file_model=ReceiptFile,
    project_model=Project,
    payment_card_model=PaymentCard,
    user_model=User,
    role_enum=Role,
)

register_receipt_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    ensure_company_user=ensure_company_user,
    is_manager=is_manager,
    build_receipts_query=build_receipts_query,
    parse_receipt_date=parse_receipt_date,
    parse_receipt_amount=parse_receipt_amount,
    make_safe_upload_name=make_safe_upload_name,
    build_receipt_object_key=build_receipt_object_key,
    store_upload_file_to_storage_async=store_upload_file_to_storage_async,
    build_receipt_original_name=build_receipt_original_name,
    notify_receipt_created=notify_receipt_created,
    delete_stored_file=delete_stored_file,
    templates=templates,
    receipt_model=Receipt,
    receipt_file_model=ReceiptFile,
    project_model=Project,
    payment_card_model=PaymentCard,
    user_model=User,
    receipt_status_enum=ReceiptStatus,
    role_enum=Role,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_user_management_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    is_manager=is_manager,
    ensure_company_user=ensure_company_user,
    manageable_roles_for_web_user_management=(
        lambda actor: manageable_roles_for_web_user_management(actor, role_enum=Role)
    ),
    can_manage_company_user=(
        lambda actor, target: can_manage_company_user(actor, target, manager_roles=MANAGER_ROLES, role_enum=Role)
    ),
    manageable_template_access_levels_for_actor=(lambda actor: manageable_template_access_levels_for_actor(actor)),
    ensure_default_role_templates=(
        lambda db, company_id, allowed_access_levels: ensure_default_role_templates(db, company_id, allowed_access_levels)
    ),
    get_manageable_role_template=(
        lambda db, actor, template_id, allowed_access_levels=None: get_manageable_role_template(
            db,
            actor,
            template_id,
            allowed_access_levels=allowed_access_levels,
        )
    ),
    role_template_payload=(lambda template: role_template_payload(template)),
    normalize_role_template_name=normalize_role_template_name,
    normalize_role_label=normalize_role_label,
    parse_optional_int=(lambda raw_value: parse_optional_int(raw_value)),
    parse_bool_text=(lambda raw, default=True: parse_bool_text(raw, default=default)),
    normalize_capability_flags=normalize_capability_flags,
    hash_password=hash_password,
    prepare_user_email_verification=prepare_user_email_verification,
    send_user_verification_email=send_user_verification_email,
    bump_user_auth_token_version=bump_user_auth_token_version,
    access_level_label_ru=access_level_label_ru,
    templates=templates,
    logger=logger,
    func=func,
    or_=or_,
    user_model=User,
    role_template_model=RoleTemplate,
    registration_invite_model=RegistrationInvite,
    ticket_model=Ticket,
    comment_model=Comment,
    attachment_model=Attachment,
    ticket_log_model=TicketLog,
    ticket_template_model=TicketTemplate,
    unit_assignment_model=UnitAssignment,
    ticket_watcher_model=TicketWatcher,
    push_subscription_model=PushSubscription,
    mobile_device_model=MobileDevice,
    deadline_reminder_log_model=DeadlineReminderLog,
    notification_model=Notification,
    role_enum=Role,
    email_delivery_error=EmailDeliveryError,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_ticket_template_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    is_manager=is_manager,
    ensure_company_user=ensure_company_user,
    query_assignable_company_users=(lambda db, company_id: query_assignable_company_users(db, company_id)),
    validate_template_links=validate_template_links,
    resolve_ticket_department_id=resolve_ticket_department_id,
    parse_template_deadline_rule_from_form=parse_template_deadline_rule_from_form,
    create_tickets_from_template=create_tickets_from_template,
    normalize_period_key=normalize_period_key,
    month_period_key=month_period_key,
    quote=quote,
    templates=templates,
    ticket_template_model=TicketTemplate,
    ticket_type_model=TicketType,
    department_model=Department,
    org_unit_model=OrgUnit,
    user_model=User,
    ticket_model=Ticket,
    ticket_generation_key_model=TicketGenerationKey,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_ticket_type_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    is_manager=is_manager,
    is_admin=is_admin,
    ensure_company_user=ensure_company_user,
    parse_archive_retention_days=parse_archive_retention_days,
    templates=templates,
    ticket_type_model=TicketType,
    ticket_model=Ticket,
    department_model=Department,
    http_303_see_other=HTTP_303_SEE_OTHER,
)

register_ticket_overview_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    ensure_company_user=ensure_company_user,
    is_platform_admin=is_platform_admin,
    can_access_ticket=can_access_ticket,
    can_archive_ticket=can_archive_ticket,
    can_delete_ticket=can_delete_ticket,
    can_restore_ticket=can_restore_ticket,
    can_manage_ticket_legal_hold=can_manage_ticket_legal_hold,
    can_take_ticket_in_work=can_take_ticket_in_work,
    can_close_ticket=can_close_ticket,
    get_company_ticket_or_404=get_company_ticket_or_404,
    render_web_tickets_page=(
        lambda **kwargs: render_web_tickets_page(
            **kwargs,
            is_platform_admin=is_platform_admin,
            ensure_company_user=ensure_company_user,
            get_company_deadline_soon_warning_minutes=get_company_deadline_soon_warning_minutes,
            can_create_company_ticket=can_create_company_ticket,
            query_assignable_company_users=(lambda db, company_id: query_assignable_company_users(db, company_id)),
            resolve_scope_descendant_units=(lambda db, company_id, root_unit_id: resolve_scope_descendant_units(db, company_id, root_unit_id)),
            local_now=local_now,
            is_manager=is_manager,
            templates=templates,
            or_=or_,
            func=func,
            cast=cast,
            string_type=String,
            company_model=Company,
            ticket_model=Ticket,
            project_model=Project,
            user_model=User,
            role_enum=Role,
            ticket_type_model=TicketType,
            department_model=Department,
            org_unit_model=OrgUnit,
            unit_assignment_model=UnitAssignment,
            ticket_status_enum=TicketStatus,
            final_ticket_statuses=FINAL_TICKET_STATUSES,
            bulk_action_labels=TICKET_BULK_ACTION_LABELS,
            max_ticket_title_len=MAX_TICKET_TITLE_LEN,
            org_structure_v2_enabled=ORG_STRUCTURE_V2_ENABLED,
            http_303_see_other=HTTP_303_SEE_OTHER,
        )
    ),
    safe_next=safe_next,
    append_query_params=append_query_params,
    archive_ticket=archive_ticket,
    delete_ticket_with_related_data=delete_ticket_with_related_data,
    restore_ticket_from_archive=restore_ticket_from_archive,
    resolve_ticket_archive_retention_days=resolve_ticket_archive_retention_days,
    local_now=local_now,
    add_ticket_log=add_ticket_log,
    ensure_default_ticket_watchers=ensure_default_ticket_watchers,
    notify_executor_reassigned=notify_executor_reassigned,
    notify_curators_status_changed=notify_curators_status_changed,
    ticket_field_change_log_action=ticket_field_change_log_action,
    ticket_status_change_log_action=ticket_status_change_log_action,
    ticket_user_name=_ticket_user_name,
    bulk_action_labels=TICKET_BULK_ACTION_LABELS,
    ticket_model=Ticket,
    company_model=Company,
    ticket_status_enum=TicketStatus,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_ticket_action_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    is_manager=is_manager,
    can_access_ticket=can_access_ticket,
    can_archive_ticket=can_archive_ticket,
    can_delete_ticket=can_delete_ticket,
    get_company_ticket_or_404=get_company_ticket_or_404,
    safe_next=safe_next,
    archive_ticket=archive_ticket,
    restore_ticket_from_archive=restore_ticket_from_archive,
    resolve_ticket_archive_retention_days=resolve_ticket_archive_retention_days,
    local_now=local_now,
    add_ticket_log=add_ticket_log,
    delete_ticket_with_related_data=delete_ticket_with_related_data,
    notify_curators_status_changed=notify_curators_status_changed,
    get_company_deadline_soon_warning_minutes=get_company_deadline_soon_warning_minutes,
    ticket_status_change_log_action=ticket_status_change_log_action,
    ticket_status_enum=TicketStatus,
    final_ticket_statuses=FINAL_TICKET_STATUSES,
    company_model=Company,
    http_303_see_other=HTTP_303_SEE_OTHER,
)

register_ticket_detail_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    safe_next=safe_next,
    get_company_ticket_or_404=get_company_ticket_or_404,
    can_access_ticket=can_access_ticket,
    add_ticket_watcher=add_ticket_watcher,
    ensure_default_ticket_watchers=ensure_default_ticket_watchers,
    normalize_optional_uploaded_files=normalize_optional_uploaded_files,
    create_comment_with_media_async=create_comment_with_media_async,
    delete_stored_file=delete_stored_file,
    notify_comment_added=notify_comment_added,
    can_delete_comment=can_delete_comment,
    is_manager=is_manager,
    normalize_uploaded_files=normalize_uploaded_files,
    make_safe_upload_name=make_safe_upload_name,
    build_attachment_object_key=build_attachment_object_key,
    store_upload_file_to_storage_async=store_upload_file_to_storage_async,
    create_ticket_attachment_record=create_ticket_attachment_record,
    notify_curators_executor_act=notify_curators_executor_act,
    add_ticket_log=add_ticket_log,
    can_edit_ticket=can_edit_ticket,
    query_assignable_company_users=(lambda db, company_id: query_assignable_company_users(db, company_id)),
    validate_ticket_links=validate_ticket_links,
    resolve_ticket_department_id=resolve_ticket_department_id,
    parse_deadline_inputs=parse_deadline_inputs,
    ticket_field_change_log_action=ticket_field_change_log_action,
    ticket_status_change_log_action=ticket_status_change_log_action,
    ticket_deadline_text=_ticket_deadline_text,
    ticket_user_name=_ticket_user_name,
    ticket_project_name=_ticket_project_name,
    ticket_type_name=_ticket_type_name,
    department_name=_department_name,
    notify_executor_reassigned=notify_executor_reassigned,
    notify_curators_status_changed=notify_curators_status_changed,
    can_close_ticket=can_close_ticket,
    can_archive_ticket=can_archive_ticket,
    local_now=local_now,
    get_company_deadline_soon_warning_minutes=get_company_deadline_soon_warning_minutes,
    normalize_ticket_title=normalize_ticket_title,
    is_ticket_title_too_long=is_ticket_title_too_long,
    templates=templates,
    comment_model=Comment,
    comment_media_model=CommentMedia,
    attachment_model=Attachment,
    ticket_log_model=TicketLog,
    project_model=Project,
    ticket_type_model=TicketType,
    department_model=Department,
    user_model=User,
    ticket_watcher_model=TicketWatcher,
    company_model=Company,
    role_enum=Role,
    ticket_status_enum=TicketStatus,
    final_ticket_statuses=FINAL_TICKET_STATUSES,
    log_action_changed=LOG_ACTION_CHANGED,
    log_action_file_deleted=LOG_ACTION_FILE_DELETED,
    max_ticket_title_len=MAX_TICKET_TITLE_LEN,
    org_structure_v2_enabled=(lambda: ORG_STRUCTURE_V2_ENABLED),
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_ticket_create_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    ensure_company_user=ensure_company_user,
    can_create_company_ticket=can_create_company_ticket,
    normalize_ticket_title=normalize_ticket_title,
    is_ticket_title_too_long=is_ticket_title_too_long,
    parse_deadline_inputs=parse_deadline_inputs,
    validate_ticket_links=validate_ticket_links,
    resolve_ticket_department_id=resolve_ticket_department_id,
    resolve_target_unit_id_from_form_input=resolve_target_unit_id_from_form_input,
    resolve_scope_leaf_units=resolve_scope_leaf_units,
    get_or_create_project_for_org_unit=get_or_create_project_for_org_unit,
    get_preferred_executor_for_unit=get_preferred_executor_for_unit,
    ensure_default_ticket_watchers=ensure_default_ticket_watchers,
    add_ticket_watcher=add_ticket_watcher,
    add_ticket_log=add_ticket_log,
    notify_executor_new_ticket=notify_executor_new_ticket,
    templates_logger=logger,
    user_model=User,
    ticket_model=Ticket,
    role_enum=Role,
    ticket_status_enum=TicketStatus,
    org_structure_v2_enabled=(lambda: ORG_STRUCTURE_V2_ENABLED),
    log_action_created=LOG_ACTION_CREATED,
    max_ticket_title_len=MAX_TICKET_TITLE_LEN,
    http_303_see_other=HTTP_303_SEE_OTHER,
    operational_error=OperationalError,
    sqlalchemy_error=SQLAlchemyError,
)

register_org_structure_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    require_role=require_role,
    ensure_company_user=ensure_company_user,
    is_admin=is_admin,
    is_manager=is_manager,
    infer_org_structure_section=infer_org_structure_section,
    build_org_structure_url=build_org_structure_url,
    normalize_department_name=normalize_department_name,
    parse_bool_text=(lambda raw, default=True: parse_bool_text(raw, default=default)),
    department_match_filter=department_match_filter,
    query_assignable_company_users=(lambda db, company_id: query_assignable_company_users(db, company_id)),
    resolve_target_unit_id_from_form_input=resolve_target_unit_id_from_form_input,
    resolve_executor_id_from_form_input=resolve_executor_id_from_form_input,
    build_unit_parent_map=(lambda db, company_id: build_unit_parent_map(db, company_id)),
    would_create_unit_cycle=(
        lambda parent_map, unit_id, new_parent_id: would_create_unit_cycle(
            parent_map,
            unit_id=unit_id,
            new_parent_id=new_parent_id,
        )
    ),
    get_or_create_unit_type=(lambda db, company_id, type_name: get_or_create_unit_type(db, company_id, type_name)),
    org_structure_v2_enabled=(lambda: ORG_STRUCTURE_V2_ENABLED),
    org_structure_sections=(lambda: ORG_STRUCTURE_SECTIONS),
    templates=templates,
    func=func,
    or_=or_,
    company_model=Company,
    user_model=User,
    department_model=Department,
    unit_type_model=UnitType,
    org_unit_model=OrgUnit,
    unit_assignment_model=UnitAssignment,
    ticket_type_model=TicketType,
    ticket_template_model=TicketTemplate,
    ticket_model=Ticket,
    ticket_generation_key_model=TicketGenerationKey,
    role_enum=Role,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_admin_company_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    is_platform_admin=is_platform_admin,
    delete_company_with_data=(lambda db, company_id: delete_company_with_data(db, company_id)),
    parse_deadline_soon_warning_minutes=parse_deadline_soon_warning_minutes,
    parse_archive_retention_days=parse_archive_retention_days,
    normalize_capability_flags=normalize_capability_flags,
    hash_password=hash_password,
    prepare_user_email_verification=prepare_user_email_verification,
    send_user_verification_email=send_user_verification_email,
    bump_user_auth_token_version=bump_user_auth_token_version,
    templates=templates,
    logger=logger,
    func=func,
    or_=or_,
    company_model=Company,
    user_model=User,
    org_unit_model=OrgUnit,
    ticket_model=Ticket,
    comment_model=Comment,
    attachment_model=Attachment,
    ticket_log_model=TicketLog,
    ticket_template_model=TicketTemplate,
    unit_assignment_model=UnitAssignment,
    ticket_watcher_model=TicketWatcher,
    push_subscription_model=PushSubscription,
    mobile_device_model=MobileDevice,
    deadline_reminder_log_model=DeadlineReminderLog,
    notification_model=Notification,
    registration_invite_model=RegistrationInvite,
    role_enum=Role,
    min_deadline_soon_warning_minutes=MIN_DEADLINE_SOON_WARNING_MINUTES,
    max_deadline_soon_warning_minutes=MAX_DEADLINE_SOON_WARNING_MINUTES,
    min_archive_retention_days=MIN_ARCHIVE_RETENTION_DAYS,
    max_archive_retention_days=MAX_ARCHIVE_RETENTION_DAYS,
    email_delivery_error=EmailDeliveryError,
    http_303_see_other=HTTP_303_SEE_OTHER,
    sqlalchemy_error=SQLAlchemyError,
)

register_notification_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    ensure_company_user=ensure_company_user,
    templates=templates,
    Notification=Notification,
    func=func,
    fix_mojibake_text=fix_mojibake_text,
    http_303_see_other=HTTP_303_SEE_OTHER,
)

register_push_mobile_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    get_client_ip=get_client_ip,
    hit_rate_limit=hit_rate_limit,
    audit_security_event=audit_security_event,
    push_is_configured=lambda: push_is_configured(),
    mobile_push_is_configured=lambda: mobile_push_is_configured(),
    send_push_to_user_report=send_push_to_user_report,
    send_mobile_push_to_user_report=send_mobile_push_to_user_report,
    normalize_mobile_platform=normalize_mobile_platform,
    get_vapid_public_key=lambda: VAPID_PUBLIC_KEY,
    push_subscription_model=PushSubscription,
    mobile_device_model=MobileDevice,
    push_subscription_in_model=PushSubscriptionIn,
    push_unsubscribe_in_model=PushUnsubscribeIn,
    mobile_device_register_in_model=MobileDeviceRegisterIn,
    mobile_device_unregister_in_model=MobileDeviceUnregisterIn,
    rl_push_test_limit=RL_PUSH_TEST_LIMIT,
    rl_push_test_window_sec=RL_PUSH_TEST_WINDOW_SEC,
)



@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and request.url.path.startswith("/web"):
        return RedirectResponse(url="/web/login", status_code=HTTP_303_SEE_OTHER)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

register_public_routes(
    app,
    templates=templates,
    pwa_static_dir=PWA_STATIC_DIR,
    get_current_user=get_current_user,
)

register_reference_data_api_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    require_role=require_role,
    ensure_company_user=ensure_company_user,
    is_platform_admin=is_platform_admin,
    normalize_department_name=normalize_department_name,
    func=func,
    project_model=Project,
    department_model=Department,
    unit_type_model=UnitType,
    ticket_type_model=TicketType,
    ticket_template_model=TicketTemplate,
    unit_assignment_model=UnitAssignment,
    ticket_model=Ticket,
    org_unit_model=OrgUnit,
    role_enum=Role,
    project_create_model=ProjectCreate,
    project_out_model=ProjectOut,
    department_create_model=DepartmentCreate,
    department_update_model=DepartmentUpdate,
    department_out_model=DepartmentOut,
    unit_type_create_model=UnitTypeCreate,
    unit_type_update_model=UnitTypeUpdate,
    unit_type_out_model=UnitTypeOut,
)

register_users_api_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    require_role=require_role,
    ensure_company_user=ensure_company_user,
    normalize_bk_last4=normalize_bk_last4,
    normalize_role_label=normalize_role_label,
    normalize_capability_flags=normalize_capability_flags,
    hash_password=hash_password,
    prepare_user_email_verification=prepare_user_email_verification,
    send_user_verification_email=send_user_verification_email,
    logger=logger,
    user_model=User,
    role_enum=Role,
    user_create_model=UserCreate,
    user_out_model=UserOut,
    email_delivery_error=EmailDeliveryError,
)

register_ticket_catalog_api_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    require_role=require_role,
    ensure_company_user=ensure_company_user,
    is_platform_admin=is_platform_admin,
    validate_ticket_links=validate_ticket_links,
    normalize_ticket_type_archive_retention_days=normalize_ticket_type_archive_retention_days,
    validate_template_links=validate_template_links,
    resolve_ticket_department_id=resolve_ticket_department_id,
    normalize_period_key=normalize_period_key,
    month_period_key=month_period_key,
    create_tickets_from_template=create_tickets_from_template,
    ticket_type_model=TicketType,
    ticket_template_model=TicketTemplate,
    ticket_model=Ticket,
    ticket_generation_key_model=TicketGenerationKey,
    role_enum=Role,
    ticket_type_create_model=TicketTypeCreate,
    ticket_type_update_model=TicketTypeUpdate,
    ticket_type_out_model=TicketTypeOut,
    ticket_template_create_model=TicketTemplateCreate,
    ticket_template_update_model=TicketTemplateUpdate,
    ticket_template_out_model=TicketTemplateOut,
    ticket_template_run_in_model=TicketTemplateRunIn,
    sqlalchemy_error=SQLAlchemyError,
)

register_tickets_api_routes(
    app,
    get_db=get_db,
    get_current_user=get_current_user,
    is_platform_admin=is_platform_admin,
    ensure_company_user=ensure_company_user,
    can_create_company_ticket=can_create_company_ticket,
    can_access_ticket=can_access_ticket,
    can_close_ticket=can_close_ticket,
    normalize_ticket_title=normalize_ticket_title,
    is_ticket_title_too_long=is_ticket_title_too_long,
    validate_ticket_links=validate_ticket_links,
    resolve_ticket_department_id=resolve_ticket_department_id,
    ensure_default_ticket_watchers=ensure_default_ticket_watchers,
    add_ticket_log=add_ticket_log,
    notify_executor_new_ticket=notify_executor_new_ticket,
    get_api_ticket_or_404=get_api_ticket_or_404,
    ticket_field_change_log_action=ticket_field_change_log_action,
    ticket_status_change_log_action=ticket_status_change_log_action,
    ticket_deadline_text=_ticket_deadline_text,
    ticket_user_name=_ticket_user_name,
    ticket_project_name=_ticket_project_name,
    ticket_type_name=_ticket_type_name,
    department_name=_department_name,
    notify_executor_reassigned=notify_executor_reassigned,
    notify_curators_status_changed=notify_curators_status_changed,
    normalize_optional_uploaded_files=normalize_optional_uploaded_files,
    create_comment_with_media_async=create_comment_with_media_async,
    delete_stored_file=delete_stored_file,
    notify_comment_added=notify_comment_added,
    serialize_comment_out=serialize_comment_out,
    normalize_uploaded_files=normalize_uploaded_files,
    make_safe_upload_name=make_safe_upload_name,
    build_attachment_object_key=build_attachment_object_key,
    store_upload_file_to_storage=store_upload_file_to_storage,
    create_ticket_attachment_record=create_ticket_attachment_record,
    notify_curators_executor_act=notify_curators_executor_act,
    get_storage_basename=get_storage_basename,
    serve_stored_file_response=serve_stored_file_response,
    ticket_model=Ticket,
    comment_model=Comment,
    comment_media_model=CommentMedia,
    attachment_model=Attachment,
    role_enum=Role,
    ticket_status_enum=TicketStatus,
    ticket_create_model=TicketCreate,
    ticket_update_model=TicketUpdate,
    ticket_out_model=TicketOut,
    comment_out_model=CommentOut,
    attachment_out_model=AttachmentOut,
    log_action_created=LOG_ACTION_CREATED,
    log_action_changed=LOG_ACTION_CHANGED,
    log_action_target_unit_changed=LOG_ACTION_TARGET_UNIT_CHANGED,
    log_action_template_changed=LOG_ACTION_TEMPLATE_CHANGED,
    log_action_template_period_changed=LOG_ACTION_TEMPLATE_PERIOD_CHANGED,
    max_ticket_title_len=MAX_TICKET_TITLE_LEN,
    sqlalchemy_error=SQLAlchemyError,
)


# =========================
# WEB UI
# =========================
def get_or_create_unit_type(db: Session, company_id: int, type_name: str) -> UnitType:
    normalized = (type_name or "").strip() or "Узел"
    existing = (
        db.query(UnitType)
        .filter(
            UnitType.company_id == company_id,
            func.lower(UnitType.name) == normalized.lower(),
        )
        .first()
    )
    if existing:
        if not existing.is_active:
            existing.is_active = True
        return existing

    base_code = normalized.lower().replace(" ", "_")[:40] or "unit"
    code = base_code
    suffix = 2
    while (
        db.query(UnitType.id)
        .filter(UnitType.company_id == company_id, UnitType.code == code)
        .first()
        is not None
    ):
        code = f"{base_code}_{suffix}"
        suffix += 1

    item = UnitType(
        company_id=company_id,
        name=normalized,
        code=code,
        is_active=True,
    )
    db.add(item)
    db.flush()
    return item


def parse_bool_text(raw: str | None, default: bool = True) -> bool:
    value = (raw or "").strip().lower()
    if not value:
        return default
    if value in {"1", "true", "yes", "y", "on", "да"}:
        return True
    if value in {"0", "false", "no", "n", "off", "нет"}:
        return False
    return default


def parse_optional_int(raw_value: str | int | None) -> int | None:
    if raw_value is None:
        return None
    if isinstance(raw_value, int):
        return raw_value
    value = str(raw_value).strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def manageable_template_access_levels_for_actor(actor: "User") -> tuple[Role, ...]:
    return manageable_roles_for_web_user_management(actor, role_enum=Role)


def query_assignable_company_users(db: Session, company_id: int):
    return (
        db.query(User.id, User.name, User.email, User.role, User.role_label)
        .filter(
            User.company_id == company_id,
            User.role != Role.platform_admin,
            User.is_assignable_executor.is_(True),
        )
    )


def get_assignable_company_user_ids(db: Session, company_id: int) -> set[int]:
    return {int(row[0]) for row in query_assignable_company_users(db, company_id).with_entities(User.id).all()}


def role_template_payload(template: "RoleTemplate") -> dict[str, bool]:
    return normalize_capability_flags(
        template.access_level,
        show_receipts_accounting_mode=template.show_receipts_accounting_mode,
        is_assignable_executor=template.is_assignable_executor,
        can_view_all_tickets=template.can_view_all_tickets,
        can_create_tickets=template.can_create_tickets,
        can_close_tickets=template.can_close_tickets,
    )


def ensure_default_role_templates(
    db: Session,
    company_id: int,
    allowed_access_levels: tuple[Role, ...],
) -> None:
    if not allowed_access_levels:
        return
    existing_names = {
        str(row[0]).strip().casefold()
        for row in (
            db.query(RoleTemplate.name)
            .filter(RoleTemplate.company_id == company_id)
            .all()
        )
    }
    created = False
    for preset in DEFAULT_ROLE_TEMPLATE_PRESETS:
        access_level = preset["access_level"]
        if access_level not in allowed_access_levels:
            continue
        preset_name = str(preset["name"]).strip()
        if preset_name.casefold() in existing_names:
            continue
        flags = normalize_capability_flags(
            access_level,
            show_receipts_accounting_mode=bool(preset["show_receipts_accounting_mode"]),
            is_assignable_executor=bool(preset["is_assignable_executor"]),
            can_view_all_tickets=bool(preset["can_view_all_tickets"]),
            can_create_tickets=bool(preset["can_create_tickets"]),
            can_close_tickets=bool(preset["can_close_tickets"]),
        )
        db.add(
            RoleTemplate(
                company_id=company_id,
                name=preset_name,
                access_level=access_level,
                **flags,
            )
        )
        existing_names.add(preset_name.casefold())
        created = True
    if created:
        db.commit()


def get_manageable_role_template(
    db: Session,
    actor: "User",
    template_id: int | None,
    *,
    allowed_access_levels: tuple[Role, ...] | None = None,
) -> Optional["RoleTemplate"]:
    if template_id is None:
        return None
    template = db.get(RoleTemplate, template_id)
    if not template or template.company_id != actor.company_id:
        return None
    access_levels = allowed_access_levels or manageable_template_access_levels_for_actor(actor)
    if template.access_level not in access_levels:
        return None
    return template


def build_unit_parent_map(db: Session, company_id: int) -> dict[int, int | None]:
    rows = db.query(OrgUnit.id, OrgUnit.parent_id).filter(OrgUnit.company_id == company_id).all()
    return {int(r[0]): (int(r[1]) if r[1] is not None else None) for r in rows}


def would_create_unit_cycle(parent_map: dict[int, int | None], unit_id: int, new_parent_id: int | None) -> bool:
    current = new_parent_id
    visited: set[int] = set()
    while current is not None and current not in visited:
        if current == unit_id:
            return True
        visited.add(current)
        current = parent_map.get(current)
    return False
