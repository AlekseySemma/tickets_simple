from calendar import monthrange
from datetime import datetime, timedelta, date
import csv
from decimal import Decimal, InvalidOperation
from email.message import EmailMessage
from enum import Enum
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import smtplib
import threading
import time
import zipfile
from typing import Optional
import uuid
from urllib.parse import quote, urlencode, urlsplit
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
class Role(str, Enum):
    platform_admin = "PLATFORM_ADMIN"
    admin = "ADMIN"
    curator = "CURATOR"
    executor = "EXECUTOR"


MANAGER_ROLES = (Role.admin, Role.curator)
COMPANY_ACCESS_LEVELS = (Role.admin, Role.curator, Role.executor)
ACCESS_LEVEL_LABELS_RU = {
    Role.platform_admin: "Платформенный админ",
    Role.admin: "Владелец",
    Role.curator: "Куратор",
    Role.executor: "Сотрудник",
}
MAX_ROLE_LABEL_LEN = 80
MAX_ROLE_TEMPLATE_NAME_LEN = 80
DEFAULT_ROLE_TEMPLATE_PRESETS = (
    {
        "name": "Куратор",
        "access_level": Role.curator,
        "is_assignable_executor": False,
        "show_receipts_accounting_mode": True,
        "can_view_all_tickets": True,
        "can_create_tickets": True,
        "can_close_tickets": True,
    },
    {
        "name": "Исполнитель",
        "access_level": Role.executor,
        "is_assignable_executor": True,
        "show_receipts_accounting_mode": False,
        "can_view_all_tickets": False,
        "can_create_tickets": True,
        "can_close_tickets": True,
    },
    {
        "name": "Старший исполнитель",
        "access_level": Role.executor,
        "is_assignable_executor": True,
        "show_receipts_accounting_mode": True,
        "can_view_all_tickets": True,
        "can_create_tickets": True,
        "can_close_tickets": True,
    },
)

class TicketStatus(str, Enum):
    new = "NEW"
    in_progress = "IN_PROGRESS"
    done = "DONE"
    canceled = "CANCELED"
    archived = "ARCHIVED"


class ReceiptStatus(str, Enum):
    new = "NEW"
    in_processing = "IN_PROCESSING"
    accepted = "ACCEPTED"
    rejected = "REJECTED"


STATUS_LABELS_RU = {
    TicketStatus.new: "\u041d\u043e\u0432\u0430\u044f",
    TicketStatus.in_progress: "\u0412 \u0440\u0430\u0431\u043e\u0442\u0435",
    TicketStatus.done: "\u0412\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0430",
    TicketStatus.canceled: "\u041e\u0442\u043c\u0435\u043d\u0435\u043d\u0430",
    TicketStatus.archived: "\u0412 \u0430\u0440\u0445\u0438\u0432\u0435",
}

FINAL_TICKET_STATUSES = (TicketStatus.done, TicketStatus.canceled, TicketStatus.archived)
ARCHIVE_SOURCE_STATUSES = (TicketStatus.done, TicketStatus.canceled)
RECEIPT_STATUS_LABELS_RU = {
    ReceiptStatus.new: "Новый",
    ReceiptStatus.in_processing: "В обработке",
    ReceiptStatus.accepted: "Принят",
    ReceiptStatus.rejected: "Отклонён",
}


def status_label_ru(value: TicketStatus | str) -> str:
    if isinstance(value, TicketStatus):
        return STATUS_LABELS_RU.get(value, value.value)
    try:
        status_value = TicketStatus(value)
    except ValueError:
        return value
    return STATUS_LABELS_RU.get(status_value, status_value.value)


def receipt_status_label_ru(value: ReceiptStatus | str) -> str:
    if isinstance(value, ReceiptStatus):
        return RECEIPT_STATUS_LABELS_RU.get(value, value.value)
    try:
        status_value = ReceiptStatus(value)
    except ValueError:
        return value
    return RECEIPT_STATUS_LABELS_RU.get(status_value, status_value.value)


def ticket_status_change_log_action(old_status: TicketStatus | str, new_status: TicketStatus | str) -> str:
    old_label = status_label_ru(old_status)
    new_label = status_label_ru(new_status)
    return f"\u0418\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0441\u0442\u0430\u0442\u0443\u0441\u0430: {old_label} -> {new_label}"


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


def access_level_label_ru(value: Role | str) -> str:
    if isinstance(value, Role):
        return ACCESS_LEVEL_LABELS_RU.get(value, value.value)
    try:
        role_value = Role(value)
    except ValueError:
        return str(value)
    return ACCESS_LEVEL_LABELS_RU.get(role_value, role_value.value)


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
    title_template: Mapped[Optional[str]] = mapped_column(String(255), default=None)
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

def safe_next(next_url: str | None, fallback: str = "/web") -> str:
    n = (next_url or "").strip()
    if not n:
        return fallback
    return n if n.startswith("/web") else fallback


def is_native_android_app_request(request: Request) -> bool:
    user_agent = (request.headers.get("user-agent") or "").strip().lower()
    return ANDROID_APP_USER_AGENT_TOKEN in user_agent


def normalize_mobile_platform(value: str | None) -> str:
    platform = (value or "android").strip().lower()
    return platform if platform in {"android"} else ""


def append_query_params(url: str, **params: object) -> str:
    items: list[tuple[str, str]] = []
    for key, value in params.items():
        if value is None or value is False or value == "":
            continue
        items.append((key, "1" if value is True else str(value)))
    if not items:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(items)}"


def first_header_value(value: str | None) -> str:
    return (value or "").split(",")[0].strip()


def get_client_ip(request: Request | None) -> str:
    if request is None:
        return "unknown"
    forwarded_for = first_header_value(request.headers.get("x-forwarded-for"))
    if forwarded_for:
        return forwarded_for
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def normalize_email(value: str | None) -> str | None:
    v = (value or "").strip().lower()
    return v or None


def normalize_department_name(value: str | None) -> str:
    return " ".join((value or "").split()).strip()


def normalize_origin(value: str | None) -> tuple[str, str, int] | None:
    raw = (value or "").strip()
    if not raw:
        return None
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    return scheme, host, port


def request_origin(request: Request) -> tuple[str, str, int] | None:
    forwarded_proto = first_header_value(request.headers.get("x-forwarded-proto"))
    forwarded_host = first_header_value(request.headers.get("x-forwarded-host"))
    host_header = first_header_value(request.headers.get("host"))
    scheme = (forwarded_proto or request.url.scheme or "http").lower()
    host = forwarded_host or host_header or request.url.netloc
    if not host:
        return None
    return normalize_origin(f"{scheme}://{host}")


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


def can_archive_ticket(user: User, ticket: Ticket) -> bool:
    if ticket.status not in ARCHIVE_SOURCE_STATUSES:
        return False
    if is_manager(user):
        return True
    return bool(user.role == Role.executor and ticket.created_by == user.id)


def can_view_all_company_tickets(user: User) -> bool:
    return bool(is_manager(user) or getattr(user, "can_view_all_tickets", False))


def can_create_company_ticket(user: User) -> bool:
    if is_platform_admin(user):
        return False
    if is_manager(user):
        return True
    return bool(user.role == Role.executor and getattr(user, "can_create_tickets", True))


def can_close_ticket(user: User, ticket: Ticket) -> bool:
    if is_manager(user):
        return True
    if user.role != Role.executor or not getattr(user, "can_close_tickets", True):
        return False
    if getattr(user, "can_view_all_tickets", False):
        return True
    return bool(ticket.executor_id == user.id or ticket.created_by == user.id)


def can_edit_ticket(user: User, ticket: Ticket) -> bool:
    if is_manager(user):
        return True
    return bool(user.role == Role.executor and (ticket.executor_id == user.id or ticket.created_by == user.id))


def can_delete_ticket(user: User, ticket: Ticket) -> bool:
    if ticket.status == TicketStatus.archived:
        return is_manager(user)
    if is_manager(user):
        return True
    return bool(user.role == Role.executor and ticket.created_by == user.id)


def can_restore_ticket(user: User, ticket: Ticket) -> bool:
    return bool(is_manager(user) and ticket.status == TicketStatus.archived)


def can_manage_ticket_legal_hold(user: User, ticket: Ticket) -> bool:
    return bool(is_manager(user) and ticket.status == TicketStatus.archived)


def can_delete_comment(user: User, comment: Comment) -> bool:
    if is_manager(user):
        return True
    return bool(comment.author_id == user.id)


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


def can_access_ticket(user: User, ticket: Ticket) -> bool:
    if is_platform_admin(user):
        return True
    if can_view_all_company_tickets(user):
        return True
    return bool(user.role == Role.executor and (ticket.executor_id == user.id or ticket.created_by == user.id))


def can_take_ticket_in_work(user: User, ticket: Ticket) -> bool:
    if ticket.status != TicketStatus.new:
        return False
    if not can_access_ticket(user, ticket):
        return False
    if not is_assignable_executor_user(user):
        return False
    return ticket.executor_id is None or ticket.executor_id == user.id


def get_api_ticket_or_404(db: Session, user: User, ticket_id: int) -> Ticket:
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if not is_platform_admin(user):
        ensure_company_user(user)
        if ticket.company_id != user.company_id:
            raise HTTPException(403, "Forbidden")
    return ticket


_s3_client = None


def get_s3_client():
    global _s3_client
    if not BOTO3_AVAILABLE:
        raise RuntimeError("boto3 is required for S3 storage support")
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
    if _s3_client is None:
        config_kwargs = {
            "signature_version": "s3v4",
            "request_checksum_calculation": "when_required",
            "response_checksum_validation": "when_required",
        }
        if S3_ADDRESSING_STYLE in {"path", "virtual"}:
            config_kwargs["s3"] = {
                "addressing_style": S3_ADDRESSING_STYLE,
                # Some S3-compatible backends reject boto3's payload hash mode for PutObject.
                "payload_signing_enabled": False,
            }
        else:
            config_kwargs["s3"] = {"payload_signing_enabled": False}
        _s3_client = boto3.client(
            "s3",
            endpoint_url=S3_ENDPOINT_URL or None,
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
            region_name=S3_REGION or None,
            config=BotoConfig(**config_kwargs),
        )
    return _s3_client


def build_storage_key(*parts: str | None) -> str:
    tokens: list[str] = []
    for part in parts:
        value = str(part or "").replace("\\", "/").strip("/")
        if value:
            tokens.append(value)
    return "/".join(tokens)


def parse_s3_storage_path(raw_path: str | None) -> tuple[str, str] | None:
    raw = (raw_path or "").strip()
    if not raw.lower().startswith("s3://"):
        return None
    parsed = urlsplit(raw)
    bucket = (parsed.netloc or "").strip()
    key = parsed.path.lstrip("/")
    if not bucket or not key:
        return None
    return bucket, key


def build_s3_storage_path(object_key: str, bucket: str | None = None) -> str:
    target_bucket = (bucket or S3_BUCKET).strip()
    normalized_key = build_storage_key(object_key)
    if not target_bucket or not normalized_key:
        raise HTTPException(500, "S3 storage is not configured")
    return f"s3://{target_bucket}/{normalized_key}"


def build_attachment_object_key(stored_name: str, archived_ticket_id: int | None = None) -> str:
    if archived_ticket_id is None:
        return build_storage_key(ATTACHMENTS_STORAGE_PREFIX, stored_name)
    return build_storage_key(ATTACHMENTS_STORAGE_PREFIX, ARCHIVE_UPLOAD_SUBDIR, str(archived_ticket_id), stored_name)


def build_comment_media_object_key(stored_name: str, archived_ticket_id: int | None = None) -> str:
    if archived_ticket_id is None:
        return build_storage_key(COMMENT_MEDIA_STORAGE_PREFIX, stored_name)
    return build_storage_key(COMMENT_MEDIA_STORAGE_PREFIX, ARCHIVE_UPLOAD_SUBDIR, str(archived_ticket_id), stored_name)


def build_receipt_object_key(stored_name: str) -> str:
    return build_storage_key(RECEIPTS_STORAGE_PREFIX, stored_name)


def get_storage_basename(raw_path: str | None) -> str:
    s3_ref = parse_s3_storage_path(raw_path)
    if s3_ref:
        return Path(s3_ref[1]).name
    raw = (raw_path or "").strip()
    if raw.startswith("/uploads/"):
        return Path(raw.replace("/uploads/", "", 1)).name
    return Path(raw).name


def build_download_content_disposition(filename: str, disposition: str) -> str:
    safe_name = (filename or "file").replace("\\", "_").replace('"', "")
    return f"{disposition}; filename*=UTF-8''{quote(safe_name)}"


def get_upload_extension(filename: str | None) -> str:
    return Path(filename or "").suffix.lower()[:10]


def detect_comment_media_kind(filename: str | None) -> str:
    ext = get_upload_extension(filename)
    if ext in COMMENT_IMAGE_EXTENSIONS:
        return "photo"
    if ext in COMMENT_AUDIO_EXTENSIONS:
        return "voice"
    if ext in ALLOWED_UPLOAD_EXTENSIONS:
        return "file"
    raise HTTPException(400, "Unsupported comment media type")


def resolve_attachment_disk_path(raw_path: str | None) -> Path | None:
    raw = (raw_path or "").strip()
    if not raw or parse_s3_storage_path(raw):
        return None
    if raw.startswith("/uploads/"):
        candidate = UPLOAD_DIR / raw.replace("/uploads/", "", 1)
    else:
        parsed = Path(raw)
        candidate = parsed if parsed.is_absolute() else (UPLOAD_DIR / parsed)
    upload_root = UPLOAD_DIR.resolve(strict=False)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(upload_root)
    except ValueError:
        return None
    return resolved


def resolve_ticket_archive_retention_days(db: Session, ticket: Ticket, company: Company | None) -> int:
    if ticket.ticket_type_id is not None:
        tt = db.get(TicketType, ticket.ticket_type_id)
        if tt and tt.company_id == ticket.company_id and tt.archive_retention_days is not None:
            return clamp_archive_retention_days(tt.archive_retention_days)
    return get_company_archive_retention_days(company)


def is_ticket_archived(ticket: Ticket) -> bool:
    return ticket.status == TicketStatus.archived


def archive_ticket(db: Session, ticket: Ticket, actor_id: int, company: Company | None) -> None:
    if ticket.status not in ARCHIVE_SOURCE_STATUSES:
        raise HTTPException(400, "Only done or canceled tickets can be archived")
    if is_ticket_archived(ticket):
        return
    archived_at = local_now()
    retention_days = resolve_ticket_archive_retention_days(db, ticket, company)
    ticket.status = TicketStatus.archived
    ticket.archived_at = archived_at
    ticket.archived_by = actor_id
    ticket.retention_days = retention_days
    ticket.delete_at = archived_at + timedelta(days=retention_days)
    ticket.is_legal_hold = False
    attachments = db.query(Attachment).filter(Attachment.ticket_id == ticket.id).all()
    for attachment in attachments:
        move_attachment_to_archive(attachment, ticket.id, archived_at)
    comment_media_items = (
        db.query(CommentMedia)
        .join(Comment, Comment.id == CommentMedia.comment_id)
        .filter(Comment.ticket_id == ticket.id)
        .all()
    )
    for item in comment_media_items:
        move_comment_media_to_archive(item, ticket.id, archived_at)
    add_ticket_log(
        db,
        ticket_id=ticket.id,
        actor_id=actor_id,
        action=f"архивирование (удаление после {format_deadline(ticket.delete_at)})",
    )


def restore_ticket_from_archive(db: Session, ticket: Ticket, actor_id: int) -> None:
    if not is_ticket_archived(ticket):
        raise HTTPException(400, "Ticket is not archived")
    ticket.status = TicketStatus.done
    ticket.archived_at = None
    ticket.archived_by = None
    ticket.retention_days = None
    ticket.delete_at = None
    ticket.is_legal_hold = False
    attachments = db.query(Attachment).filter(Attachment.ticket_id == ticket.id).all()
    for attachment in attachments:
        move_attachment_to_active_storage(attachment, ticket.id)
    comment_media_items = (
        db.query(CommentMedia)
        .join(Comment, Comment.id == CommentMedia.comment_id)
        .filter(Comment.ticket_id == ticket.id)
        .all()
    )
    for item in comment_media_items:
        move_comment_media_to_active_storage(item, ticket.id)
    add_ticket_log(db, ticket_id=ticket.id, actor_id=actor_id, action="восстановление из архива")


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


def run_archive_cleanup_once() -> None:
    with SessionLocal() as db:
        candidates = (
            db.query(Ticket)
            .filter(
                Ticket.status == TicketStatus.archived,
                Ticket.delete_at.is_not(None),
                Ticket.delete_at <= local_now(),
                Ticket.is_legal_hold.is_(False),
            )
            .order_by(Ticket.delete_at.asc(), Ticket.id.asc())
            .all()
        )
        for ticket in candidates:
            try:
                deleted_at = local_now()
                db.add(
                    ArchiveCleanupLog(
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
                delete_ticket_with_related_data(db, ticket, remove_files=True)
                db.commit()
            except Exception:
                db.rollback()


def run_archive_cleanup_forever() -> None:
    while True:
        try:
            run_archive_cleanup_once()
        except Exception:
            pass
        time.sleep(ARCHIVE_CLEANUP_POLL_SECONDS)


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


def render_template_value(raw_value: str | None, period_key: str, unit_name: str) -> str | None:
    text = (raw_value or "").strip()
    if not text:
        return None
    return (
        text.replace("{period}", period_key)
        .replace("{unit_name}", unit_name)
        .replace("{month}", period_key)
    )


def ticket_exists_for_template_period(
    db: Session,
    company_id: int,
    template_id: int,
    target_unit_id: int,
    period_key: str,
) -> bool:
    row = (
        db.query(TicketGenerationKey.id)
        .filter(
            TicketGenerationKey.company_id == company_id,
            TicketGenerationKey.ticket_template_id == template_id,
            TicketGenerationKey.target_unit_id == target_unit_id,
            TicketGenerationKey.period_key == period_key,
        )
        .first()
    )
    return row is not None


def create_tickets_from_template(
    db: Session,
    *,
    template: TicketTemplate,
    actor_id: int,
    period_key: str | None = None,
) -> tuple[int, int, str]:
    effective_period = (period_key or "").strip() or month_period_key()
    if template.scope_unit_id is None:
        return 0, 0, effective_period
    template_department_id = resolve_ticket_department_id(
        db,
        company_id=template.company_id,
        ticket_type_id=template.ticket_type_id,
        department_id=template.department_id,
    )

    leaf_unit_ids = resolve_scope_leaf_units(db, template.company_id, template.scope_unit_id)
    if not leaf_unit_ids:
        return 0, 0, effective_period

    unit_rows = (
        db.query(OrgUnit.id, OrgUnit.name)
        .filter(OrgUnit.id.in_(leaf_unit_ids))
        .all()
    )
    unit_names = {int(unit_id): str(name or "").strip() for unit_id, name in unit_rows}

    batch_id = uuid.uuid4().hex
    created_count = 0
    skipped_count = 0
    for leaf_unit_id in leaf_unit_ids:
        if ticket_exists_for_template_period(
            db=db,
            company_id=template.company_id,
            template_id=template.id,
            target_unit_id=leaf_unit_id,
            period_key=effective_period,
        ):
            skipped_count += 1
            continue

        unit_name = unit_names.get(leaf_unit_id, f"Unit #{leaf_unit_id}")
        title = render_template_value(template.title_template, effective_period, unit_name) or f"{template.name} {effective_period}"
        description = render_template_value(template.description_template, effective_period, unit_name)
        project_id = get_or_create_project_for_org_unit(db, template.company_id, leaf_unit_id)
        resolved_executor_id = (
            template.default_executor_id
            if template.default_executor_id is not None
            else get_preferred_executor_for_unit(
                db,
                template.company_id,
                leaf_unit_id,
                department_id=template_department_id,
            )
        )

        try:
            with db.begin_nested():
                generation_key = TicketGenerationKey(
                    company_id=template.company_id,
                    ticket_template_id=template.id,
                    target_unit_id=leaf_unit_id,
                    period_key=effective_period,
                )
                db.add(generation_key)
                db.flush()
                ticket = Ticket(
                    title=title,
                    description=description,
                    deadline=resolve_deadline_by_rule(template.default_deadline_rule),
                    status=TicketStatus.new,
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
                ensure_default_ticket_watchers(db, ticket)
                generation_key.ticket_id = ticket.id
                add_ticket_log(db, ticket_id=ticket.id, actor_id=actor_id, action=LOG_ACTION_CREATED_FROM_TEMPLATE)
                if ticket.executor_id and ticket.executor_id != actor_id:
                    send_push_to_user(
                        db=db,
                        user_id=ticket.executor_id,
                        title=ticket_notification_title("Новая заявка", ticket.title, ticket_id=ticket.id),
                        body=ticket.title or "Вам назначена новая заявка",
                        url=f"/web/tickets/{ticket.id}",
                    )
            created_count += 1
        except SQLAlchemyError:
            skipped_count += 1

    return created_count, skipped_count, effective_period


def resolve_company_actor_id(db: Session, company_id: int) -> int | None:
    manager_row = (
        db.query(User.id)
        .filter(
            User.company_id == company_id,
            User.role.in_([Role.admin, Role.curator]),
        )
        .order_by(User.id.asc())
        .first()
    )
    if manager_row:
        return int(manager_row[0])
    any_row = (
        db.query(User.id)
        .filter(User.company_id == company_id)
        .order_by(User.id.asc())
        .first()
    )
    return int(any_row[0]) if any_row else None


def make_safe_upload_name(
    filename: str | None,
    ticket_id: int | None = None,
    allowed_extensions: set[str] | None = None,
) -> str:
    ext = get_upload_extension(filename)
    allowed = allowed_extensions or ALLOWED_UPLOAD_EXTENSIONS
    if not ext or ext not in allowed:
        raise HTTPException(400, "Unsupported file type")
    prefix = f"{ticket_id}_" if ticket_id is not None else ""
    return f"{prefix}{uuid.uuid4().hex}{ext}"


def normalize_ticket_title(raw_title: str | None) -> str:
    return (raw_title or "").strip()


def is_ticket_title_too_long(title: str | None) -> bool:
    return len(title or "") > MAX_TICKET_TITLE_LEN


def write_upload_file(upload: UploadFile, destination: Path, max_size: int = MAX_UPLOAD_SIZE_BYTES) -> None:
    total = 0
    try:
        with destination.open("wb") as out:
            while True:
                chunk = upload.file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    raise HTTPException(413, "File too large")
                out.write(chunk)
    except Exception:
        if destination.exists():
            destination.unlink()
        raise


async def write_upload_file_async(upload: UploadFile, destination: Path, max_size: int = MAX_UPLOAD_SIZE_BYTES) -> None:
    total = 0
    try:
        with destination.open("wb") as out:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    raise HTTPException(413, "File too large")
                out.write(chunk)
    except Exception:
        if destination.exists():
            destination.unlink()
        raise


def read_upload_bytes(upload: UploadFile, max_size: int = MAX_UPLOAD_SIZE_BYTES) -> bytes:
    total = 0
    chunks: list[bytes] = []
    while True:
        chunk = upload.file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_size:
            raise HTTPException(413, "File too large")
        chunks.append(chunk)
    return b"".join(chunks)


async def read_upload_bytes_async(upload: UploadFile, max_size: int = MAX_UPLOAD_SIZE_BYTES) -> bytes:
    total = 0
    chunks: list[bytes] = []
    while True:
        chunk = await upload.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_size:
            raise HTTPException(413, "File too large")
        chunks.append(chunk)
    return b"".join(chunks)


def build_upload_url_from_disk_path(path: Path) -> str:
    upload_root = UPLOAD_DIR.resolve(strict=False)
    resolved = path.resolve(strict=False)
    relative = resolved.relative_to(upload_root).as_posix()
    return f"/uploads/{relative}"


def compute_bytes_sha256_and_size(payload: bytes) -> tuple[str, int]:
    return hashlib.sha256(payload).hexdigest(), len(payload)


def store_bytes_in_storage(object_key: str, payload: bytes, content_type: str | None = None) -> str:
    normalized_key = build_storage_key(object_key)
    if STORAGE_BACKEND == "s3":
        put_kwargs = {
            "Bucket": S3_BUCKET,
            "Key": normalized_key,
            "Body": payload,
        }
        if content_type:
            put_kwargs["ContentType"] = content_type
        get_s3_client().put_object(**put_kwargs)
        return build_s3_storage_path(normalized_key)

    destination = UPLOAD_DIR / Path(normalized_key)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("wb") as out:
            out.write(payload)
    except Exception:
        if destination.exists():
            destination.unlink()
        raise
    return build_upload_url_from_disk_path(destination)


def store_upload_file_to_storage(upload: UploadFile, object_key: str, max_size: int = MAX_UPLOAD_SIZE_BYTES) -> tuple[str, str, int]:
    normalized_key = build_storage_key(object_key)
    if STORAGE_BACKEND == "s3":
        payload = read_upload_bytes(upload, max_size=max_size)
        file_hash, file_size = compute_bytes_sha256_and_size(payload)
        stored_path = store_bytes_in_storage(normalized_key, payload, content_type=upload.content_type)
        return stored_path, file_hash, file_size

    destination = UPLOAD_DIR / Path(normalized_key)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_upload_file(upload, destination, max_size=max_size)
    file_hash, file_size = compute_file_sha256_and_size(destination)
    return build_upload_url_from_disk_path(destination), file_hash, file_size


async def store_upload_file_to_storage_async(upload: UploadFile, object_key: str, max_size: int = MAX_UPLOAD_SIZE_BYTES) -> tuple[str, str, int]:
    normalized_key = build_storage_key(object_key)
    if STORAGE_BACKEND == "s3":
        payload = await read_upload_bytes_async(upload, max_size=max_size)
        file_hash, file_size = compute_bytes_sha256_and_size(payload)
        stored_path = store_bytes_in_storage(normalized_key, payload, content_type=upload.content_type)
        return stored_path, file_hash, file_size

    destination = UPLOAD_DIR / Path(normalized_key)
    destination.parent.mkdir(parents=True, exist_ok=True)
    await write_upload_file_async(upload, destination, max_size=max_size)
    file_hash, file_size = compute_file_sha256_and_size(destination)
    return build_upload_url_from_disk_path(destination), file_hash, file_size


def read_stored_file_bytes(raw_path: str | None) -> tuple[bytes, str] | None:
    s3_ref = parse_s3_storage_path(raw_path)
    if s3_ref:
        bucket, key = s3_ref
        try:
            response = get_s3_client().get_object(Bucket=bucket, Key=key)
            body = response.get("Body")
            if body is None:
                return None
            try:
                payload = body.read()
            finally:
                close = getattr(body, "close", None)
                if callable(close):
                    close()
            return payload, Path(key).name
        except (BotoCoreError, ClientError):
            return None

    disk_path = resolve_attachment_disk_path(raw_path)
    if not disk_path or not disk_path.exists() or not disk_path.is_file():
        return None
    return disk_path.read_bytes(), disk_path.name


def delete_stored_file(raw_path: str | None) -> None:
    s3_ref = parse_s3_storage_path(raw_path)
    if s3_ref:
        bucket, key = s3_ref
        try:
            get_s3_client().delete_object(Bucket=bucket, Key=key)
        except (BotoCoreError, ClientError, RuntimeError):
            pass
        return

    disk_path = resolve_attachment_disk_path(raw_path)
    if not disk_path:
        return
    try:
        if disk_path.exists() and disk_path.is_file():
            disk_path.unlink()
    except OSError:
        pass


def build_presigned_storage_download_url(raw_path: str | None, display_name: str, disposition: str) -> str | None:
    s3_ref = parse_s3_storage_path(raw_path)
    if not s3_ref:
        return None
    bucket, key = s3_ref
    params = {
        "Bucket": bucket,
        "Key": key,
        "ResponseContentDisposition": build_download_content_disposition(display_name, disposition),
    }
    return str(get_s3_client().generate_presigned_url("get_object", Params=params, ExpiresIn=S3_PRESIGNED_TTL_SECONDS))


def serve_stored_file_response(raw_path: str | None, display_name: str, disposition: str, not_found_detail: str):
    presigned_url = build_presigned_storage_download_url(raw_path, display_name, disposition)
    if presigned_url:
        return RedirectResponse(url=presigned_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    disk_path = resolve_attachment_disk_path(raw_path)
    if not disk_path or not disk_path.exists() or not disk_path.is_file():
        raise HTTPException(404, not_found_detail)
    return FileResponse(disk_path, filename=display_name, content_disposition_type=disposition)


def move_stored_file_to_key(raw_path: str | None, target_key: str) -> str | None:
    normalized_key = build_storage_key(target_key)
    s3_ref = parse_s3_storage_path(raw_path)

    if STORAGE_BACKEND == "s3":
        if s3_ref:
            source_bucket, source_key = s3_ref
            target_bucket = S3_BUCKET or source_bucket
            if source_bucket == target_bucket and source_key == normalized_key:
                return build_s3_storage_path(normalized_key, bucket=target_bucket)
            client = get_s3_client()
            client.copy_object(Bucket=target_bucket, CopySource={"Bucket": source_bucket, "Key": source_key}, Key=normalized_key)
            client.delete_object(Bucket=source_bucket, Key=source_key)
            return build_s3_storage_path(normalized_key, bucket=target_bucket)

        source = resolve_attachment_disk_path(raw_path)
        if not source or not source.exists() or not source.is_file():
            return None
        payload = source.read_bytes()
        stored_path = store_bytes_in_storage(normalized_key, payload)
        try:
            source.unlink()
        except OSError:
            pass
        return stored_path

    target = UPLOAD_DIR / Path(normalized_key)
    target.parent.mkdir(parents=True, exist_ok=True)
    if s3_ref:
        payload_info = read_stored_file_bytes(raw_path)
        if not payload_info:
            return None
        payload, _ = payload_info
        try:
            with target.open("wb") as out:
                out.write(payload)
        except Exception:
            if target.exists():
                target.unlink()
            raise
        delete_stored_file(raw_path)
        return build_upload_url_from_disk_path(target)

    source = resolve_attachment_disk_path(raw_path)
    if not source or not source.exists() or not source.is_file():
        return None
    if source.resolve(strict=False) != target.resolve(strict=False):
        shutil.move(str(source), str(target))
    return build_upload_url_from_disk_path(target)


def compute_file_sha256_and_size(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


def enrich_attachment_metadata(attachment: Attachment, disk_path: Path | None = None) -> None:
    resolved = disk_path or resolve_attachment_disk_path(attachment.file_path)
    if not resolved or not resolved.exists() or not resolved.is_file():
        return
    file_hash, file_size = compute_file_sha256_and_size(resolved)
    attachment.file_sha256 = file_hash
    attachment.file_size_bytes = file_size



def create_ticket_attachment_record(
    *,
    db: Session,
    ticket_id: int,
    uploader_id: int,
    upload: UploadFile,
    stored_path: str,
    file_hash: str,
    file_size: int,
) -> Attachment:
    attachment = Attachment(
        ticket_id=ticket_id,
        uploader_id=uploader_id,
        file_path=stored_path,
        original_name=upload.filename,
    )
    attachment.file_sha256 = file_hash
    attachment.file_size_bytes = file_size
    db.add(attachment)
    add_ticket_log(db, ticket_id=ticket_id, actor_id=uploader_id, action=LOG_ACTION_FILE_ADDED)
    return attachment


def create_comment_media_record(
    *,
    db: Session,
    comment_id: int,
    upload: UploadFile,
    stored_path: str,
    file_hash: str,
    file_size: int,
    media_kind: str,
) -> CommentMedia:
    item = CommentMedia(
        comment_id=comment_id,
        file_path=stored_path,
        original_name=upload.filename,
        media_kind=media_kind,
    )
    item.file_sha256 = file_hash
    item.file_size_bytes = file_size
    db.add(item)
    return item


def normalize_uploaded_files(files: list[UploadFile]) -> list[UploadFile]:
    valid_files: list[UploadFile] = []
    for upload in files:
        if upload and (upload.filename or "").strip():
            valid_files.append(upload)
    if not valid_files:
        raise HTTPException(400, "No files uploaded")
    return valid_files


def normalize_optional_uploaded_files(files: list[UploadFile] | None) -> list[UploadFile]:
    valid_files: list[UploadFile] = []
    for upload in files or []:
        if upload and (upload.filename or "").strip():
            valid_files.append(upload)
    return valid_files


def serialize_comment_out(comment: Comment, media_items: list[CommentMedia] | None = None) -> CommentOut:
    return CommentOut(
        id=comment.id,
        ticket_id=comment.ticket_id,
        author_id=comment.author_id,
        text=comment.text,
        created_at=comment.created_at,
        media=[
            CommentMediaOut(
                id=item.id,
                comment_id=item.comment_id,
                file_path=item.file_path,
                original_name=item.original_name,
                media_kind=item.media_kind,
                file_size_bytes=item.file_size_bytes,
                file_sha256=item.file_sha256,
                archived_at=item.archived_at,
                created_at=item.created_at,
            )
            for item in (media_items or [])
        ],
    )


def summarize_comment_media(photo_count: int, voice_count: int, file_count: int, author_name: str) -> str:
    if photo_count and voice_count and file_count:
        return f"{author_name} добавил фото, голосовое сообщение и файл"
    if photo_count and voice_count:
        return f"{author_name} добавил фото и голосовое сообщение"
    if photo_count and file_count:
        return f"{author_name} добавил фото и файл"
    if voice_count and file_count:
        return f"{author_name} добавил голосовое сообщение и файл"
    if photo_count:
        return f"{author_name} добавил фото"
    if voice_count:
        return f"{author_name} добавил голосовое сообщение"
    if file_count:
        return f"{author_name} добавил файл"
    return f"{author_name} оставил комментарий"


async def create_comment_with_media_async(
    *,
    db: Session,
    ticket_id: int,
    author_id: int,
    text: str,
    photos: list[UploadFile] | None = None,
    voice_messages: list[UploadFile] | None = None,
    attachments: list[UploadFile] | None = None,
) -> tuple[Comment, list[CommentMedia], list[str]]:
    clean_text = (text or "").strip()
    photo_uploads = normalize_optional_uploaded_files(photos)
    voice_uploads = normalize_optional_uploaded_files(voice_messages)
    attachment_uploads = normalize_optional_uploaded_files(attachments)
    if not clean_text and not photo_uploads and not voice_uploads and not attachment_uploads:
        raise HTTPException(400, "Comment text, photo or voice message is required")

    upload_plan: list[tuple[UploadFile, str, str]] = []
    for upload in photo_uploads:
        if detect_comment_media_kind(upload.filename) != "photo":
            raise HTTPException(400, "Photos field accepts images only")
        upload_plan.append(
            (
                upload,
                "photo",
                make_safe_upload_name(
                    upload.filename,
                    ticket_id=ticket_id,
                    allowed_extensions=COMMENT_MEDIA_EXTENSIONS,
                ),
            )
        )
    for upload in voice_uploads:
        if detect_comment_media_kind(upload.filename) != "voice":
            raise HTTPException(400, "Voice messages field accepts audio only")
        upload_plan.append(
            (
                upload,
                "voice",
                make_safe_upload_name(
                    upload.filename,
                    ticket_id=ticket_id,
                    allowed_extensions=COMMENT_MEDIA_EXTENSIONS,
                ),
            )
        )
    for upload in attachment_uploads:
        media_kind = detect_comment_media_kind(upload.filename)
        upload_plan.append(
            (
                upload,
                media_kind,
                make_safe_upload_name(
                    upload.filename,
                    ticket_id=ticket_id,
                    allowed_extensions=COMMENT_MEDIA_EXTENSIONS,
                ),
            )
        )

    comment = Comment(ticket_id=ticket_id, author_id=author_id, text=clean_text)
    db.add(comment)
    db.flush()

    stored_paths: list[str] = []
    media_items: list[CommentMedia] = []
    try:
        for upload, media_kind, safe_name in upload_plan:
            object_key = build_comment_media_object_key(safe_name)
            stored_path, file_hash, file_size = await store_upload_file_to_storage_async(upload, object_key)
            stored_paths.append(stored_path)
            media_items.append(
                create_comment_media_record(
                    db=db,
                    comment_id=comment.id,
                    upload=upload,
                    stored_path=stored_path,
                    file_hash=file_hash,
                    file_size=file_size,
                    media_kind=media_kind,
                )
            )
    except Exception:
        for stored_path in stored_paths:
            delete_stored_file(stored_path)
        raise
    return comment, media_items, stored_paths

def choose_attachment_storage_name(attachment: Attachment, ticket_id: int) -> str:
    preferred_name = (attachment.original_name or "").strip()
    if preferred_name:
        try:
            return make_safe_upload_name(preferred_name, ticket_id=ticket_id)
        except HTTPException:
            pass
    fallback_name = Path(attachment.file_path or "").name
    try:
        return make_safe_upload_name(fallback_name, ticket_id=ticket_id)
    except HTTPException:
        ext = Path(fallback_name).suffix.lower()[:10]
        if not ext:
            ext = ".bin"
        return f"{ticket_id}_{uuid.uuid4().hex}{ext}"


def choose_comment_media_storage_name(item: CommentMedia, ticket_id: int) -> str:
    preferred_name = (item.original_name or "").strip()
    if preferred_name:
        try:
            return make_safe_upload_name(
                preferred_name,
                ticket_id=ticket_id,
                allowed_extensions=COMMENT_MEDIA_EXTENSIONS,
            )
        except HTTPException:
            pass
    fallback_name = Path(item.file_path or "").name
    try:
        return make_safe_upload_name(
            fallback_name,
            ticket_id=ticket_id,
            allowed_extensions=COMMENT_MEDIA_EXTENSIONS,
        )
    except HTTPException:
        ext = get_upload_extension(fallback_name)
        if not ext:
            ext = ".bin"
        return f"{ticket_id}_{uuid.uuid4().hex}{ext}"


def move_attachment_to_archive(attachment: Attachment, ticket_id: int, archived_at: datetime) -> None:
    archive_name = choose_attachment_storage_name(attachment, ticket_id)
    target_key = build_attachment_object_key(archive_name, archived_ticket_id=ticket_id)
    target_path = move_stored_file_to_key(attachment.file_path, target_key)
    if not target_path:
        attachment.archived_at = archived_at
        return
    attachment.file_path = target_path
    attachment.archived_at = archived_at


def move_attachment_to_active_storage(attachment: Attachment, ticket_id: int) -> None:
    active_name = choose_attachment_storage_name(attachment, ticket_id)
    target_key = build_attachment_object_key(active_name)
    target_path = move_stored_file_to_key(attachment.file_path, target_key)
    if not target_path:
        attachment.archived_at = None
        return
    attachment.file_path = target_path
    attachment.archived_at = None


def move_comment_media_to_archive(item: CommentMedia, ticket_id: int, archived_at: datetime) -> None:
    archive_name = choose_comment_media_storage_name(item, ticket_id)
    target_key = build_comment_media_object_key(archive_name, archived_ticket_id=ticket_id)
    target_path = move_stored_file_to_key(item.file_path, target_key)
    if not target_path:
        item.archived_at = archived_at
        return
    item.file_path = target_path
    item.archived_at = archived_at


def move_comment_media_to_active_storage(item: CommentMedia, ticket_id: int) -> None:
    active_name = choose_comment_media_storage_name(item, ticket_id)
    target_key = build_comment_media_object_key(active_name)
    target_path = move_stored_file_to_key(item.file_path, target_key)
    if not target_path:
        item.archived_at = None
        return
    item.file_path = target_path
    item.archived_at = None


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


def create_inapp_notification(db: Session, user_id: int, title: str, body: str, url: str) -> None:
    user = db.get(User, user_id)
    if not user:
        return
    n = Notification(
        company_id=user.company_id,
        user_id=user_id,
        title=fix_mojibake_text((title or "").strip())[:255] or "Уведомление",
        body=(fix_mojibake_text((body or "").strip())[:2000] or None),
        url=(url or "").strip()[:500] or "/web",
        is_read=False,
    )
    db.add(n)


def send_push_to_user(db: Session, user_id: int, title: str, body: str, url: str) -> None:
    safe_title = fix_mojibake_text((title or "").strip()) or "\u0423\u0432\u0435\u0434\u043e\u043c\u043b\u0435\u043d\u0438\u0435"
    safe_body = fix_mojibake_text((body or "").strip())
    safe_url = (url or "").strip() or "/web"
    create_inapp_notification(db=db, user_id=user_id, title=safe_title, body=safe_body, url=safe_url)
    _ = send_push_to_user_report(db=db, user_id=user_id, title=safe_title, body=safe_body, url=safe_url)
    _ = send_mobile_push_to_user_report(db=db, user_id=user_id, title=safe_title, body=safe_body, url=safe_url)


def notify_executor_new_ticket(db: Session, ticket: Ticket, actor: User) -> None:
    if not ticket.executor_id:
        return
    if ticket.executor_id == actor.id:
        return
    send_push_to_user(
        db=db,
        user_id=ticket.executor_id,
        title=ticket_notification_title("Новая заявка", ticket.title, ticket_id=ticket.id),
        body=ticket.title or "\u0412\u0430\u043c \u043d\u0430\u0437\u043d\u0430\u0447\u0435\u043d\u0430 \u043d\u043e\u0432\u0430\u044f \u0437\u0430\u044f\u0432\u043a\u0430",
        url=f"/web/tickets/{ticket.id}",
    )


def notify_executor_reassigned(db: Session, ticket: Ticket, old_executor_id: Optional[int], actor: User) -> None:
    if not ticket.executor_id or ticket.executor_id == old_executor_id:
        return
    if ticket.executor_id == actor.id:
        return
    send_push_to_user(
        db=db,
        user_id=ticket.executor_id,
        title=ticket_notification_title("Вам назначена заявка", ticket.title, ticket_id=ticket.id),
        body=ticket.title or "\u0417\u0430\u044f\u0432\u043a\u0430 \u043d\u0430\u0437\u043d\u0430\u0447\u0435\u043d\u0430 \u043d\u0430 \u0432\u0430\u0441",
        url=f"/web/tickets/{ticket.id}",
    )


def notify_curators_status_changed(db: Session, ticket: Ticket, actor: User, old_status: TicketStatus) -> None:
    if old_status == ticket.status:
        return
    curator_ids = [
        u.id
        for u in db.query(User).filter(User.role == Role.curator, User.company_id == ticket.company_id).all()
        if u.id != actor.id
    ]
    for curator_id in curator_ids:
        send_push_to_user(
            db=db,
            user_id=curator_id,
            title=ticket_notification_title("Изменен статус заявки", ticket.title, ticket_id=ticket.id),
            body=f"{actor.name}: {status_label_ru(old_status)} -> {status_label_ru(ticket.status)}",
            url=f"/web/tickets/{ticket.id}",
        )


def notify_comment_added(
    db: Session,
    ticket: Ticket,
    author: User,
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
        u.id for u in db.query(User).filter(User.role == Role.curator, User.company_id == ticket.company_id).all()
    ]
    recipient_ids.update(int(curator_id) for curator_id in curator_ids)

    watcher_rows = (
        db.query(TicketWatcher.user_id)
        .join(User, User.id == TicketWatcher.user_id)
        .filter(
            TicketWatcher.ticket_id == ticket.id,
            User.notify_comments_as_watcher.is_(True),
        )
        .all()
    )
    recipient_ids.update(int(row[0]) for row in watcher_rows if row and row[0] is not None)

    recipient_ids.discard(author.id)

    for recipient_id in recipient_ids:
        send_push_to_user(
            db=db,
            user_id=recipient_id,
            title=ticket_notification_title("Новый комментарий", ticket.title, ticket_id=ticket.id),
            body=short_text or summarize_comment_media(photo_count, voice_count, file_count, author.name),
            url=f"/web/tickets/{ticket.id}",
        )


def notify_curators_executor_act(db: Session, ticket: Ticket, uploader: User, original_name: str | None) -> None:
    if uploader.role != Role.executor:
        return
    file_name = fix_mojibake_text((original_name or "").lower())
    if "\u0430\u043a\u0442" not in file_name and "act" not in file_name:
        return
    curator_ids = [
        u.id
        for u in db.query(User).filter(User.role == Role.curator, User.company_id == ticket.company_id).all()
        if u.id != uploader.id
    ]
    for curator_id in curator_ids:
        send_push_to_user(
            db=db,
            user_id=curator_id,
            title=ticket_notification_title("Исполнитель прикрепил акт", ticket.title, ticket_id=ticket.id),
            body=original_name or "\u0414\u043e\u0431\u0430\u0432\u043b\u0435\u043d \u0444\u0430\u0439\u043b \u0430\u043a\u0442\u0430",
            url=f"/web/tickets/{ticket.id}",
        )


def notify_receipt_created(db: Session, receipt: Receipt, actor: User) -> None:
    recipient_rows = (
        db.query(User.id)
        .filter(
            User.company_id == receipt.company_id,
            User.id != actor.id,
            User.show_receipts_accounting_mode.is_(True),
            User.notify_receipt_created.is_(True),
            User.role != Role.platform_admin,
        )
        .all()
    )
    if not recipient_rows:
        return

    project_name = (
        db.query(Project.name)
        .filter(Project.id == receipt.project_id, Project.company_id == receipt.company_id)
        .scalar()
    )
    card_name = (
        db.query(PaymentCard.name)
        .filter(PaymentCard.id == receipt.card_id, PaymentCard.company_id == receipt.company_id)
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
    url = f"/web/receipts?mode=accounting"
    title = f"Новый чек #{receipt.id}"
    for row in recipient_rows:
        recipient_id = int(row[0])
        send_push_to_user(
            db=db,
            user_id=recipient_id,
            title=title,
            body=body,
            url=url,
        )


def run_deadline_reminders_forever() -> None:
    while True:
        try:
            with SessionLocal() as db:
                now = local_now()
                horizon = now + timedelta(seconds=PUSH_REMINDER_POLL_SECONDS)
                deadline_from = now + timedelta(minutes=PUSH_REMINDER_MINUTES)
                deadline_to = horizon + timedelta(minutes=PUSH_REMINDER_MINUTES)
                candidates = (
                    db.query(Ticket.id, Ticket.title, Ticket.executor_id, Ticket.deadline)
                    .filter(
                        Ticket.executor_id.is_not(None),
                        Ticket.deadline.is_not(None),
                        Ticket.status.notin_(list(FINAL_TICKET_STATUSES)),
                        Ticket.deadline >= deadline_from,
                        Ticket.deadline <= deadline_to,
                    )
                    .all()
                )

                reminder_keys = [
                    f"{t.id}:{t.executor_id}:{int(t.deadline.timestamp())}:{PUSH_REMINDER_MINUTES}"
                    for t in candidates
                ]
                existing_keys = set()
                if reminder_keys:
                    existing_rows = (
                        db.query(DeadlineReminderLog.reminder_key)
                        .filter(DeadlineReminderLog.reminder_key.in_(reminder_keys))
                        .all()
                    )
                    existing_keys = {row[0] for row in existing_rows}

                for t in candidates:
                    reminder_key = f"{t.id}:{t.executor_id}:{int(t.deadline.timestamp())}:{PUSH_REMINDER_MINUTES}"
                    if reminder_key in existing_keys:
                        continue
                    existing_keys.add(reminder_key)
                    db.add(
                        DeadlineReminderLog(
                            ticket_id=t.id,
                            user_id=t.executor_id,
                            reminder_key=reminder_key,
                        )
                    )
                    send_push_to_user(
                        db=db,
                        user_id=t.executor_id,
                        title=ticket_notification_title("Срок заявки скоро истечет", t.title, ticket_id=t.id),
                        body=f"\u0414\u043e \u0434\u0435\u0434\u043b\u0430\u0439\u043d\u0430 \u043e\u0441\u0442\u0430\u043b\u043e\u0441\u044c {PUSH_REMINDER_MINUTES} \u043c\u0438\u043d\u0443\u0442",
                        url=f"/web/tickets/{t.id}",
                    )
                db.commit()
        except Exception:
            pass
        time.sleep(max(5, PUSH_REMINDER_POLL_SECONDS))


def run_template_autogen_once() -> None:
    with SessionLocal() as db:
        templates_to_run = (
            db.query(TicketTemplate)
            .filter(TicketTemplate.is_active.is_(True), TicketTemplate.scope_unit_id.is_not(None))
            .order_by(TicketTemplate.id.asc())
            .all()
        )
        if not templates_to_run:
            return

        for item in templates_to_run:
            actor_id = resolve_company_actor_id(db, item.company_id)
            if actor_id is None:
                continue
            created_count, _, _ = create_tickets_from_template(
                db=db,
                template=item,
                actor_id=actor_id,
                period_key=month_period_key(),
            )
            if created_count > 0:
                db.commit()
            else:
                db.rollback()


def run_template_autogen_forever() -> None:
    while True:
        try:
            run_template_autogen_once()
        except Exception:
            pass
        time.sleep(TEMPLATE_AUTOGEN_POLL_SECONDS)


def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, ph: str) -> bool:
    return pwd_context.verify(p, ph)

def get_user_auth_token_version(user: User | None) -> int:
    if not user:
        return 0
    return int(getattr(user, "auth_token_version", 0) or 0)


def bump_user_auth_token_version(user: User) -> int:
    next_value = get_user_auth_token_version(user) + 1
    user.auth_token_version = next_value
    return next_value


def create_access_token(subject: str, token_version: int = 0) -> str:
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": subject, "exp": exp, "tv": int(token_version)}, JWT_SECRET, algorithm=ALGORITHM)


class EmailDeliveryError(RuntimeError):
    pass


def is_email_verification_required(user: User | None) -> bool:
    return bool(user and user.role != Role.platform_admin)


def is_user_email_verified(user: User | None) -> bool:
    if not user:
        return False
    if not is_email_verification_required(user):
        return True
    return bool(getattr(user, "email_verified", False))


def ensure_user_can_authenticate(user: User) -> None:
    if not is_user_email_verified(user):
        raise HTTPException(status_code=403, detail="Email address is not verified")


def mark_user_email_verified(user: User) -> None:
    now = datetime.utcnow()
    user.email_verified = True
    user.email_verified_at = now
    user.email_verification_token = None
    user.email_verification_expires_at = None
    user.email_verification_sent_at = None


def prepare_user_email_verification(user: User, *, force_new_token: bool = False) -> str:
    now = datetime.utcnow()
    token_value = (user.email_verification_token or "").strip()
    token_expired = bool(user.email_verification_expires_at and user.email_verification_expires_at <= now)
    if force_new_token or not token_value or token_expired:
        token_value = secrets.token_urlsafe(32)
        user.email_verification_token = token_value
        user.email_verification_expires_at = now + timedelta(hours=EMAIL_VERIFICATION_EXPIRE_HOURS)
    user.email_verified = False
    user.email_verified_at = None
    return token_value


def clear_password_reset_state(user: User) -> None:
    user.password_reset_token = None
    user.password_reset_expires_at = None
    user.password_reset_sent_at = None


def prepare_user_password_reset(user: User, *, force_new_token: bool = False) -> str:
    now = datetime.utcnow()
    token_value = (user.password_reset_token or "").strip()
    token_expired = bool(user.password_reset_expires_at and user.password_reset_expires_at <= now)
    if force_new_token or not token_value or token_expired:
        token_value = secrets.token_urlsafe(32)
        user.password_reset_token = token_value
        user.password_reset_expires_at = now + timedelta(hours=PASSWORD_RESET_EXPIRE_HOURS)
    return token_value


def format_email_sender() -> str:
    sender_email = SMTP_FROM_EMAIL or SMTP_USERNAME or "no-reply@localhost"
    if SMTP_FROM_NAME:
        return f"{SMTP_FROM_NAME} <{sender_email}>"
    return sender_email


def send_email_message(recipient: str, subject: str, text_body: str, html_body: str | None = None) -> bool:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = format_email_sender()
    msg["To"] = recipient
    if html_body:
        msg.set_content(text_body)
        msg.add_alternative(html_body, subtype="html")
    else:
        msg.set_content(text_body)

    if not SMTP_HOST:
        logger.warning("SMTP_HOST is not configured. Email to %s was not sent.", recipient)
        return False

    smtp = None
    try:
        if SMTP_USE_SSL:
            smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SEC)
        else:
            smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SEC)
            if SMTP_USE_TLS:
                smtp.starttls()
        if SMTP_USERNAME:
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(msg)
        return True
    except Exception as exc:
        raise EmailDeliveryError("Could not send email") from exc
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                pass


def build_email_verification_url(request: Request, token: str) -> str:
    return f"{str(request.base_url).rstrip('/')}/web/verify-email?token={quote(token)}"


def build_password_reset_url(request: Request, token: str) -> str:
    return f"{str(request.base_url).rstrip('/')}/web/password-reset/confirm?token={quote(token)}"


def send_user_verification_email(
    request: Request,
    db: Session,
    user: User,
    *,
    force_new_token: bool = False,
) -> str:
    if not is_email_verification_required(user):
        return ""
    token_value = prepare_user_email_verification(user, force_new_token=force_new_token)
    verification_url = build_email_verification_url(request, token_value)
    subject = "Подтвердите email в servora"
    ttl_hours_text = str(EMAIL_VERIFICATION_EXPIRE_HOURS)
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
    sent = send_email_message(user.email, subject, text_body, html_body=html_body)
    if not sent:
        logger.warning("Verification link for %s: %s", user.email, verification_url)
    user.email_verification_sent_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return verification_url


def send_user_password_reset_email(
    request: Request,
    db: Session,
    user: User,
    *,
    force_new_token: bool = False,
) -> str:
    token_value = prepare_user_password_reset(user, force_new_token=force_new_token)
    reset_url = build_password_reset_url(request, token_value)
    ttl_hours_text = str(PASSWORD_RESET_EXPIRE_HOURS)
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
    sent = send_email_message(user.email, subject, text_body, html_body=html_body)
    if not sent:
        logger.warning("Password reset link for %s: %s", user.email, reset_url)
    user.password_reset_sent_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return reset_url


def delete_auth_cookie(response: Response, request: Request) -> None:
    cookie_params = get_auth_cookie_params(request)
    response.delete_cookie(
        "access_token",
        domain=cookie_params.get("domain"),
        path=str(cookie_params.get("path") or "/"),
    )


def get_auth_cookie_params(request: Request) -> dict[str, object]:
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    scheme = forwarded_proto or request.url.scheme

    cookie_domain = None
    if host.endswith(".servora.ru") or host == "servora.ru":
        cookie_domain = ".servora.ru"

    return {
        "httponly": True,
        "samesite": "lax",
        "secure": (scheme == "https"),
        "domain": cookie_domain,
        "path": "/",
        "max_age": ACCESS_TOKEN_COOKIE_MAX_AGE,
        "expires": ACCESS_TOKEN_COOKIE_MAX_AGE,
    }


def get_current_user(request: Request, token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    final_token = (token or "") or (request.cookies.get("access_token") or "")
    if not final_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(final_token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
        token_version = int(payload.get("tv", 0) or 0)
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if token_version != get_user_auth_token_version(user):
        raise HTTPException(status_code=401, detail="Token is no longer valid")
    ensure_user_can_authenticate(user)
    return user

def require_role(*roles: Role):
    def checker(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return checker


def is_admin(user: User) -> bool:
    return user.role == Role.admin


def is_manager(user: User) -> bool:
    return user.role in MANAGER_ROLES


def is_platform_admin(user: User) -> bool:
    return user.role == Role.platform_admin


def ensure_company_user(user: User) -> None:
    if is_platform_admin(user):
        return
    if user.company_id is None:
        raise HTTPException(403, "Company is not assigned")


def get_company_ticket_or_404(db: Session, user: User, ticket_id: int) -> Ticket:
    ensure_company_user(user)
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if ticket.company_id != user.company_id:
        raise HTTPException(403, "Forbidden")
    return ticket


def can_access_receipt(user: User, receipt: Receipt) -> bool:
    if is_platform_admin(user):
        return True
    if is_manager(user):
        return True
    return bool(user.role == Role.executor and receipt.created_by == user.id)


def get_company_receipt_or_404(db: Session, user: User, receipt_id: int) -> Receipt:
    ensure_company_user(user)
    receipt = db.get(Receipt, receipt_id)
    if not receipt:
        raise HTTPException(404, "Receipt not found")
    if receipt.company_id != user.company_id:
        raise HTTPException(403, "Forbidden")
    return receipt


def parse_receipt_date(raw: str | None) -> date | None:
    value = (raw or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_receipt_amount(raw: str | None) -> Decimal | None:
    value = (raw or "").strip().replace(",", ".")
    if not value:
        return None
    try:
        amount = Decimal(value)
    except InvalidOperation:
        return None
    if amount < 0:
        return None
    return amount.quantize(Decimal("0.01"))


def normalize_bk_last4(raw: str | None) -> str | None:
    digits = re.sub(r"\D+", "", (raw or "").strip())
    if not digits:
        return None
    if len(digits) != 4:
        return None
    return digits


def sanitize_export_token(raw: str | None, max_len: int = 40) -> str:
    value = re.sub(r"[^0-9A-Za-z._-]+", "_", (raw or "").strip())
    value = value.strip("._-")
    if not value:
        return "item"
    return value[:max_len]


def sanitize_filename_part(raw: str | None, max_len: int = 80) -> str:
    value = (raw or "").strip()
    value = re.sub(r'[\\/:*?"<>|\r\n\t]+', "_", value)
    value = re.sub(r"\s+", " ", value).strip(" ._-")
    if not value:
        return "Объект"
    return value[:max_len]


def build_receipt_original_name(
    *,
    receipt_date_value: date | None,
    card_name: str | None,
    project_name: str | None,
    source_filename: str | None,
    fallback_card_id: int,
) -> str:
    ext = Path(source_filename or "").suffix.lower()[:10] or ".bin"
    dt_token = (receipt_date_value or datetime.utcnow().date()).isoformat()
    digits = re.sub(r"\D+", "", (card_name or "").strip())
    card_last4 = digits[-4:] if len(digits) >= 4 else f"{int(fallback_card_id):04d}"[-4:]
    project_token = sanitize_filename_part(project_name, max_len=80)
    return f"{dt_token}_БК{card_last4}_{project_token}{ext}"


def build_receipts_query(
    db: Session,
    user: User,
    *,
    status_filter: str | None = None,
    project_id: int | None = None,
    card_id: int | None = None,
    employee_id: int | None = None,
    date_from_value: date | None = None,
    date_to_value: date | None = None,
    q: str | None = None,
):
    query = db.query(Receipt).filter(Receipt.company_id == user.company_id)
    if user.role == Role.executor:
        query = query.filter(Receipt.created_by == user.id)

    if status_filter:
        try:
            query = query.filter(Receipt.status == ReceiptStatus(status_filter))
        except ValueError:
            pass
    if project_id is not None:
        query = query.filter(Receipt.project_id == project_id)
    if card_id is not None:
        query = query.filter(Receipt.card_id == card_id)
    if employee_id is not None:
        query = query.filter(Receipt.created_by == employee_id)
    if date_from_value is not None:
        query = query.filter(cast(Receipt.created_at, Date) >= date_from_value)
    if date_to_value is not None:
        query = query.filter(cast(Receipt.created_at, Date) <= date_to_value)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Receipt.comment.ilike(like),
                Receipt.category.ilike(like),
                Receipt.supplier.ilike(like),
            )
        )

    return query.order_by(Receipt.id.desc())


def resolve_preferred_card_id(cards, bk_last4: str | None) -> int | None:
    digits = normalize_bk_last4(bk_last4)
    if not digits:
        return None
    fallback_match_id: int | None = None
    for card in cards:
        if not getattr(card, "is_active", True):
            continue
        card_name_digits = re.sub(r"\D+", "", str(getattr(card, "name", "")))
        if not card_name_digits:
            continue
        # Primary match: the card name ends with the configured 4 digits.
        if card_name_digits.endswith(digits):
            return int(getattr(card, "id"))
        # Fallback: card name contains these 4 digits somewhere in the number.
        if fallback_match_id is None and digits in card_name_digits:
            fallback_match_id = int(getattr(card, "id"))
    return fallback_match_id


def delete_company_with_data(db: Session, company_id: int) -> None:
    ticket_ids = [row[0] for row in db.query(Ticket.id).filter(Ticket.company_id == company_id).all()]
    receipt_ids = [row[0] for row in db.query(Receipt.id).filter(Receipt.company_id == company_id).all()]
    user_ids = [row[0] for row in db.query(User.id).filter(User.company_id == company_id).all()]

    if ticket_ids:
        attachments = db.query(Attachment).filter(Attachment.ticket_id.in_(ticket_ids)).all()
        for a in attachments:
            delete_stored_file(a.file_path)

        db.query(Comment).filter(Comment.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        db.query(Attachment).filter(Attachment.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        db.query(TicketLog).filter(TicketLog.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        db.query(TicketWatcher).filter(TicketWatcher.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        db.query(DeadlineReminderLog).filter(DeadlineReminderLog.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
    if receipt_ids:
        receipt_files = db.query(ReceiptFile).filter(ReceiptFile.receipt_id.in_(receipt_ids)).all()
        for file_row in receipt_files:
            delete_stored_file(file_row.file_path)
        db.query(ReceiptFile).filter(ReceiptFile.receipt_id.in_(receipt_ids)).delete(synchronize_session=False)
        db.query(Receipt).filter(Receipt.id.in_(receipt_ids)).delete(synchronize_session=False)

    db.query(TicketGenerationKey).filter(TicketGenerationKey.company_id == company_id).delete(synchronize_session=False)
    db.query(UnitAssignment).filter(UnitAssignment.company_id == company_id).delete(synchronize_session=False)
    db.query(TicketTemplate).filter(TicketTemplate.company_id == company_id).delete(synchronize_session=False)
    db.query(Ticket).filter(Ticket.company_id == company_id).delete(synchronize_session=False)
    db.query(TicketType).filter(TicketType.company_id == company_id).delete(synchronize_session=False)
    db.query(OrgUnit).filter(OrgUnit.company_id == company_id).delete(synchronize_session=False)
    db.query(UnitType).filter(UnitType.company_id == company_id).delete(synchronize_session=False)
    db.query(Department).filter(Department.company_id == company_id).delete(synchronize_session=False)
    db.query(PaymentCard).filter(PaymentCard.company_id == company_id).delete(synchronize_session=False)
    db.query(Project).filter(Project.company_id == company_id).delete(synchronize_session=False)
    db.query(RegistrationInvite).filter(RegistrationInvite.company_id == company_id).delete(synchronize_session=False)
    db.query(Notification).filter(Notification.company_id == company_id).delete(synchronize_session=False)
    db.query(ArchiveCleanupLog).filter(ArchiveCleanupLog.company_id == company_id).delete(synchronize_session=False)
    if user_ids:
        db.query(PushSubscription).filter(PushSubscription.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(MobileDevice).filter(MobileDevice.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(DeadlineReminderLog).filter(DeadlineReminderLog.user_id.in_(user_ids)).delete(synchronize_session=False)
    db.query(User).filter(User.company_id == company_id).delete(synchronize_session=False)
    db.query(Company).filter(Company.id == company_id).delete(synchronize_session=False)


def get_active_invite(db: Session, token: str | None) -> RegistrationInvite | None:
    token_value = (token or "").strip()
    if not token_value:
        return None
    invite = db.query(RegistrationInvite).filter(RegistrationInvite.token == token_value).first()
    if not invite:
        return None
    if invite.used_by is not None:
        return None
    if invite.expires_at and invite.expires_at < datetime.utcnow():
        return None
    if invite.company_id is None:
        return None
    return invite

# =========================
# РџСЂРёР»РѕР¶РµРЅРёРµ
# =========================
app = FastAPI(title="Tickets Simple + Web UI")

@app.get("/")
def root(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})

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
    if TEXT_REPAIR_ON_START:
        db = SessionLocal()
        try:
            repair_mojibake_data(db)
        finally:
            db.close()

    platform_email = (os.getenv("PLATFORM_ADMIN_EMAIL", "") or "").strip()
    platform_password = (os.getenv("PLATFORM_ADMIN_PASSWORD", "") or "").strip()
    if platform_email and platform_password:
        db = SessionLocal()
        try:
            existing = db.query(User).filter(User.email == platform_email).first()
            if not existing:
                platform_name = (os.getenv("PLATFORM_ADMIN_NAME", "") or "").strip() or "Platform Admin"
                user = User(
                    email=platform_email,
                    name=platform_name,
                    password_hash=hash_password(platform_password),
                    role=Role.platform_admin,
                    company_id=None,
                    email_verified=True,
                    email_verified_at=datetime.utcnow(),
                    **normalize_capability_flags(Role.platform_admin),
                )
                db.add(user)
                db.commit()
        finally:
            db.close()
    if push_is_configured():
        threading.Thread(target=run_deadline_reminders_forever, daemon=True).start()
    if TEMPLATE_AUTOGEN_ENABLED:
        threading.Thread(target=run_template_autogen_forever, daemon=True).start()
    threading.Thread(target=run_archive_cleanup_forever, daemon=True).start()



@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and request.url.path.startswith("/web"):
        return RedirectResponse(url="/web/login", status_code=HTTP_303_SEE_OTHER)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/manifest.webmanifest")
def pwa_manifest():
    return FileResponse(
        PWA_STATIC_DIR / "manifest.webmanifest",
        media_type="application/manifest+json",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/favicon.ico")
def favicon():
    return FileResponse(
        PWA_STATIC_DIR / "favicon.ico",
        media_type="image/x-icon",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/sw.js")
def service_worker():
    return FileResponse(
        PWA_STATIC_DIR / "sw.js",
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/api/push/public-key")
def push_public_key(user: User = Depends(get_current_user)):
    if not push_is_configured():
        raise HTTPException(503, "Push is not configured")
    return {"publicKey": VAPID_PUBLIC_KEY, "enabled": True, "user_id": user.id}


@app.post("/api/push/subscribe")
def push_subscribe(payload: PushSubscriptionIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    endpoint = (payload.endpoint or "").strip()
    p256dh = (payload.keys.get("p256dh") or "").strip()
    auth = (payload.keys.get("auth") or "").strip()
    if not endpoint or not p256dh or not auth:
        raise HTTPException(400, "Invalid subscription payload")

    existing = db.query(PushSubscription).filter(PushSubscription.endpoint == endpoint).first()
    if existing:
        existing.user_id = user.id
        existing.p256dh = p256dh
        existing.auth = auth
        existing.updated_at = datetime.utcnow()
    else:
        db.add(
            PushSubscription(
                user_id=user.id,
                endpoint=endpoint,
                p256dh=p256dh,
                auth=auth,
            )
        )
    db.commit()
    return {"ok": True}


@app.post("/api/push/unsubscribe")
def push_unsubscribe(payload: PushUnsubscribeIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    endpoint = (payload.endpoint or "").strip()
    if endpoint:
        db.query(PushSubscription).filter(
            PushSubscription.user_id == user.id,
            PushSubscription.endpoint == endpoint,
        ).delete(synchronize_session=False)
        db.commit()
    return {"ok": True}


@app.post("/api/push/test")
def push_test(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    limited_user, _ = hit_rate_limit(f"push-test-user:{user.id}", RL_PUSH_TEST_LIMIT, RL_PUSH_TEST_WINDOW_SEC)
    limited_ip, _ = hit_rate_limit(f"push-test-ip:{get_client_ip(request)}", RL_PUSH_TEST_LIMIT * 2, RL_PUSH_TEST_WINDOW_SEC)
    if limited_user or limited_ip:
        audit_security_event("push_test", request, success=False, user_id=user.id, detail="rate_limited")
        raise HTTPException(status_code=429, detail="Too many push test requests")
    if not push_is_configured():
        audit_security_event("push_test", request, success=False, user_id=user.id, detail="push_not_configured")
        raise HTTPException(503, "Push is not configured")
    report = send_push_to_user_report(
        db=db,
        user_id=user.id,
        title="\u0422\u0435\u0441\u0442 push",
        body=f"\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0443\u0432\u0435\u0434\u043e\u043c\u043b\u0435\u043d\u0438\u0439 \u0434\u043b\u044f {user.name}",
        url="/web",
    )
    db.commit()
    ok_count = sum(1 for r in report if r.get("ok"))
    audit_security_event(
        "push_test",
        request,
        success=True,
        user_id=user.id,
        detail=f"sent={ok_count}/{len(report)}",
    )
    return {"ok": True, "sent": ok_count, "total": len(report), "report": report}



@app.get("/api/push/debug")
def push_debug(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    subs = db.query(PushSubscription).filter(PushSubscription.user_id == user.id).order_by(PushSubscription.updated_at.desc()).all()
    items = []
    for s in subs:
        endpoint = s.endpoint or ""
        masked = endpoint[:42] + ("..." if len(endpoint) > 42 else "")
        items.append(
            {
                "id": s.id,
                "endpoint": masked,
                "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
        )
    return {"user_id": user.id, "count": len(subs), "subscriptions": items}


@app.post("/api/push/reset")
def push_reset(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    deleted = db.query(PushSubscription).filter(PushSubscription.user_id == user.id).delete(synchronize_session=False)
    db.commit()
    return {"ok": True, "deleted": int(deleted)}


@app.post("/api/mobile/devices/register")
def mobile_device_register(
    payload: MobileDeviceRegisterIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    platform = normalize_mobile_platform(payload.platform)
    if not platform:
        raise HTTPException(400, "Unsupported mobile platform")

    token = (payload.token or "").strip()
    device_id = (payload.device_id or "").strip()
    if not token or not device_id:
        raise HTTPException(400, "Device token and device id are required")

    now = datetime.utcnow()
    existing_by_device = (
        db.query(MobileDevice)
        .filter(MobileDevice.platform == platform, MobileDevice.device_id == device_id)
        .first()
    )
    existing_by_token = db.query(MobileDevice).filter(MobileDevice.token == token).first()

    if existing_by_device and existing_by_token and existing_by_device.id != existing_by_token.id:
        db.delete(existing_by_token)
        db.flush()
        existing_by_token = None

    device = existing_by_device or existing_by_token
    if device:
        device.user_id = user.id
        device.platform = platform
        device.device_id = device_id
        device.token = token
        device.app_version = (payload.app_version or "").strip()[:64] or None
        device.device_name = (payload.device_name or "").strip()[:255] or None
        device.last_seen_at = now
        device.updated_at = now
    else:
        db.add(
            MobileDevice(
                user_id=user.id,
                platform=platform,
                device_id=device_id,
                token=token,
                app_version=(payload.app_version or "").strip()[:64] or None,
                device_name=(payload.device_name or "").strip()[:255] or None,
                last_seen_at=now,
            )
        )
    db.commit()
    return {
        "ok": True,
        "platform": platform,
        "device_id": device_id,
        "mobile_push_configured": mobile_push_is_configured(),
    }


@app.post("/api/mobile/devices/unregister")
def mobile_device_unregister(
    payload: MobileDeviceUnregisterIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    platform = normalize_mobile_platform(payload.platform)
    if not platform:
        raise HTTPException(400, "Unsupported mobile platform")

    query = db.query(MobileDevice).filter(
        MobileDevice.user_id == user.id,
        MobileDevice.platform == platform,
    )
    token = (payload.token or "").strip()
    device_id = (payload.device_id or "").strip()
    if device_id:
        query = query.filter(MobileDevice.device_id == device_id)
    elif token:
        query = query.filter(MobileDevice.token == token)
    else:
        raise HTTPException(400, "Device token or device id is required")

    deleted = query.delete(synchronize_session=False)
    db.commit()
    return {"ok": True, "deleted": int(deleted)}


@app.get("/api/mobile/devices/debug")
def mobile_devices_debug(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    devices = (
        db.query(MobileDevice)
        .filter(MobileDevice.user_id == user.id)
        .order_by(MobileDevice.updated_at.desc())
        .all()
    )
    items = []
    for device in devices:
        masked = device.token[:18] + ("..." if len(device.token) > 18 else "")
        items.append(
            {
                "id": device.id,
                "platform": device.platform,
                "device_id": device.device_id,
                "token": masked,
                "app_version": device.app_version,
                "device_name": device.device_name,
                "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
                "updated_at": device.updated_at.isoformat() if device.updated_at else None,
            }
        )
    return {
        "user_id": user.id,
        "count": len(items),
        "mobile_push_configured": mobile_push_is_configured(),
        "devices": items,
    }


@app.post("/api/mobile/push/test")
def mobile_push_test(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    limited_user, _ = hit_rate_limit(f"mobile-push-test-user:{user.id}", RL_PUSH_TEST_LIMIT, RL_PUSH_TEST_WINDOW_SEC)
    limited_ip, _ = hit_rate_limit(f"mobile-push-test-ip:{get_client_ip(request)}", RL_PUSH_TEST_LIMIT * 2, RL_PUSH_TEST_WINDOW_SEC)
    if limited_user or limited_ip:
        audit_security_event("mobile_push_test", request, success=False, user_id=user.id, detail="rate_limited")
        raise HTTPException(status_code=429, detail="Too many mobile push test requests")
    if not mobile_push_is_configured():
        audit_security_event("mobile_push_test", request, success=False, user_id=user.id, detail="mobile_push_not_configured")
        raise HTTPException(503, "Mobile push is not configured")

    report = send_mobile_push_to_user_report(
        db=db,
        user_id=user.id,
        title="Тест мобильного push",
        body=f"Проверка Android-уведомлений для {user.name}",
        url="/web",
    )
    db.commit()
    ok_count = sum(1 for item in report if item.get("ok"))
    audit_security_event(
        "mobile_push_test",
        request,
        success=True,
        user_id=user.id,
        detail=f"sent={ok_count}/{len(report)}",
    )
    return {"ok": True, "sent": ok_count, "total": len(report), "report": report}

# =========================
# AUTH API
# =========================
@app.post("/auth/bootstrap", response_model=BootstrapSetupOut)
def bootstrap_platform_admin(payload: BootstrapSetupIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.role == Role.platform_admin).first():
        raise HTTPException(400, "Bootstrap already done")
    if db.query(User).filter(User.email == payload.admin_email).first():
        raise HTTPException(400, "Admin email already exists")

    company_name = (payload.company_name or "").strip() or "Platform"
    company = db.query(Company).filter(Company.name == company_name).first()
    if not company:
        company = Company(name=company_name)
        db.add(company)
        db.flush()

    u = User(
        email=payload.admin_email,
        name=payload.admin_name,
        password_hash=hash_password(payload.admin_password),
        role=Role.platform_admin,
        company_id=None,
        email_verified=True,
        email_verified_at=datetime.utcnow(),
        **normalize_capability_flags(Role.platform_admin),
    )
    try:
        db.add(u)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(400, "Could not create platform admin")
    db.refresh(u)
    db.refresh(company)
    return BootstrapSetupOut(company=company, admin=u)


@app.post("/auth/register-company", response_model=BootstrapSetupOut)
def register_company_and_owner(payload: BootstrapSetupIn, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    limited, _ = hit_rate_limit(f"register-company:{ip}", RL_REGISTER_LIMIT, RL_REGISTER_WINDOW_SEC)
    if limited:
        audit_security_event("register_company", request, success=False, email=payload.admin_email, detail="rate_limited")
        raise HTTPException(429, "Too many registration attempts")

    company_name = (payload.company_name or "").strip()
    if not company_name:
        audit_security_event("register_company", request, success=False, email=payload.admin_email, detail="missing_company_name")
        raise HTTPException(422, "Company name is required")
    if db.query(Company).filter(Company.name == company_name).first():
        audit_security_event("register_company", request, success=False, email=payload.admin_email, detail="company_exists")
        raise HTTPException(400, "Company already exists")
    if db.query(User).filter(User.email == payload.admin_email).first():
        audit_security_event("register_company", request, success=False, email=payload.admin_email, detail="email_exists")
        raise HTTPException(400, "Email already exists")

    company = Company(name=company_name)
    db.add(company)
    db.flush()

    owner = User(
        email=payload.admin_email,
        name=payload.admin_name,
        password_hash=hash_password(payload.admin_password),
        role=Role.admin,
        company_id=company.id,
        **normalize_capability_flags(Role.admin, is_assignable_executor=True),
    )
    prepare_user_email_verification(owner, force_new_token=True)
    db.add(owner)
    db.commit()
    db.refresh(owner)
    db.refresh(company)
    try:
        send_user_verification_email(request, db, owner)
    except EmailDeliveryError:
        logger.exception("Could not send verification email to %s", owner.email)
    audit_security_event("register_company", request, success=True, email=payload.admin_email, user_id=owner.id)
    return BootstrapSetupOut(company=company, admin=owner)

@app.post("/auth/login", response_model=TokenOut)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    email = (form.username or "").strip()
    limited_ip, _ = hit_rate_limit(f"auth-login-ip:{ip}", RL_LOGIN_LIMIT * 3, RL_LOGIN_WINDOW_SEC)
    limited_user, _ = hit_rate_limit(f"auth-login-user:{ip}:{(email or '').lower()}", RL_LOGIN_LIMIT, RL_LOGIN_WINDOW_SEC)
    if limited_ip or limited_user:
        audit_security_event("auth_login", request, success=False, email=email, detail="rate_limited")
        raise HTTPException(status_code=429, detail="Too many login attempts")
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        audit_security_event("auth_login", request, success=False, email=email, detail="invalid_credentials")
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    try:
        ensure_user_can_authenticate(user)
    except HTTPException:
        audit_security_event("auth_login", request, success=False, email=email, user_id=user.id, detail="email_not_verified")
        raise
    audit_security_event("auth_login", request, success=True, email=email, user_id=user.id)
    return TokenOut(access_token=create_access_token(str(user.id), get_user_auth_token_version(user)))

# =========================
# USERS API
# =========================
@app.get("/users/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user

@app.post("/users", response_model=UserOut)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role(Role.admin)),
):
    ensure_company_user(_admin)
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already exists")
    if payload.role not in (Role.curator, Role.executor):
        raise HTTPException(400, "Only CURATOR or EXECUTOR can be created")
    bk_last4 = normalize_bk_last4(payload.bk_last4)
    if payload.bk_last4 and bk_last4 is None:
        raise HTTPException(422, "bk_last4 must contain exactly 4 digits")
    preferred_card_id = None
    role_label = normalize_role_label(payload.role_label)
    capability_flags = normalize_capability_flags(
        payload.role,
        show_receipts_accounting_mode=payload.show_receipts_accounting_mode,
        is_assignable_executor=payload.is_assignable_executor,
        can_view_all_tickets=payload.can_view_all_tickets,
        can_create_tickets=payload.can_create_tickets,
        can_close_tickets=payload.can_close_tickets,
    )
    u = User(
        email=payload.email,
        name=payload.name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        company_id=_admin.company_id,
        bk_last4=bk_last4,
        preferred_payment_card_id=preferred_card_id,
        role_label=role_label,
        notify_receipt_created=(
            bool(payload.notify_receipt_created)
            if payload.notify_receipt_created is not None
            else True
        ),
        **capability_flags,
    )
    prepare_user_email_verification(u, force_new_token=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    try:
        send_user_verification_email(request, db, u)
    except EmailDeliveryError:
        logger.exception("Could not send verification email to %s", u.email)
    return u

# =========================
# PROJECTS API
# =========================
@app.post("/projects", response_model=ProjectOut)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db), _manager: User = Depends(require_role(Role.admin, Role.curator))):
    ensure_company_user(_manager)
    if db.query(Project).filter(Project.name == payload.name, Project.company_id == _manager.company_id).first():
        raise HTTPException(400, "Project already exists")
    p = Project(name=payload.name, description=payload.description, company_id=_manager.company_id)
    db.add(p); db.commit(); db.refresh(p)
    return p

@app.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db), _u: User = Depends(get_current_user)):
    if is_platform_admin(_u):
        return db.query(Project).order_by(Project.id.desc()).all()
    ensure_company_user(_u)
    return db.query(Project).filter(Project.company_id == _u.company_id).order_by(Project.id.desc()).all()


@app.post("/departments", response_model=DepartmentOut)
def create_department(
    payload: DepartmentCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role(Role.admin)),
):
    ensure_company_user(_admin)
    name = normalize_department_name(payload.name)
    if not name:
        raise HTTPException(422, "Name is required")
    exists = (
        db.query(Department.id)
        .filter(Department.company_id == _admin.company_id, func.lower(Department.name) == name.lower())
        .first()
    )
    if exists:
        raise HTTPException(400, "Department already exists")
    item = Department(
        company_id=_admin.company_id,
        name=name,
        is_active=bool(payload.is_active),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@app.get("/departments", response_model=list[DepartmentOut])
def list_departments(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if is_platform_admin(user):
        return db.query(Department).order_by(Department.id.desc()).all()
    ensure_company_user(user)
    return (
        db.query(Department)
        .filter(Department.company_id == user.company_id)
        .order_by(Department.name.asc(), Department.id.asc())
        .all()
    )


@app.patch("/departments/{department_id}", response_model=DepartmentOut)
def update_department(
    department_id: int,
    patch: DepartmentUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role(Role.admin)),
):
    ensure_company_user(_admin)
    item = db.get(Department, department_id)
    if not item or item.company_id != _admin.company_id:
        raise HTTPException(404, "Department not found")
    incoming = patch.model_dump(exclude_unset=True)
    if "name" in incoming:
        next_name = normalize_department_name(incoming.get("name"))
        if not next_name:
            raise HTTPException(422, "Name is required")
        exists = (
            db.query(Department.id)
            .filter(
                Department.company_id == _admin.company_id,
                func.lower(Department.name) == next_name.lower(),
                Department.id != item.id,
            )
            .first()
        )
        if exists:
            raise HTTPException(400, "Department already exists")
        item.name = next_name
    if "is_active" in incoming:
        item.is_active = bool(incoming.get("is_active"))
    db.commit()
    db.refresh(item)
    return item


@app.delete("/departments/{department_id}")
def delete_department(
    department_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role(Role.admin)),
):
    ensure_company_user(_admin)
    item = db.get(Department, department_id)
    if not item or item.company_id != _admin.company_id:
        raise HTTPException(404, "Department not found")
    in_use = any(
        (
            db.query(TicketType.id).filter(TicketType.department_id == item.id).first() is not None,
            db.query(TicketTemplate.id).filter(TicketTemplate.department_id == item.id).first() is not None,
            db.query(UnitAssignment.id).filter(UnitAssignment.department_id == item.id).first() is not None,
            db.query(Ticket.id).filter(Ticket.department_id == item.id).first() is not None,
        )
    )
    if in_use:
        raise HTTPException(400, "Department is in use")
    db.delete(item)
    db.commit()
    return {"ok": True}

# =========================
# UNIT TYPES API
# =========================
@app.post("/unit-types", response_model=UnitTypeOut)
def create_unit_type(
    payload: UnitTypeCreate,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    name = (payload.name or "").strip()
    code = (payload.code or "").strip() or None
    if not name:
        raise HTTPException(422, "Name is required")
    if (
        db.query(UnitType.id)
        .filter(UnitType.company_id == _manager.company_id, func.lower(UnitType.name) == name.lower())
        .first()
    ):
        raise HTTPException(400, "Unit type already exists")
    if code and (
        db.query(UnitType.id)
        .filter(UnitType.company_id == _manager.company_id, func.lower(UnitType.code) == code.lower())
        .first()
    ):
        raise HTTPException(400, "Unit type code already exists")
    item = UnitType(
        company_id=_manager.company_id,
        name=name,
        code=code,
        is_active=bool(payload.is_active),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@app.get("/unit-types", response_model=list[UnitTypeOut])
def list_unit_types(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if is_platform_admin(user):
        return db.query(UnitType).order_by(UnitType.id.desc()).all()
    ensure_company_user(user)
    return (
        db.query(UnitType)
        .filter(UnitType.company_id == user.company_id)
        .order_by(UnitType.id.desc())
        .all()
    )


@app.patch("/unit-types/{unit_type_id}", response_model=UnitTypeOut)
def update_unit_type(
    unit_type_id: int,
    patch: UnitTypeUpdate,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    item = db.get(UnitType, unit_type_id)
    if not item or item.company_id != _manager.company_id:
        raise HTTPException(404, "Unit type not found")
    incoming = patch.model_dump(exclude_unset=True)
    if "name" in incoming:
        next_name = (incoming.get("name") or "").strip()
        if not next_name:
            raise HTTPException(422, "Name is required")
        exists = (
            db.query(UnitType.id)
            .filter(
                UnitType.company_id == _manager.company_id,
                func.lower(UnitType.name) == next_name.lower(),
                UnitType.id != item.id,
            )
            .first()
        )
        if exists:
            raise HTTPException(400, "Unit type already exists")
        item.name = next_name
    if "code" in incoming:
        next_code = (incoming.get("code") or "").strip() or None
        if next_code:
            exists = (
                db.query(UnitType.id)
                .filter(
                    UnitType.company_id == _manager.company_id,
                    func.lower(UnitType.code) == next_code.lower(),
                    UnitType.id != item.id,
                )
                .first()
            )
            if exists:
                raise HTTPException(400, "Unit type code already exists")
        item.code = next_code
    if "is_active" in incoming:
        item.is_active = bool(incoming.get("is_active"))
    db.commit()
    db.refresh(item)
    return item


@app.delete("/unit-types/{unit_type_id}")
def delete_unit_type(
    unit_type_id: int,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    item = db.get(UnitType, unit_type_id)
    if not item or item.company_id != _manager.company_id:
        raise HTTPException(404, "Unit type not found")
    in_use = db.query(OrgUnit.id).filter(OrgUnit.unit_type_id == item.id).first() is not None
    if in_use:
        raise HTTPException(400, "Unit type is in use")
    db.delete(item)
    db.commit()
    return {"ok": True}


# =========================
# TICKET TYPES API
# =========================
@app.post("/ticket-types", response_model=TicketTypeOut)
def create_ticket_type(
    payload: TicketTypeCreate,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(422, "Name is required")
    exists = (
        db.query(TicketType)
        .filter(TicketType.company_id == _manager.company_id, TicketType.name == name)
        .first()
    )
    if exists:
        raise HTTPException(400, "Ticket type already exists")
    validate_ticket_links(
        db,
        _manager.company_id,
        None,
        None,
        None,
        None,
        None,
        payload.department_id,
    )
    item = TicketType(
        company_id=_manager.company_id,
        name=name,
        description=(payload.description or "").strip() or None,
        department_id=payload.department_id,
        archive_retention_days=normalize_ticket_type_archive_retention_days(payload.archive_retention_days),
        is_active=bool(payload.is_active),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item

@app.get("/ticket-types", response_model=list[TicketTypeOut])
def list_ticket_types(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if is_platform_admin(user):
        return db.query(TicketType).order_by(TicketType.id.desc()).all()
    ensure_company_user(user)
    return (
        db.query(TicketType)
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.id.desc())
        .all()
    )

@app.patch("/ticket-types/{ticket_type_id}", response_model=TicketTypeOut)
def update_ticket_type(
    ticket_type_id: int,
    patch: TicketTypeUpdate,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    item = db.get(TicketType, ticket_type_id)
    if not item or item.company_id != _manager.company_id:
        raise HTTPException(404, "Ticket type not found")

    incoming = patch.model_dump(exclude_unset=True)
    if "name" in incoming:
        next_name = (incoming.get("name") or "").strip()
        if not next_name:
            raise HTTPException(422, "Name is required")
        exists = (
            db.query(TicketType)
            .filter(
                TicketType.company_id == _manager.company_id,
                TicketType.name == next_name,
                TicketType.id != item.id,
            )
            .first()
        )
        if exists:
            raise HTTPException(400, "Ticket type already exists")
        item.name = next_name
    if "description" in incoming:
        item.description = (incoming.get("description") or "").strip() or None
    if "department_id" in incoming:
        validate_ticket_links(
            db,
            _manager.company_id,
            None,
            None,
            None,
            None,
            None,
            incoming.get("department_id"),
        )
        item.department_id = incoming.get("department_id")
    if "is_active" in incoming:
        item.is_active = bool(incoming.get("is_active"))
    if "archive_retention_days" in incoming:
        item.archive_retention_days = normalize_ticket_type_archive_retention_days(incoming.get("archive_retention_days"))
    db.commit()
    db.refresh(item)
    return item

@app.delete("/ticket-types/{ticket_type_id}")
def delete_ticket_type(
    ticket_type_id: int,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    item = db.get(TicketType, ticket_type_id)
    if not item or item.company_id != _manager.company_id:
        raise HTTPException(404, "Ticket type not found")

    has_tickets = db.query(Ticket.id).filter(Ticket.ticket_type_id == item.id).first() is not None
    has_templates = db.query(TicketTemplate.id).filter(TicketTemplate.ticket_type_id == item.id).first() is not None
    if has_tickets or has_templates:
        raise HTTPException(400, "Ticket type is in use")

    db.delete(item)
    db.commit()
    return {"ok": True}


# =========================
# TICKET TEMPLATES API
# =========================
@app.post("/ticket-templates", response_model=TicketTemplateOut)
def create_ticket_template(
    payload: TicketTemplateCreate,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(422, "Name is required")
    validate_template_links(
        db,
        _manager.company_id,
        payload.ticket_type_id,
        payload.department_id,
        payload.default_executor_id,
        payload.scope_unit_id,
    )
    resolved_department_id = resolve_ticket_department_id(
        db,
        company_id=_manager.company_id,
        ticket_type_id=payload.ticket_type_id,
        department_id=payload.department_id,
    )
    exists = (
        db.query(TicketTemplate.id)
        .filter(TicketTemplate.company_id == _manager.company_id, TicketTemplate.name == name)
        .first()
    )
    if exists:
        raise HTTPException(400, "Ticket template already exists")
    item = TicketTemplate(
        company_id=_manager.company_id,
        ticket_type_id=payload.ticket_type_id,
        department_id=resolved_department_id,
        name=name,
        title_template=(payload.title_template or "").strip() or None,
        description_template=(payload.description_template or "").strip() or None,
        default_deadline_rule=(payload.default_deadline_rule or "").strip() or None,
        default_executor_id=payload.default_executor_id,
        scope_unit_id=payload.scope_unit_id,
        is_active=bool(payload.is_active),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@app.get("/ticket-templates", response_model=list[TicketTemplateOut])
def list_ticket_templates(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if is_platform_admin(user):
        return db.query(TicketTemplate).order_by(TicketTemplate.id.desc()).all()
    ensure_company_user(user)
    return (
        db.query(TicketTemplate)
        .filter(TicketTemplate.company_id == user.company_id)
        .order_by(TicketTemplate.id.desc())
        .all()
    )


@app.patch("/ticket-templates/{template_id}", response_model=TicketTemplateOut)
def update_ticket_template(
    template_id: int,
    patch: TicketTemplateUpdate,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    item = db.get(TicketTemplate, template_id)
    if not item or item.company_id != _manager.company_id:
        raise HTTPException(404, "Ticket template not found")
    incoming = patch.model_dump(exclude_unset=True)
    if "name" in incoming:
        next_name = (incoming.get("name") or "").strip()
        if not next_name:
            raise HTTPException(422, "Name is required")
        exists = (
            db.query(TicketTemplate.id)
            .filter(
                TicketTemplate.company_id == _manager.company_id,
                TicketTemplate.name == next_name,
                TicketTemplate.id != item.id,
            )
            .first()
        )
        if exists:
            raise HTTPException(400, "Ticket template already exists")
        item.name = next_name

    next_ticket_type_id = incoming.get("ticket_type_id", item.ticket_type_id)
    next_department_id = incoming.get("department_id", item.department_id)
    next_default_executor_id = incoming.get("default_executor_id", item.default_executor_id)
    next_scope_unit_id = incoming.get("scope_unit_id", item.scope_unit_id)
    validate_template_links(
        db,
        _manager.company_id,
        next_ticket_type_id,
        next_department_id,
        next_default_executor_id,
        next_scope_unit_id,
    )
    resolved_department_id = resolve_ticket_department_id(
        db,
        company_id=_manager.company_id,
        ticket_type_id=next_ticket_type_id,
        department_id=next_department_id,
    )

    if "ticket_type_id" in incoming:
        item.ticket_type_id = incoming.get("ticket_type_id")
    if "department_id" in incoming or "ticket_type_id" in incoming:
        item.department_id = resolved_department_id
    if "title_template" in incoming:
        item.title_template = (incoming.get("title_template") or "").strip() or None
    if "description_template" in incoming:
        item.description_template = (incoming.get("description_template") or "").strip() or None
    if "default_deadline_rule" in incoming:
        item.default_deadline_rule = (incoming.get("default_deadline_rule") or "").strip() or None
    if "default_executor_id" in incoming:
        item.default_executor_id = incoming.get("default_executor_id")
    if "scope_unit_id" in incoming:
        item.scope_unit_id = incoming.get("scope_unit_id")
    if "is_active" in incoming:
        item.is_active = bool(incoming.get("is_active"))
    db.commit()
    db.refresh(item)
    return item


@app.delete("/ticket-templates/{template_id}")
def delete_ticket_template(
    template_id: int,
    db: Session = Depends(get_db),
    _manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(_manager)
    item = db.get(TicketTemplate, template_id)
    if not item or item.company_id != _manager.company_id:
        raise HTTPException(404, "Ticket template not found")
    try:
        db.query(Ticket).filter(
            Ticket.company_id == _manager.company_id,
            Ticket.ticket_template_id == item.id,
        ).update({"ticket_template_id": None}, synchronize_session=False)
        db.query(TicketGenerationKey).filter(
            TicketGenerationKey.company_id == _manager.company_id,
            TicketGenerationKey.ticket_template_id == item.id,
        ).delete(synchronize_session=False)
        db.delete(item)
        db.commit()
        return {"ok": True}
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(400, "Cannot delete ticket template")


@app.post("/ticket-templates/{template_id}/run")
def run_ticket_template(
    template_id: int,
    payload: TicketTemplateRunIn,
    db: Session = Depends(get_db),
    manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(manager)
    item = db.get(TicketTemplate, template_id)
    if not item or item.company_id != manager.company_id:
        raise HTTPException(404, "Ticket template not found")
    normalized_period = normalize_period_key(payload.period_key)
    if payload.period_key and normalized_period is None:
        raise HTTPException(422, "Invalid period_key format, expected YYYY-MM")

    created_count, skipped_count, effective_period = create_tickets_from_template(
        db=db,
        template=item,
        actor_id=manager.id,
        period_key=normalized_period,
    )
    db.commit()
    return {
        "ok": True,
        "created_count": created_count,
        "skipped_count": skipped_count,
        "period_key": effective_period,
    }


@app.post("/ticket-templates/{template_id}/clear-keys")
def clear_ticket_template_keys(
    template_id: int,
    payload: TicketTemplateRunIn,
    db: Session = Depends(get_db),
    manager: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(manager)
    item = db.get(TicketTemplate, template_id)
    if not item or item.company_id != manager.company_id:
        raise HTTPException(404, "Ticket template not found")

    normalized_period = normalize_period_key(payload.period_key) or month_period_key()
    deleted_count = (
        db.query(TicketGenerationKey)
        .filter(
            TicketGenerationKey.company_id == manager.company_id,
            TicketGenerationKey.ticket_template_id == item.id,
            TicketGenerationKey.period_key == normalized_period,
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    return {"ok": True, "period_key": normalized_period, "deleted_count": int(deleted_count or 0)}

# =========================
# TICKETS API
# =========================
@app.post("/tickets", response_model=TicketOut)
def create_ticket(payload: TicketCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if is_platform_admin(user):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)
    if not can_create_company_ticket(user):
        raise HTTPException(403, "Forbidden")
    title = normalize_ticket_title(payload.title)
    if not title:
        raise HTTPException(422, "Title is required")
    if is_ticket_title_too_long(title):
        raise HTTPException(422, f"Title is too long (max {MAX_TICKET_TITLE_LEN})")

    validate_ticket_links(
        db,
        user.company_id,
        payload.project_id,
        payload.executor_id,
        payload.ticket_type_id,
        payload.target_unit_id,
        payload.ticket_template_id,
        payload.department_id,
    )
    resolved_department_id = resolve_ticket_department_id(
        db,
        company_id=user.company_id,
        ticket_type_id=payload.ticket_type_id,
        department_id=payload.department_id,
    )
    t = Ticket(
        title=title,
        description=payload.description,
        deadline=payload.deadline,
        company_id=user.company_id,
        executor_id=payload.executor_id,
        ticket_type_id=payload.ticket_type_id,
        department_id=resolved_department_id,
        target_unit_id=payload.target_unit_id,
        ticket_template_id=payload.ticket_template_id,
        period_key=(payload.period_key or "").strip() or None,
        project_id=payload.project_id,
        created_by=user.id
    )
    try:
        db.add(t)
        db.flush()
        ensure_default_ticket_watchers(db, t)
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=LOG_ACTION_CREATED)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(400, "РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ Р·Р°СЏРІРєСѓ")
    db.refresh(t)
    notify_executor_new_ticket(db, t, user)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
    return t

@app.get("/tickets", response_model=list[TicketOut])
def list_tickets(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(Ticket).order_by(Ticket.id.desc())
    if not is_platform_admin(user):
        ensure_company_user(user)
        q = q.filter(Ticket.company_id == user.company_id)
    if user.role == Role.executor:
        if not getattr(user, "can_view_all_tickets", False):
            q = q.filter((Ticket.executor_id == user.id) | (Ticket.created_by == user.id))
    return q.all()

@app.patch("/tickets/{ticket_id}", response_model=TicketOut)
def update_ticket(ticket_id: int, patch: TicketUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = get_api_ticket_or_404(db, user, ticket_id)
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    incoming = patch.model_dump(exclude_unset=True)
    if incoming.get("status") == TicketStatus.archived:
        raise HTTPException(400, "Use archive endpoint")

    if user.role == Role.executor:
        if not can_access_ticket(user, t):
            raise HTTPException(403, "Forbidden")
        allowed = {"description"}
        if can_close_ticket(user, t):
            allowed.add("status")
        incoming = {k: v for k, v in incoming.items() if k in allowed}

    if "title" in incoming:
        incoming["title"] = normalize_ticket_title(incoming.get("title"))
        if incoming["title"] and is_ticket_title_too_long(incoming["title"]):
            raise HTTPException(422, f"Title is too long (max {MAX_TICKET_TITLE_LEN})")

    validate_ticket_links(
        db,
        t.company_id,
        incoming.get("project_id"),
        incoming.get("executor_id"),
        incoming.get("ticket_type_id"),
        incoming.get("target_unit_id"),
        incoming.get("ticket_template_id"),
        incoming.get("department_id"),
    )

    old_deadline = t.deadline
    old_executor_id = t.executor_id
    old_project_id = t.project_id
    old_ticket_type_id = t.ticket_type_id
    old_department_id = t.department_id
    old_target_unit_id = t.target_unit_id
    old_template_id = t.ticket_template_id
    old_period_key = t.period_key
    old_status = t.status

    for k, v in incoming.items():
        setattr(t, k, v)
    if "ticket_type_id" in incoming or "department_id" in incoming:
        t.department_id = resolve_ticket_department_id(
            db,
            company_id=t.company_id,
            ticket_type_id=t.ticket_type_id,
            department_id=t.department_id,
        )

    has_specific_log = False
    if t.deadline != old_deadline:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u0441\u0440\u043e\u043a\u0430",
                _ticket_deadline_text(old_deadline),
                _ticket_deadline_text(t.deadline),
            ),
        )
        has_specific_log = True
    if t.executor_id != old_executor_id:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u0438\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044f",
                _ticket_user_name(db, old_executor_id),
                _ticket_user_name(db, t.executor_id),
            ),
        )
        has_specific_log = True
    if t.project_id != old_project_id:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u043f\u0440\u043e\u0435\u043a\u0442\u0430",
                _ticket_project_name(db, old_project_id),
                _ticket_project_name(db, t.project_id),
            ),
        )
        has_specific_log = True

    if t.ticket_type_id != old_ticket_type_id:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u0442\u0438\u043f\u0430 \u0437\u0430\u044f\u0432\u043a\u0438",
                _ticket_type_name(db, old_ticket_type_id),
                _ticket_type_name(db, t.ticket_type_id),
            ),
        )
        has_specific_log = True
    if t.department_id != old_department_id:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "отдела",
                _department_name(db, old_department_id),
                _department_name(db, t.department_id),
            ),
        )
        has_specific_log = True
    if t.target_unit_id != old_target_unit_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=LOG_ACTION_TARGET_UNIT_CHANGED)
        has_specific_log = True
    if t.ticket_template_id != old_template_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=LOG_ACTION_TEMPLATE_CHANGED)
        has_specific_log = True
    if t.period_key != old_period_key:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=LOG_ACTION_TEMPLATE_PERIOD_CHANGED)
        has_specific_log = True

    if t.status != old_status:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=ticket_status_change_log_action(old_status, t.status))
        has_specific_log = True

    if not has_specific_log:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=LOG_ACTION_CHANGED)

    ensure_default_ticket_watchers(db, t)
    db.commit(); db.refresh(t)
    notify_executor_reassigned(db, t, old_executor_id=old_executor_id, actor=user)
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()
    return t

@app.post("/tickets/{ticket_id}/comments", response_model=CommentOut)
async def add_comment(ticket_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = get_api_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if not can_close_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    content_type = (request.headers.get("content-type") or "").lower()
    text_value = ""
    photo_uploads: list[UploadFile] = []
    voice_uploads: list[UploadFile] = []
    attachment_uploads: list[UploadFile] = []
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception as exc:
            raise HTTPException(400, "Invalid JSON payload") from exc
        if not isinstance(payload, dict):
            raise HTTPException(400, "Invalid JSON payload")
        text_value = (payload.get("text") or "").strip()
    else:
        form = await request.form()
        text_value = (form.get("text") or "").strip()
        photo_uploads = normalize_optional_uploaded_files(list(form.getlist("photos")))
        voice_uploads = normalize_optional_uploaded_files(list(form.getlist("voice_messages")))
        attachment_uploads = normalize_optional_uploaded_files(list(form.getlist("attachments")))

    comment, media_items, stored_paths = await create_comment_with_media_async(
        db=db,
        ticket_id=ticket_id,
        author_id=user.id,
        text=text_value,
        photos=photo_uploads,
        voice_messages=voice_uploads,
        attachments=attachment_uploads,
    )
    try:
        db.commit()
        db.refresh(comment)
        for item in media_items:
            db.refresh(item)
    except Exception:
        db.rollback()
        for stored_path in stored_paths:
            delete_stored_file(stored_path)
        raise
    try:
        notify_comment_added(
            db,
            ticket=t,
            author=user,
            comment_text=text_value,
            photo_count=sum(1 for item in media_items if item.media_kind == "photo"),
            voice_count=sum(1 for item in media_items if item.media_kind == "voice"),
            file_count=sum(1 for item in media_items if item.media_kind == "file"),
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
    return serialize_comment_out(comment, media_items)

@app.post("/tickets/{ticket_id}/attachments", response_model=list[AttachmentOut])
def upload_attachment(ticket_id: int, files: list[UploadFile] = File(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = get_api_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    saved_attachments: list[Attachment] = []
    for upload in normalize_uploaded_files(files):
        safe_name = make_safe_upload_name(upload.filename, ticket_id=ticket_id)
        object_key = build_attachment_object_key(safe_name)
        stored_path, file_hash, file_size = store_upload_file_to_storage(upload, object_key)
        attachment = create_ticket_attachment_record(
            db=db,
            ticket_id=ticket_id,
            uploader_id=user.id,
            upload=upload,
            stored_path=stored_path,
            file_hash=file_hash,
            file_size=file_size,
        )
        saved_attachments.append(attachment)

    db.commit()
    for attachment in saved_attachments:
        db.refresh(attachment)
    for attachment in saved_attachments:
        notify_curators_executor_act(db, ticket=t, uploader=user, original_name=attachment.original_name)
    db.commit()
    return saved_attachments


@app.get("/attachments/{attachment_id}")
def download_attachment(
    attachment_id: int,
    download: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    a = db.get(Attachment, attachment_id)
    if not a:
        raise HTTPException(404, "Attachment not found")
    t = get_api_ticket_or_404(db, user, a.ticket_id)
    display_name = ((a.original_name or "").strip() or get_storage_basename(a.file_path) or "file")[:255]
    disposition = "attachment" if str(download or "").strip() == "1" else "inline"
    return serve_stored_file_response(a.file_path, display_name, disposition, "Attachment file not found")


@app.get("/comment-media/{media_id}")
def download_comment_media(
    media_id: int,
    download: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    item = db.get(CommentMedia, media_id)
    if not item:
        raise HTTPException(404, "Comment media not found")
    comment = db.get(Comment, item.comment_id)
    if not comment:
        raise HTTPException(404, "Comment not found")
    _ = get_api_ticket_or_404(db, user, comment.ticket_id)
    display_name = ((item.original_name or "").strip() or get_storage_basename(item.file_path) or "file")[:255]
    disposition = "attachment" if str(download or "").strip() == "1" else "inline"
    return serve_stored_file_response(item.file_path, display_name, disposition, "Comment media file not found")

# =========================
# WEB UI
# =========================
@app.get("/web/login")
def web_login_page(request: Request):
    info = (request.query_params.get("info") or "").strip().lower()
    info_message = None
    if info == "logged_out_all":
        info_message = "Сессии на всех устройствах завершены. Войдите снова."
    elif info == "password_changed":
        info_message = "Пароль изменён. Войдите с новым паролем."
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "info": info_message})

@app.post("/web/login")
async def web_login(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = (form.get("email") or "").strip()
    password = form.get("password")
    ip = get_client_ip(request)

    limited_ip, _ = hit_rate_limit(f"web-login-ip:{ip}", RL_LOGIN_LIMIT * 3, RL_LOGIN_WINDOW_SEC)
    limited_user, _ = hit_rate_limit(f"web-login-user:{ip}:{email.lower()}", RL_LOGIN_LIMIT, RL_LOGIN_WINDOW_SEC)
    if limited_ip or limited_user:
        audit_security_event("web_login", request, success=False, email=email, detail="rate_limited")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "\u0421\u043b\u0438\u0448\u043a\u043e\u043c \u043c\u043d\u043e\u0433\u043e \u043f\u043e\u043f\u044b\u0442\u043e\u043a \u0432\u0445\u043e\u0434\u0430. \u041f\u043e\u043f\u0440\u043e\u0431\u0443\u0439\u0442\u0435 \u043f\u043e\u0437\u0436\u0435.", "info": None},
            status_code=429,
        )

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        audit_security_event("web_login", request, success=False, email=email, detail="invalid_credentials")
        return templates.TemplateResponse("login.html", {"request": request, "error": "\u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 email \u0438\u043b\u0438 \u043f\u0430\u0440\u043e\u043b\u044c", "info": None})
    if not is_user_email_verified(user):
        audit_security_event("web_login", request, success=False, email=email, user_id=user.id, detail="email_not_verified")
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Подтвердите email по ссылке из письма, затем повторите вход.",
                "info": None,
            },
            status_code=403,
        )

    token = create_access_token(str(user.id), get_user_auth_token_version(user))
    resp = RedirectResponse(url="/web", status_code=HTTP_303_SEE_OTHER)

    resp.set_cookie(
        "access_token",
        token,
        **get_auth_cookie_params(request),
    )
    audit_security_event("web_login", request, success=True, email=email, user_id=user.id)
    return resp


@app.get("/web/register-company")
def web_register_company_page(request: Request):
    return templates.TemplateResponse(
        "register_company.html",
        {"request": request, "error": None, "success": False},
    )


@app.post("/web/register-company")
async def web_register_company_submit(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    company_name = (form.get("company_name") or "").strip()
    admin_name = (form.get("admin_name") or "").strip()
    admin_email = (form.get("admin_email") or "").strip()
    admin_password = (form.get("admin_password") or "").strip()

    try:
        payload = BootstrapSetupIn(
            company_name=company_name,
            admin_name=admin_name,
            admin_email=admin_email,
            admin_password=admin_password,
        )
        _ = register_company_and_owner(payload=payload, request=request, db=db)
        return templates.TemplateResponse(
            "register_company.html",
            {"request": request, "error": None, "success": True},
        )
    except HTTPException as exc:
        return templates.TemplateResponse(
            "register_company.html",
            {"request": request, "error": str(exc.detail), "success": False},
        )
    except Exception:
        audit_security_event("register_company", request, success=False, email=admin_email, detail="validation_error")
        return templates.TemplateResponse(
            "register_company.html",
            {"request": request, "error": "РџСЂРѕРІРµСЂСЊС‚Рµ РІРІРµРґРµРЅРЅС‹Рµ РґР°РЅРЅС‹Рµ", "success": False},
        )


@app.get("/web/register")
def web_register_page(request: Request, token: str | None = None, db: Session = Depends(get_db)):
    invite = get_active_invite(db, token)
    role_value = invite.role.value if invite else ""
    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "token": (token or "").strip(),
            "role_value": role_value,
            "error": None,
            "success": False,
        },
    )


@app.post("/web/register")
async def web_register_submit(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    token = (form.get("token") or "").strip()
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip()
    password = (form.get("password") or "").strip()
    ip = get_client_ip(request)
    limited, _ = hit_rate_limit(f"web-register:{ip}", RL_REGISTER_LIMIT * 2, RL_REGISTER_WINDOW_SEC)
    if limited:
        audit_security_event("web_register", request, success=False, email=email, detail="rate_limited")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "token": token, "role_value": "", "error": "РЎР»РёС€РєРѕРј РјРЅРѕРіРѕ РїРѕРїС‹С‚РѕРє. РџРѕРїСЂРѕР±СѓР№С‚Рµ РїРѕР·Р¶Рµ.", "success": False},
            status_code=429,
        )

    invite = get_active_invite(db, token)
    role_value = invite.role.value if invite else ""

    if not invite:
        audit_security_event("web_register", request, success=False, email=email, detail="invalid_invite")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "token": token, "role_value": role_value, "error": "РЎСЃС‹Р»РєР° РЅРµРґРµР№СЃС‚РІРёС‚РµР»СЊРЅР°", "success": False},
        )
    if not (name and email and password):
        audit_security_event("web_register", request, success=False, email=email, detail="missing_fields")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "token": token, "role_value": role_value, "error": "Р—Р°РїРѕР»РЅРёС‚Рµ РІСЃРµ РїРѕР»СЏ", "success": False},
        )
    if db.query(User).filter(User.email == email).first():
        audit_security_event("web_register", request, success=False, email=email, detail="email_exists")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "token": token, "role_value": role_value, "error": "Email СѓР¶Рµ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ", "success": False},
        )

    try:
        user = User(
            email=email,
            name=name,
            password_hash=hash_password(password),
            role=invite.role,
            company_id=invite.company_id,
            **normalize_capability_flags(invite.role),
        )
        prepare_user_email_verification(user, force_new_token=True)
        db.add(user)
        db.flush()

        invite.used_by = user.id
        invite.used_at = datetime.utcnow()
        db.commit()
    except SQLAlchemyError:
        audit_security_event("web_register", request, success=False, email=email, detail="db_error")
        db.rollback()
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "token": token, "role_value": role_value, "error": "РќРµ СѓРґР°Р»РѕСЃСЊ Р·Р°РІРµСЂС€РёС‚СЊ СЂРµРіРёСЃС‚СЂР°С†РёСЋ", "success": False},
        )
    try:
        send_user_verification_email(request, db, user)
    except EmailDeliveryError:
        logger.exception("Could not send verification email to %s", user.email)

    audit_security_event("web_register", request, success=True, email=email, user_id=user.id)
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "token": "", "role_value": invite.role.value, "error": None, "success": True},
    )


@app.get("/web/verify-email")
def web_verify_email_page(request: Request, token: str | None = None, db: Session = Depends(get_db)):
    token_value = (token or "").strip()
    user = None
    if token_value:
        user = db.query(User).filter(User.email_verification_token == token_value).first()

    if not user:
        return templates.TemplateResponse(
            "verify_email.html",
            {"request": request, "success": False, "error": "Ссылка подтверждения недействительна или уже использована."},
            status_code=400,
        )
    if user.email_verification_expires_at and user.email_verification_expires_at <= datetime.utcnow():
        return templates.TemplateResponse(
            "verify_email.html",
            {"request": request, "success": False, "error": "Срок действия ссылки истёк. Запросите новое письмо."},
            status_code=400,
        )

    mark_user_email_verified(user)
    db.commit()
    audit_security_event("email_verify", request, success=True, email=user.email, user_id=user.id)
    return templates.TemplateResponse(
        "verify_email.html",
        {"request": request, "success": True, "error": None},
    )


@app.get("/web/verify-email/resend")
def web_resend_verification_page(request: Request):
    return templates.TemplateResponse(
        "verify_email_resend.html",
        {"request": request, "success": False, "message": None},
    )


@app.post("/web/verify-email/resend")
async def web_resend_verification_submit(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = (form.get("email") or "").strip()
    ip = get_client_ip(request)
    limited_ip, _ = hit_rate_limit(
        f"email-verify-resend-ip:{ip}",
        RL_EMAIL_VERIFICATION_LIMIT * 2,
        RL_EMAIL_VERIFICATION_WINDOW_SEC,
    )
    limited_email, _ = hit_rate_limit(
        f"email-verify-resend-email:{(email or '').lower()}",
        RL_EMAIL_VERIFICATION_LIMIT,
        RL_EMAIL_VERIFICATION_WINDOW_SEC,
    )
    if not limited_ip and not limited_email and email:
        user = db.query(User).filter(User.email == email).first()
        if user and not is_user_email_verified(user):
            try:
                send_user_verification_email(request, db, user, force_new_token=True)
                audit_security_event("email_verify_resend", request, success=True, email=email, user_id=user.id)
            except EmailDeliveryError:
                logger.exception("Could not resend verification email to %s", user.email)
        else:
            audit_security_event("email_verify_resend", request, success=True, email=email, detail="ignored")
    else:
        audit_security_event("email_verify_resend", request, success=False, email=email, detail="rate_limited")
    return templates.TemplateResponse(
        "verify_email_resend.html",
        {
            "request": request,
            "success": True,
            "message": "Если аккаунт существует и ещё не подтверждён, мы отправили новое письмо.",
        },
    )


@app.get("/web/password-reset")
def web_password_reset_page(request: Request):
    return templates.TemplateResponse(
        "password_reset_request.html",
        {"request": request, "success": False, "message": None},
    )


@app.post("/web/password-reset")
async def web_password_reset_submit(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = (form.get("email") or "").strip()
    ip = get_client_ip(request)
    limited_ip, _ = hit_rate_limit(
        f"password-reset-ip:{ip}",
        RL_PASSWORD_RESET_LIMIT * 2,
        RL_PASSWORD_RESET_WINDOW_SEC,
    )
    limited_email, _ = hit_rate_limit(
        f"password-reset-email:{(email or '').lower()}",
        RL_PASSWORD_RESET_LIMIT,
        RL_PASSWORD_RESET_WINDOW_SEC,
    )
    if not limited_ip and not limited_email and email:
        user = db.query(User).filter(User.email == email).first()
        if user:
            try:
                send_user_password_reset_email(request, db, user, force_new_token=True)
                audit_security_event("password_reset_request", request, success=True, email=email, user_id=user.id)
            except EmailDeliveryError:
                logger.exception("Could not send password reset email to %s", user.email)
        else:
            audit_security_event("password_reset_request", request, success=True, email=email, detail="ignored")
    else:
        audit_security_event("password_reset_request", request, success=False, email=email, detail="rate_limited")
    return templates.TemplateResponse(
        "password_reset_request.html",
        {
            "request": request,
            "success": True,
            "message": "Если аккаунт существует, мы отправили письмо со ссылкой для сброса пароля.",
        },
    )


@app.get("/web/password-reset/confirm")
def web_password_reset_confirm_page(request: Request, token: str | None = None, db: Session = Depends(get_db)):
    token_value = (token or "").strip()
    user = None
    if token_value:
        user = db.query(User).filter(User.password_reset_token == token_value).first()
    if not user:
        return templates.TemplateResponse(
            "password_reset_confirm.html",
            {"request": request, "token": "", "success": False, "error": "Ссылка сброса пароля недействительна или уже использована."},
            status_code=400,
        )
    if user.password_reset_expires_at and user.password_reset_expires_at <= datetime.utcnow():
        return templates.TemplateResponse(
            "password_reset_confirm.html",
            {"request": request, "token": "", "success": False, "error": "Срок действия ссылки истёк. Запросите новое письмо."},
            status_code=400,
        )
    return templates.TemplateResponse(
        "password_reset_confirm.html",
        {"request": request, "token": token_value, "success": False, "error": None},
    )


@app.post("/web/password-reset/confirm")
async def web_password_reset_confirm_submit(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    token_value = (form.get("token") or "").strip()
    password = (form.get("password") or "").strip()
    password_confirm = (form.get("password_confirm") or "").strip()
    user = None
    if token_value:
        user = db.query(User).filter(User.password_reset_token == token_value).first()
    if not user:
        return templates.TemplateResponse(
            "password_reset_confirm.html",
            {"request": request, "token": "", "success": False, "error": "Ссылка сброса пароля недействительна или уже использована."},
            status_code=400,
        )
    if user.password_reset_expires_at and user.password_reset_expires_at <= datetime.utcnow():
        return templates.TemplateResponse(
            "password_reset_confirm.html",
            {"request": request, "token": "", "success": False, "error": "Срок действия ссылки истёк. Запросите новое письмо."},
            status_code=400,
        )
    if not password:
        return templates.TemplateResponse(
            "password_reset_confirm.html",
            {"request": request, "token": token_value, "success": False, "error": "Введите новый пароль."},
            status_code=400,
        )
    if len(password) < 8:
        return templates.TemplateResponse(
            "password_reset_confirm.html",
            {"request": request, "token": token_value, "success": False, "error": "Пароль должен быть не короче 8 символов."},
            status_code=400,
        )
    if password != password_confirm:
        return templates.TemplateResponse(
            "password_reset_confirm.html",
            {"request": request, "token": token_value, "success": False, "error": "Пароли не совпадают."},
            status_code=400,
        )
    user.password_hash = hash_password(password)
    bump_user_auth_token_version(user)
    clear_password_reset_state(user)
    db.commit()
    audit_security_event("password_reset_confirm", request, success=True, email=user.email, user_id=user.id)
    return templates.TemplateResponse(
        "password_reset_confirm.html",
        {"request": request, "token": "", "success": True, "error": None},
    )

@app.get("/web/logout")
def web_logout(request: Request):
    resp = RedirectResponse(url="/web/login", status_code=HTTP_303_SEE_OTHER)
    delete_auth_cookie(resp, request)
    return resp

def _render_web_tickets_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = None,
    project_id: str | None = None,
    ticket_type_id: str | None = None,
    department_id: str | None = None,
    executor_id: str | None = None,   # <-- Р”РћР‘РђР’РР›Р
    target_unit_id: str | None = None,
    unit_executor_id: str | None = None,
    q: str | None = None,
    only_overdue: str | None = None,
    sort: str | None = None,
    view_mode: str | None = None,
    open_create: str | None = None,
    create_error: str | None = None,
    page: int = 1,
    page_size: str | None = None,
    archive_mode: bool = False,
):
    if is_platform_admin(user):
        return RedirectResponse(url="/web/admin/companies", status_code=HTTP_303_SEE_OTHER)
    ensure_company_user(user)
    company = db.get(Company, user.company_id) if user.company_id is not None else None
    deadline_soon_warning_minutes = get_company_deadline_soon_warning_minutes(company)
    list_path = "/web/archive" if archive_mode else "/web"
    page_title = "Архив заявок" if archive_mode else "Заявки"
    empty_text = "В архиве пока нет заявок." if archive_mode else "Заявок пока нет."
    status_filter_options = ["ARCHIVED"] if archive_mode else ["NEW", "IN_PROGRESS", "DONE", "CANCELED"]
    create_enabled = (not archive_mode) and can_create_company_ticket(user)
    view_mode_storage_key = "tickets_view_mode_archive" if archive_mode else "tickets_view_mode"
    # 1) tickets СЃ СѓС‡РµС‚РѕРј СЂРѕР»Рё
    base_query = db.query(Ticket).filter(Ticket.company_id == user.company_id)
    if user.role == Role.executor and not getattr(user, "can_view_all_tickets", False):
        base_query = base_query.filter(or_(Ticket.executor_id == user.id, Ticket.created_by == user.id))
    if archive_mode:
        base_query = base_query.filter(Ticket.status == TicketStatus.archived)
    else:
        base_query = base_query.filter(Ticket.status != TicketStatus.archived)

    # 2) РґР°РЅРЅС‹Рµ РґР»СЏ UI
    projects = (
        db.query(Project.id, Project.name)
        .filter(Project.company_id == user.company_id)
        .order_by(Project.id.desc())
        .all()
    )
    users = (
        db.query(User.id, User.name, User.email)
        .filter(
            User.company_id == user.company_id,
            User.role.in_([Role.admin, Role.curator, Role.executor]),
            User.role != Role.platform_admin,
        )
        .order_by(User.id.desc())
        .all()
    )
    executors = (
        query_assignable_company_users(db, user.company_id)
        .order_by(User.id.desc())
        .all()
    )
    ticket_types = (
        db.query(TicketType.id, TicketType.name, TicketType.is_active, TicketType.department_id)
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.id.desc())
        .all()
    )
    departments = (
        db.query(Department.id, Department.name, Department.is_active)
        .filter(Department.company_id == user.company_id)
        .order_by(Department.name.asc(), Department.id.asc())
        .all()
    )
    org_unit_rows = (
        db.query(OrgUnit.id, OrgUnit.name, OrgUnit.parent_id)
        .filter(OrgUnit.company_id == user.company_id, OrgUnit.is_active.is_(True))
        .order_by(OrgUnit.id.asc())
        .all()
    )
    by_parent: dict[int | None, list[tuple[int, str]]] = {}
    for unit_id, unit_name, parent_id in org_unit_rows:
        by_parent.setdefault(parent_id, []).append((int(unit_id), str(unit_name or "").strip()))
    for siblings in by_parent.values():
        siblings.sort(key=lambda x: (x[1].lower(), x[0]))

    org_units: list[dict[str, int | str]] = []
    stack: list[tuple[int, str, int, list[bool], bool]] = []
    roots = by_parent.get(None, [])
    for idx in range(len(roots) - 1, -1, -1):
        root_id, root_name = roots[idx]
        stack.append((root_id, root_name, 0, [], idx == len(roots) - 1))
    while stack:
        current_id, current_name, depth, ancestor_has_next, is_last = stack.pop()
        if depth > 0:
            tree_name = f"{'- ' * depth}{current_name}"
            short_name = f"{'- ' * depth}{current_name}"
        else:
            tree_name = current_name
            short_name = current_name
        org_units.append(
            {
                "id": current_id,
                "name": tree_name,
                "tree_name": tree_name,
                "short_name": short_name,
            }
        )
        children = by_parent.get(current_id, [])
        if depth == 0:
            child_ancestor_has_next: list[bool] = []
        else:
            child_ancestor_has_next = ancestor_has_next + [not is_last]
        for idx in range(len(children) - 1, -1, -1):
            child_id, child_name = children[idx]
            child_is_last = (idx == len(children) - 1)
            stack.append((child_id, child_name, depth + 1, child_ancestor_has_next, child_is_last))

    users_by_id = {u.id: f"{u.name}" for u in users}
    projects_by_id = {p.id: p.name for p in projects}
    ticket_types_by_id = {tt.id: tt.name for tt in ticket_types}
    departments_by_id = {d.id: d.name for d in departments}

    # 3) С„РёР»СЊС‚СЂС‹
    project_id_int: int | None = None
    if project_id is not None and str(project_id).strip() != "":
        try:
            project_id_int = int(project_id)
        except ValueError:
            project_id_int = None

    ticket_type_id_int: int | None = None
    if ticket_type_id is not None and str(ticket_type_id).strip() != "":
        try:
            ticket_type_id_int = int(ticket_type_id)
        except ValueError:
            ticket_type_id_int = None

    department_id_int: int | None = None
    if department_id is not None and str(department_id).strip() != "":
        try:
            department_id_int = int(department_id)
        except ValueError:
            department_id_int = None

    target_unit_id_int: int | None = None
    if target_unit_id is not None and str(target_unit_id).strip() != "":
        try:
            target_unit_id_int = int(target_unit_id)
        except ValueError:
            target_unit_id_int = None

    unit_executor_id_int: int | None = None
    if unit_executor_id is not None and str(unit_executor_id).strip() != "":
        try:
            unit_executor_id_int = int(unit_executor_id)
        except ValueError:
            unit_executor_id_int = None

    executor_id_int: int | None = None
    executor_none = False
    if executor_id is not None and str(executor_id).strip() != "":
        if str(executor_id).strip() == "__none__":
            executor_none = True
        else:
            try:
                executor_id_int = int(executor_id)
            except ValueError:
                executor_id_int = None

    filtered_query = base_query
    if status_filter:
        try:
            status_enum = TicketStatus(status_filter)
            if archive_mode and status_enum != TicketStatus.archived:
                filtered_query = filtered_query.filter(Ticket.id == -1)
            else:
                filtered_query = filtered_query.filter(Ticket.status == status_enum)
        except ValueError:
            filtered_query = filtered_query.filter(Ticket.id == -1)

    if project_id_int is not None:
        filtered_query = filtered_query.filter(Ticket.project_id == project_id_int)
    if ticket_type_id_int is not None:
        filtered_query = filtered_query.filter(Ticket.ticket_type_id == ticket_type_id_int)
    if department_id_int is not None:
        filtered_query = filtered_query.filter(Ticket.department_id == department_id_int)
    if target_unit_id_int is not None:
        subtree_unit_ids = resolve_scope_descendant_units(db, user.company_id, target_unit_id_int)
        if subtree_unit_ids:
            filtered_query = filtered_query.filter(Ticket.target_unit_id.in_(subtree_unit_ids))
        else:
            filtered_query = filtered_query.filter(Ticket.id == -1)
    if unit_executor_id_int is not None:
        assignment_query = (
            db.query(UnitAssignment.unit_id)
            .filter(
                UnitAssignment.company_id == user.company_id,
                UnitAssignment.user_id == unit_executor_id_int,
                UnitAssignment.role_code == "EXECUTOR",
            )
        )
        if department_id_int is not None:
            assignment_query = assignment_query.filter(UnitAssignment.department_id == department_id_int)
        assigned_unit_ids = [int(row[0]) for row in assignment_query.all()]
        if assigned_unit_ids:
            filtered_query = filtered_query.filter(Ticket.target_unit_id.in_(assigned_unit_ids))
        else:
            filtered_query = filtered_query.filter(Ticket.id == -1)

    # Р¤РёР»СЊС‚СЂ РїРѕ РёСЃРїРѕР»РЅРёС‚РµР»СЋ вЂ” С‚РѕР»СЊРєРѕ РєСѓСЂР°С‚РѕСЂ
    if is_manager(user):
        if executor_none:
            filtered_query = filtered_query.filter(Ticket.executor_id.is_(None))
        elif executor_id_int is not None:
            filtered_query = filtered_query.filter(Ticket.executor_id == executor_id_int)

    if q:
        q_value = q.strip()
        if q_value:
            pattern = f"%{q_value}%"
            filtered_query = filtered_query.filter(
                or_(
                    Ticket.title.ilike(pattern),
                    Ticket.description.ilike(pattern),
                    cast(Ticket.id, String).ilike(pattern),
                )
            )

    now = local_now()
    now_plus_deadline_warning = now + timedelta(minutes=deadline_soon_warning_minutes)

        # С‚РѕР»СЊРєРѕ РїСЂРѕСЃСЂРѕС‡РµРЅРЅС‹Рµ
    overdue_enabled = (only_overdue == "1")
    if archive_mode:
        overdue_enabled = False
    if overdue_enabled:
        filtered_query = filtered_query.filter(
            Ticket.deadline.is_not(None),
            Ticket.deadline < now,
            Ticket.status.notin_(list(FINAL_TICKET_STATUSES)),
        )

        # СЃРѕСЂС‚РёСЂРѕРІРєР°
    sort_value = (sort or "").strip() or "id_desc"
    raw_view_mode = (view_mode or "").strip().lower()
    can_switch_view_mode = user.role in (Role.admin, Role.curator, Role.executor)
    if can_switch_view_mode:
        if user.role == Role.executor:
            view_mode_value = "table" if raw_view_mode == "table" else "cards"
        else:
            view_mode_value = "cards" if raw_view_mode == "cards" else "table"
    else:
        view_mode_value = "cards"

    total_count = filtered_query.count()
    legal_hold_count = filtered_query.filter(Ticket.is_legal_hold.is_(True)).count()

    counts_by_status = {"NEW": 0, "IN_PROGRESS": 0, "DONE": 0, "CANCELED": 0, "ARCHIVED": 0}
    status_counts = (
        filtered_query.with_entities(Ticket.status, func.count(Ticket.id))
        .group_by(Ticket.status)
        .all()
    )
    for status_value, count_value in status_counts:
        status_code = status_value.value if isinstance(status_value, TicketStatus) else str(status_value)
        if status_code in counts_by_status:
            counts_by_status[status_code] = int(count_value)

    overdue_count = (
        filtered_query.filter(
            Ticket.deadline.is_not(None),
            Ticket.deadline < now,
            Ticket.status.notin_(list(FINAL_TICKET_STATUSES)),
        ).count()
    )

    tickets_query = filtered_query
    if sort_value == "deadline_asc":
        tickets_query = tickets_query.order_by(
            Ticket.deadline.is_(None).asc(),
            Ticket.deadline.asc(),
            Ticket.id.desc(),
        )
    elif sort_value == "deadline_desc":
        tickets_query = tickets_query.order_by(
            Ticket.deadline.is_(None).desc(),
            Ticket.deadline.desc(),
            Ticket.id.desc(),
        )
    elif sort_value == "status":
        tickets_query = tickets_query.order_by(
            Ticket.status.asc(),
            Ticket.deadline.is_(None).desc(),
            Ticket.deadline.desc(),
            Ticket.id.desc(),
        )
    elif sort_value == "id_asc":
        tickets_query = tickets_query.order_by(Ticket.id.asc())
    else:  # id_desc
        tickets_query = tickets_query.order_by(Ticket.id.desc())

    status_labels = {
        "NEW": "\u041d\u043e\u0432\u0430\u044f",
        "IN_PROGRESS": "\u0412 \u0440\u0430\u0431\u043e\u0442\u0435",
        "DONE": "\u0412\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0430",
        "CANCELED": "\u041e\u0442\u043c\u0435\u043d\u0435\u043d\u0430",
        "ARCHIVED": "\u0412 \u0430\u0440\u0445\u0438\u0432\u0435",
    }

    # Р”Р°С€Р±РѕСЂРґ РїРѕ С‚РµРєСѓС‰РµРјСѓ СЃРїРёСЃРєСѓ tickets (РїРѕСЃР»Рµ С„РёР»СЊС‚СЂРѕРІ)
    filters_form_open = bool(
        (status_filter or "").strip()
        or project_id_int is not None
        or ticket_type_id_int is not None
        or department_id_int is not None
        or target_unit_id_int is not None
        or unit_executor_id_int is not None
        or (executor_id or "").strip()
        or (q or "").strip()
        or overdue_enabled
        or sort_value != "id_desc"
    )
    create_form_open = create_enabled and (open_create == "1")
    create_error_value = (create_error or "") if create_enabled else ""
    bulk_action_value = (request.query_params.get("bulk_action") or "").strip().lower()
    if bulk_action_value not in TICKET_BULK_ACTION_LABELS:
        bulk_action_value = ""
    bulk_error_value = (request.query_params.get("bulk_error") or "").strip().lower()
    if bulk_error_value not in {"no_selection", "bad_action", "save_failed"}:
        bulk_error_value = ""

    def parse_non_negative_int(raw: str | None) -> int:
        try:
            parsed = int((raw or "").strip())
        except (TypeError, ValueError):
            return 0
        return max(0, parsed)

    bulk_done_count = parse_non_negative_int(request.query_params.get("bulk_done"))
    bulk_skipped_count = parse_non_negative_int(request.query_params.get("bulk_skipped"))
    bulk_notice = ""
    bulk_notice_level = "success"
    if (request.query_params.get("bulk_ok") or "").strip() == "1" and bulk_action_value:
        bulk_notice = (
            f"Массовое действие «{TICKET_BULK_ACTION_LABELS[bulk_action_value]}»: "
            f"выполнено {bulk_done_count}"
        )
        if bulk_skipped_count:
            bulk_notice += f", пропущено {bulk_skipped_count}"
            bulk_notice_level = "warning" if bulk_done_count else "danger"
    elif bulk_error_value == "no_selection":
        bulk_notice = "Выберите хотя бы одну заявку."
        bulk_notice_level = "warning"
    elif bulk_error_value == "bad_action":
        bulk_notice = "Выберите корректное действие для отмеченных заявок."
        bulk_notice_level = "warning"
    elif bulk_error_value == "save_failed":
        bulk_notice = "Не удалось выполнить массовое действие. Попробуйте еще раз."
        bulk_notice_level = "danger"

    if archive_mode:
        bulk_actions = []
        if is_manager(user):
            bulk_actions = [
                {"id": "restore", "label": "Восстановить"},
                {"id": "legal_hold_on", "label": "Включить Legal hold"},
                {"id": "legal_hold_off", "label": "Снять Legal hold"},
                {"id": "delete", "label": "Удалить навсегда"},
            ]
    else:
        bulk_actions = [
            {"id": "archive", "label": "В архив"},
            {"id": "delete", "label": "Удалить"},
        ]
    page_size_options = (10, 20, 30, 50, 100)
    page_size_raw = (page_size or "").strip() if page_size is not None else ""
    if not page_size_raw:
        page_size_raw = (request.cookies.get("tickets_page_size") or "").strip()
    try:
        per_page = int(page_size_raw) if page_size_raw else 10
    except ValueError:
        per_page = 10
    if per_page not in page_size_options:
        per_page = 10
    reset_filters_url = list_path
    if can_switch_view_mode:
        reset_filters_url = f"{list_path}?view_mode={view_mode_value}&page_size={per_page}"
    current_list_url = request.url.path
    if request.url.query:
        current_list_url = f"{current_list_url}?{request.url.query}"
    current_list_url_encoded = quote(current_list_url, safe="")

    # РџР°РіРёРЅР°С†РёСЏ
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    tickets = tickets_query.offset(start).limit(per_page).all()

    response = templates.TemplateResponse(
        "tickets.html",
        {
            "request": request,
            "user": user,
            "tickets": tickets,
            "list_path": list_path,
            "page_title": page_title,
            "empty_text": empty_text,
            "is_archive_page": archive_mode,
            "create_enabled": create_enabled,
            "status_filter_options": status_filter_options,
            "reset_filters_url": reset_filters_url,
            "active_list_path": "/web",
            "archive_list_path": "/web/archive",
            "view_mode_storage_key": view_mode_storage_key,
            "can_switch_view_mode": can_switch_view_mode,
            "projects": projects,
            "executors": executors,
            "watcher_candidates": users,
            "ticket_types": ticket_types,
            "departments": departments,
            "org_units": org_units,
            "users_by_id": users_by_id,
            "projects_by_id": projects_by_id,
            "ticket_types_by_id": ticket_types_by_id,
            "departments_by_id": departments_by_id,
            "now": now,
            "now_plus_deadline_warning": now_plus_deadline_warning,
            "deadline_soon_warning_minutes": deadline_soon_warning_minutes,
            "status_filter": status_filter or "",
            "project_id_filter": project_id_int if project_id_int is not None else "",
            "ticket_type_id_filter": ticket_type_id_int if ticket_type_id_int is not None else "",
            "department_id_filter": department_id_int if department_id_int is not None else "",
            "target_unit_id_filter": target_unit_id_int if target_unit_id_int is not None else "",
            "unit_executor_id_filter": unit_executor_id_int if unit_executor_id_int is not None else "",
            "executor_id_filter": executor_id or "",  # <-- Р”РћР‘РђР’РР›Р (СЃС‚СЂРѕРєР°!)
            "q": q or "",
            "only_overdue": "1" if overdue_enabled else "",
            "sort": sort_value,
            "view_mode": view_mode_value,
            "page_size": per_page,
            "page_size_options": page_size_options,
            "status_labels": status_labels,
            "total_count": total_count,
            "legal_hold_count": legal_hold_count,
            "counts_by_status": counts_by_status,
            "overdue_count": overdue_count,
            "filters_form_open": filters_form_open,
            "create_form_open": create_form_open,
            "create_error": create_error_value,
            "bulk_actions": bulk_actions,
            "bulk_notice": bulk_notice,
            "bulk_notice_level": bulk_notice_level,
            "max_ticket_title_len": MAX_TICKET_TITLE_LEN,
            "current_list_url": current_list_url,
            "current_list_url_encoded": current_list_url_encoded,
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1,
            "org_v2_enabled": ORG_STRUCTURE_V2_ENABLED,

        },
    )
    response.set_cookie(
        "tickets_page_size",
        str(per_page),
        max_age=60 * 60 * 24 * 365,
        httponly=False,
        samesite="lax",
        path="/",
    )
    return response


@app.get("/web")
def web_tickets(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = None,
    project_id: str | None = None,
    ticket_type_id: str | None = None,
    department_id: str | None = None,
    executor_id: str | None = None,
    target_unit_id: str | None = None,
    unit_executor_id: str | None = None,
    q: str | None = None,
    only_overdue: str | None = None,
    sort: str | None = None,
    view_mode: str | None = None,
    open_create: str | None = None,
    create_error: str | None = None,
    page: int = 1,
    page_size: str | None = None,
):
    return _render_web_tickets_page(
        request=request,
        db=db,
        user=user,
        status_filter=status_filter,
        project_id=project_id,
        ticket_type_id=ticket_type_id,
        department_id=department_id,
        executor_id=executor_id,
        target_unit_id=target_unit_id,
        unit_executor_id=unit_executor_id,
        q=q,
        only_overdue=only_overdue,
        sort=sort,
        view_mode=view_mode,
        open_create=open_create,
        create_error=create_error,
        page=page,
        page_size=page_size,
        archive_mode=False,
    )


@app.get("/web/archive")
def web_archive_tickets(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = None,
    project_id: str | None = None,
    ticket_type_id: str | None = None,
    department_id: str | None = None,
    executor_id: str | None = None,
    target_unit_id: str | None = None,
    unit_executor_id: str | None = None,
    q: str | None = None,
    only_overdue: str | None = None,
    sort: str | None = None,
    view_mode: str | None = None,
    page: int = 1,
    page_size: str | None = None,
):
    return _render_web_tickets_page(
        request=request,
        db=db,
        user=user,
        status_filter=status_filter,
        project_id=project_id,
        ticket_type_id=ticket_type_id,
        department_id=department_id,
        executor_id=executor_id,
        target_unit_id=target_unit_id,
        unit_executor_id=unit_executor_id,
        q=q,
        only_overdue=only_overdue,
        sort=sort,
        view_mode=view_mode,
        open_create=None,
        create_error=None,
        page=page,
        page_size=page_size,
        archive_mode=True,
    )


@app.get("/web/settings")
def web_settings(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    selected_settings_section = normalize_settings_section(request.query_params.get("section"))
    company: Company | None = None
    if not is_platform_admin(user):
        ensure_company_user(user)
        if user.company_id is not None:
            company = db.get(Company, user.company_id)
    deadline_soon_warning_minutes = get_company_deadline_soon_warning_minutes(company)
    archive_retention_days_default = get_company_archive_retention_days(company)
    deadline_warning_saved = (request.query_params.get("deadline_warning_saved") or "").strip() == "1"
    deadline_warning_error = (request.query_params.get("deadline_warning_error") or "").strip().lower()
    if deadline_warning_error not in {"bad_value", "save_failed"}:
        deadline_warning_error = ""
    archive_retention_saved = (request.query_params.get("archive_retention_saved") or "").strip() == "1"
    archive_retention_error = (request.query_params.get("archive_retention_error") or "").strip().lower()
    if archive_retention_error not in {"bad_value", "save_failed"}:
        archive_retention_error = ""
    watcher_comments_saved = (request.query_params.get("watcher_comments_saved") or "").strip() == "1"
    watcher_comments_error = (request.query_params.get("watcher_comments_error") or "").strip().lower()
    if watcher_comments_error not in {"save_failed"}:
        watcher_comments_error = ""
    receipt_notifications_saved = (request.query_params.get("receipt_notifications_saved") or "").strip() == "1"
    receipt_notifications_error = (request.query_params.get("receipt_notifications_error") or "").strip().lower()
    if receipt_notifications_error not in {"save_failed"}:
        receipt_notifications_error = ""
    preferred_card_saved = (request.query_params.get("preferred_card_saved") or "").strip() == "1"
    preferred_card_error = (request.query_params.get("preferred_card_error") or "").strip().lower()
    if preferred_card_error not in {"bad_value", "save_failed"}:
        preferred_card_error = ""
    card_created = (request.query_params.get("card_created") or "").strip() == "1"
    card_create_error = (request.query_params.get("card_create_error") or "").strip().lower()
    if card_create_error not in {"missing_required", "card_exists", "save_failed"}:
        card_create_error = ""
    card_deleted = (request.query_params.get("card_deleted") or "").strip() == "1"
    card_delete_error = (request.query_params.get("card_delete_error") or "").strip().lower()
    if card_delete_error not in {"not_found", "in_use", "save_failed"}:
        card_delete_error = ""
    session_revoke_error = (request.query_params.get("session_revoke_error") or "").strip().lower()
    if session_revoke_error not in {"save_failed"}:
        session_revoke_error = ""
    password_change_error = (request.query_params.get("password_change_error") or "").strip().lower()
    if password_change_error not in {"invalid_current_password", "password_mismatch", "password_too_short", "save_failed"}:
        password_change_error = ""
    cards = (
        db.query(PaymentCard.id, PaymentCard.name, PaymentCard.is_active)
        .filter(PaymentCard.company_id == user.company_id, PaymentCard.owner_user_id == user.id)
        .order_by(PaymentCard.name.asc())
        .all()
    ) if user.company_id is not None else []
    can_manage_deadline_warning = user.role in (Role.admin, Role.curator)
    can_manage_archive_retention = user.role in (Role.admin, Role.curator)
    settings_sections = [
        {
            **meta,
            "href": build_settings_url(meta["id"]),
            "is_active": meta["id"] == selected_settings_section,
        }
        for meta in SETTINGS_SECTIONS.values()
    ]
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "org_v2_enabled": ORG_STRUCTURE_V2_ENABLED,
            "deadline_soon_warning_minutes": deadline_soon_warning_minutes,
            "deadline_warning_saved": deadline_warning_saved,
            "deadline_warning_error": deadline_warning_error,
            "archive_retention_days_default": archive_retention_days_default,
            "archive_retention_saved": archive_retention_saved,
            "archive_retention_error": archive_retention_error,
            "watcher_comments_saved": watcher_comments_saved,
            "watcher_comments_error": watcher_comments_error,
            "receipt_notifications_saved": receipt_notifications_saved,
            "receipt_notifications_error": receipt_notifications_error,
            "preferred_card_saved": preferred_card_saved,
            "preferred_card_error": preferred_card_error,
            "card_created": card_created,
            "card_create_error": card_create_error,
            "card_deleted": card_deleted,
            "card_delete_error": card_delete_error,
            "session_revoke_error": session_revoke_error,
            "password_change_error": password_change_error,
            "cards": cards,
            "preferred_payment_card_id": user.preferred_payment_card_id,
            "settings_sections": settings_sections,
            "selected_settings_section": selected_settings_section,
            "selected_settings_section_meta": SETTINGS_SECTIONS.get(selected_settings_section),
            "native_push_managed": is_native_android_app_request(request),
            "can_manage_deadline_warning": can_manage_deadline_warning,
            "can_manage_archive_retention": can_manage_archive_retention,
            "can_manage_cards": not is_platform_admin(user),
            "can_manage_receipt_settings": user.company_id is not None and not is_platform_admin(user),
            "min_deadline_soon_warning_minutes": MIN_DEADLINE_SOON_WARNING_MINUTES,
            "max_deadline_soon_warning_minutes": MAX_DEADLINE_SOON_WARNING_MINUTES,
            "min_archive_retention_days": MIN_ARCHIVE_RETENTION_DAYS,
            "max_archive_retention_days": MAX_ARCHIVE_RETENTION_DAYS,
        },
    )


@app.post("/web/settings/logout-all")
async def web_settings_logout_all(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    try:
        bump_user_auth_token_version(user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, session_revoke_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    audit_security_event("logout_all_devices", request, success=True, email=user.email, user_id=user.id)
    resp = RedirectResponse(url="/web/login?info=logged_out_all", status_code=HTTP_303_SEE_OTHER)
    delete_auth_cookie(resp, request)
    return resp


@app.post("/web/settings/change-password")
async def web_settings_change_password(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    current_password = (form.get("current_password") or "").strip()
    new_password = (form.get("new_password") or "").strip()
    new_password_confirm = (form.get("new_password_confirm") or "").strip()
    if not verify_password(current_password, user.password_hash):
        return RedirectResponse(
            url=build_settings_url(section, password_change_error="invalid_current_password"),
            status_code=HTTP_303_SEE_OTHER,
        )
    if len(new_password) < 8:
        return RedirectResponse(
            url=build_settings_url(section, password_change_error="password_too_short"),
            status_code=HTTP_303_SEE_OTHER,
        )
    if new_password != new_password_confirm:
        return RedirectResponse(
            url=build_settings_url(section, password_change_error="password_mismatch"),
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        user.password_hash = hash_password(new_password)
        bump_user_auth_token_version(user)
        clear_password_reset_state(user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, password_change_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    audit_security_event("password_change", request, success=True, email=user.email, user_id=user.id)
    resp = RedirectResponse(url="/web/login?info=password_changed", status_code=HTTP_303_SEE_OTHER)
    delete_auth_cookie(resp, request)
    return resp


@app.post("/web/settings/deadline-warning")
async def web_settings_deadline_warning(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    company = db.get(Company, user.company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    parsed = parse_deadline_soon_warning_minutes(form.get("deadline_soon_warning_minutes"))
    if parsed is None:
        return RedirectResponse(
            url=build_settings_url(section, deadline_warning_error="bad_value"),
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        company.deadline_soon_warning_minutes = parsed
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, deadline_warning_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=build_settings_url(section, deadline_warning_saved=True),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/settings/archive-retention")
async def web_settings_archive_retention(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    company = db.get(Company, user.company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    parsed = parse_archive_retention_days(form.get("archive_retention_days_default"))
    if parsed is None:
        return RedirectResponse(
            url=build_settings_url(section, archive_retention_error="bad_value"),
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        company.archive_retention_days_default = parsed
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, archive_retention_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=build_settings_url(section, archive_retention_saved=True),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/settings/watcher-comments")
async def web_settings_watcher_comments(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    # Unchecked checkbox is absent from form payload.
    enabled = (form.get("notify_comments_as_watcher") or "").strip() in {"1", "true", "on"}
    try:
        user.notify_comments_as_watcher = enabled
        db.add(user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, watcher_comments_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=build_settings_url(section, watcher_comments_saved=True),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/settings/receipt-notifications")
async def web_settings_receipt_notifications(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    enabled = (form.get("notify_receipt_created") or "").strip() in {"1", "true", "on"}
    try:
        user.notify_receipt_created = enabled
        db.add(user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, receipt_notifications_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=build_settings_url(section, receipt_notifications_saved=True),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/settings/preferred-card")
async def web_settings_preferred_card(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_company_user(user)
    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    raw_value = (form.get("preferred_payment_card_id") or "").strip()
    preferred_card_id: int | None = None
    if raw_value:
        try:
            preferred_card_id = int(raw_value)
        except ValueError:
            preferred_card_id = None
    if raw_value and preferred_card_id is None:
        return RedirectResponse(
            url=build_settings_url(section, preferred_card_error="bad_value"),
            status_code=HTTP_303_SEE_OTHER,
        )
    if preferred_card_id is not None:
        exists = (
            db.query(PaymentCard.id)
            .filter(
                PaymentCard.id == preferred_card_id,
                PaymentCard.company_id == user.company_id,
                PaymentCard.owner_user_id == user.id,
                PaymentCard.is_active.is_(True),
            )
            .first()
        )
        if not exists:
            return RedirectResponse(
                url=build_settings_url(section, preferred_card_error="bad_value"),
                status_code=HTTP_303_SEE_OTHER,
            )
    try:
        user.preferred_payment_card_id = preferred_card_id
        db.add(user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, preferred_card_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=build_settings_url(section, preferred_card_saved=True),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.get("/web/notifications")
def web_notifications(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = None,
    kind_filter: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    ensure_company_user(user)
    base_query = (
        db.query(Notification)
        .filter(Notification.user_id == user.id)
    )
    status_value = (status_filter or "all").strip().lower()
    if status_value == "unread":
        base_query = base_query.filter(Notification.is_read.is_(False))
    elif status_value == "read":
        base_query = base_query.filter(Notification.is_read.is_(True))
    else:
        status_value = "all"

    date_from_value = (date_from or "").strip()
    if date_from_value:
        try:
            dt_from = datetime.strptime(date_from_value, "%Y-%m-%d")
            base_query = base_query.filter(Notification.created_at >= dt_from)
        except ValueError:
            date_from_value = ""

    date_to_value = (date_to or "").strip()
    if date_to_value:
        try:
            dt_to = datetime.strptime(date_to_value, "%Y-%m-%d") + timedelta(days=1)
            base_query = base_query.filter(Notification.created_at < dt_to)
        except ValueError:
            date_to_value = ""

    raw_items = base_query.order_by(Notification.id.desc()).limit(1000).all()
    kind_value = (kind_filter or "all").strip().lower()
    if kind_value not in {"all", "status", "comment", "deadline", "assignment", "other"}:
        kind_value = "all"
    q_value = (q or "").strip().lower()

    items: list[Notification] = []
    needs_repair_commit = False
    for item in raw_items:
        fixed_title = fix_mojibake_text(item.title or "")
        fixed_body = fix_mojibake_text(item.body or "") if item.body else None
        if fixed_title != (item.title or ""):
            item.title = fixed_title
            needs_repair_commit = True
        if fixed_body != item.body:
            item.body = fixed_body
            needs_repair_commit = True
        item_kind = infer_notification_kind(item.title, item.body, item.url)
        setattr(item, "kind", item_kind)
        if kind_value != "all" and item_kind != kind_value:
            continue
        searchable_url = (item.url or '').lower()
        haystack = f"{(item.title or '').lower()} {(item.body or '').lower()} {searchable_url}"
        if q_value and q_value not in haystack:
            continue
        items.append(item)

    if needs_repair_commit:
        db.commit()

    items.sort(key=lambda n: (n.is_read, -int(n.id)))
    unread_count = (
        db.query(func.count(Notification.id))
        .filter(Notification.user_id == user.id, Notification.is_read.is_(False))
        .scalar()
        or 0
    )
    return templates.TemplateResponse(
        "notifications.html",
        {
            "request": request,
            "user": user,
            "notifications": items,
            "unread_count": int(unread_count),
            "status_filter": status_value,
            "kind_filter": kind_value,
            "q": q or "",
            "date_from": date_from_value,
            "date_to": date_to_value,
        },
    )


@app.get("/web/notifications/unread-count")
def web_notifications_unread_count(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_company_user(user)
    unread_count = (
        db.query(func.count(Notification.id))
        .filter(Notification.user_id == user.id, Notification.is_read.is_(False))
        .scalar()
        or 0
    )
    return {"unread": int(unread_count)}


@app.post("/web/notifications/read-all")
def web_notifications_read_all(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_company_user(user)
    (
        db.query(Notification)
        .filter(Notification.user_id == user.id, Notification.is_read.is_(False))
        .update(
            {
                Notification.is_read: True,
                Notification.read_at: datetime.utcnow(),
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return RedirectResponse(url="/web/notifications", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/notifications/delete-all")
def web_notifications_delete_all(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_company_user(user)
    db.query(Notification).filter(Notification.user_id == user.id).delete(synchronize_session=False)
    db.commit()
    return RedirectResponse(url="/web/notifications", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/notifications/{notification_id}/delete")
def web_notifications_delete_one(
    notification_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_company_user(user)
    item = db.get(Notification, notification_id)
    if not item or item.user_id != user.id:
        raise HTTPException(404, "Notification not found")
    db.delete(item)
    db.commit()
    return RedirectResponse(url="/web/notifications", status_code=HTTP_303_SEE_OTHER)


@app.get("/web/notifications/{notification_id}/open")
def web_notifications_open(
    notification_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_company_user(user)
    item = db.get(Notification, notification_id)
    if not item or item.user_id != user.id:
        raise HTTPException(404, "Notification not found")
    if not item.is_read:
        item.is_read = True
        item.read_at = datetime.utcnow()
        db.commit()
    return RedirectResponse(url=safe_notification_target(item.url), status_code=HTTP_303_SEE_OTHER)


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
    return manageable_roles_for_web_user_management(actor)


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


def safe_notification_target(raw_url: str | None) -> str:
    target = (raw_url or "").strip()
    if not target:
        return "/web/notifications"
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return "/web/notifications"
    if not target.startswith("/"):
        return "/web/notifications"
    return target


def infer_notification_kind(title: str | None, body: str | None, url: str | None) -> str:
    normalized_title = fix_mojibake_text(title or "").lower()
    normalized_body = fix_mojibake_text(body or "").lower()
    normalized_url = (url or "").lower()
    text = f"{normalized_title} {normalized_body} {normalized_url}"
    if "комментар" in text:
        return "comment"
    if "срок" in text or "дедлайн" in text:
        return "deadline"
    if "статус" in text:
        return "status"
    if "назнач" in text or "исполнител" in text:
        return "assignment"
    return "other"


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


@app.get("/web/org-structure")
def web_org_structure(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
    section: str | None = None,
    edit_unit_id: str | None = None,
    assignment_unit_id: str | None = None,
    assignment_executor_id: str | None = None,
    assignment_department_id: str | None = None,
    assignment_unit_q: str | None = None,
    assignment_executor_q: str | None = None,
    assignment_primary: str | None = None,
    assignment_page: int = 1,
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)
    selected_org_section = infer_org_structure_section(
        section,
        error=request.query_params.get("error"),
        import_ok=request.query_params.get("import_ok"),
        edit_unit_id=edit_unit_id,
        assignment_unit_id=assignment_unit_id,
        assignment_executor_id=assignment_executor_id,
        assignment_department_id=assignment_department_id,
        assignment_unit_q=assignment_unit_q,
        assignment_executor_q=assignment_executor_q,
        assignment_primary=assignment_primary,
        assignment_page=assignment_page,
    )

    rows = (
        db.query(
            OrgUnit.id,
            OrgUnit.name,
            OrgUnit.parent_id,
            OrgUnit.unit_type_id,
            OrgUnit.is_active,
            UnitType.name,
        )
        .join(UnitType, UnitType.id == OrgUnit.unit_type_id)
        .filter(OrgUnit.company_id == user.company_id)
        .order_by(OrgUnit.id.asc())
        .all()
    )
    items = [
        {
            "id": r[0],
            "name": r[1],
            "parent_id": r[2],
            "unit_type_id": r[3],
            "is_active": bool(r[4]),
            "unit_type_name": r[5],
        }
        for r in rows
    ]
    by_parent: dict[int | None, list[dict]] = {}
    for item in items:
        by_parent.setdefault(item["parent_id"], []).append(item)
    for siblings in by_parent.values():
        siblings.sort(key=lambda x: (x["name"].lower(), x["id"]))

    ordered_units: list[dict] = []
    stack: list[tuple[dict, int]] = []
    for root in reversed(by_parent.get(None, [])):
        stack.append((root, 0))
    while stack:
        node, level = stack.pop()
        ordered_units.append(
            {
                "id": node["id"],
                "name": node["name"],
                "parent_id": node["parent_id"],
                "unit_type_name": node["unit_type_name"],
                "is_active": node["is_active"],
                "level": level,
            }
        )
        children = by_parent.get(node["id"], [])
        for child in reversed(children):
            stack.append((child, level + 1))

    type_names = (
        db.query(UnitType.name)
        .filter(UnitType.company_id == user.company_id, UnitType.is_active.is_(True))
        .order_by(UnitType.name.asc())
        .all()
    )
    unit_type_names = [r[0] for r in type_names]
    if not unit_type_names:
        unit_type_names = ["РЈР·РµР»"]
    executors = (
        query_assignable_company_users(db, user.company_id)
        .order_by(User.name.asc(), User.id.asc())
        .all()
    )
    departments = (
        db.query(Department.id, Department.name, Department.is_active)
        .filter(Department.company_id == user.company_id)
        .order_by(Department.name.asc(), Department.id.asc())
        .all()
    )
    unit_children_by_id: dict[int, list[int]] = {}
    for item in items:
        parent_id = item["parent_id"]
        if parent_id is not None:
            unit_children_by_id.setdefault(int(parent_id), []).append(int(item["id"]))
    unit_labels_by_id = {
        int(u["id"]): f"{'- ' * int(u['level'])}{u['name']}" for u in ordered_units
    }
    assignment_unit_id_int = int(assignment_unit_id) if (assignment_unit_id or "").strip().isdigit() else None
    assignment_executor_id_int = int(assignment_executor_id) if (assignment_executor_id or "").strip().isdigit() else None
    assignment_department_filter = (assignment_department_id or "").strip()
    assignment_unit_lookup = " ".join((assignment_unit_q or "").split()).strip()
    assignment_executor_lookup = " ".join((assignment_executor_q or "").split()).strip()
    resolved_unit_id_from_lookup = (
        resolve_target_unit_id_from_form_input(db, user.company_id, assignment_unit_lookup)
        if assignment_unit_lookup
        else None
    )
    resolved_executor_id_from_lookup = (
        resolve_executor_id_from_form_input(db, user.company_id, assignment_executor_lookup)
        if assignment_executor_lookup
        else None
    )
    if assignment_unit_id_int is None and resolved_unit_id_from_lookup is not None:
        assignment_unit_id_int = resolved_unit_id_from_lookup
    if assignment_executor_id_int is None and resolved_executor_id_from_lookup is not None:
        assignment_executor_id_int = resolved_executor_id_from_lookup
    assignment_unit_query = assignment_unit_lookup.lower() if assignment_unit_id_int is None else ""
    assignment_executor_query = assignment_executor_lookup.lower() if assignment_executor_id_int is None else ""
    assignment_department_id_int = int(assignment_department_filter) if assignment_department_filter.isdigit() else None
    assignment_without_department = assignment_department_filter == "__none__"
    assignment_only_primary = (assignment_primary or "").strip() in {"1", "true", "on", "yes"}

    filtered_unit_ids: set[int] | None = None
    if assignment_unit_id_int is not None and assignment_unit_id_int in unit_labels_by_id:
        filtered_unit_ids = set()
        stack_ids = [assignment_unit_id_int]
        while stack_ids:
            current_id = stack_ids.pop()
            if current_id in filtered_unit_ids:
                continue
            filtered_unit_ids.add(current_id)
            stack_ids.extend(unit_children_by_id.get(current_id, []))

    assignment_query = (
        db.query(
            UnitAssignment.id,
            UnitAssignment.unit_id,
            UnitAssignment.user_id,
            UnitAssignment.department_id,
            UnitAssignment.is_primary,
            Department.name,
            User.name,
            User.email,
        )
        .join(User, User.id == UnitAssignment.user_id)
        .outerjoin(Department, Department.id == UnitAssignment.department_id)
        .filter(
            UnitAssignment.company_id == user.company_id,
            UnitAssignment.role_code == "EXECUTOR",
        )
    )
    assignments_total_all = assignment_query.count()
    if filtered_unit_ids is not None:
        assignment_query = assignment_query.filter(UnitAssignment.unit_id.in_(sorted(filtered_unit_ids)))
    if assignment_unit_query:
        matched_unit_ids = [
            int(unit["id"])
            for unit in ordered_units
            if assignment_unit_query in str(unit["name"] or "").strip().lower()
            or assignment_unit_query in unit_labels_by_id.get(int(unit["id"]), "").lower()
        ]
        if matched_unit_ids:
            assignment_query = assignment_query.filter(UnitAssignment.unit_id.in_(matched_unit_ids))
        else:
            assignment_query = assignment_query.filter(UnitAssignment.id == -1)
    if assignment_executor_id_int is not None:
        assignment_query = assignment_query.filter(UnitAssignment.user_id == assignment_executor_id_int)
    if assignment_executor_query:
        assignment_query = assignment_query.filter(
            or_(
                func.lower(User.name).like(f"%{assignment_executor_query}%"),
                func.lower(User.email).like(f"%{assignment_executor_query}%"),
            )
        )
    if assignment_without_department:
        assignment_query = assignment_query.filter(UnitAssignment.department_id.is_(None))
    elif assignment_department_id_int is not None:
        assignment_query = assignment_query.filter(UnitAssignment.department_id == assignment_department_id_int)
    if assignment_only_primary:
        assignment_query = assignment_query.filter(UnitAssignment.is_primary.is_(True))

    assignment_filters_active = bool(
        assignment_unit_id_int is not None
        or assignment_executor_id_int is not None
        or assignment_department_filter
        or bool(assignment_unit_query)
        or bool(assignment_executor_query)
        or assignment_only_primary
    )
    assignments_total = assignment_query.count()
    assignments_per_page = 40
    assignments_total_pages = max(1, (assignments_total + assignments_per_page - 1) // assignments_per_page)
    assignment_page = max(1, min(assignment_page, assignments_total_pages))
    assignment_rows = (
        assignment_query
        .order_by(UnitAssignment.unit_id.asc(), UnitAssignment.is_primary.desc(), UnitAssignment.id.asc())
        .offset((assignment_page - 1) * assignments_per_page)
        .limit(assignments_per_page)
        .all()
    )
    assignments = [
        {
            "id": int(r[0]),
            "unit_id": int(r[1]),
            "user_id": int(r[2]),
            "department_id": int(r[3]) if r[3] is not None else None,
            "is_primary": bool(r[4]),
            "department_name": str(r[5] or "").strip() or "Без отдела",
            "user_name": str(r[6] or ""),
            "user_email": str(r[7] or ""),
            "unit_label": unit_labels_by_id.get(int(r[1]), f"Unit #{int(r[1])}"),
        }
        for r in assignment_rows
    ]
    edit_unit = None
    edit_forbidden_parent_ids: set[int] = set()
    if edit_unit_id and edit_unit_id.strip():
        try:
            edit_id_int = int(edit_unit_id)
        except ValueError:
            edit_id_int = None
        if edit_id_int is not None:
            found = next((u for u in ordered_units if int(u["id"]) == edit_id_int), None)
            if found:
                edit_unit = {
                    "id": int(found["id"]),
                    "name": str(found["name"]),
                    "parent_id": found["parent_id"],
                    "unit_type_name": str(found["unit_type_name"]),
                    "is_active": bool(found["is_active"]),
                }
                edit_forbidden_parent_ids.add(edit_unit["id"])
                stack_ids = [edit_unit["id"]]
                children_by_parent: dict[int, list[int]] = {}
                for unit in ordered_units:
                    parent_id = unit["parent_id"]
                    if parent_id is None:
                        continue
                    children_by_parent.setdefault(int(parent_id), []).append(int(unit["id"]))
                while stack_ids:
                    current_id = stack_ids.pop()
                    for child_id in children_by_parent.get(current_id, []):
                        if child_id in edit_forbidden_parent_ids:
                            continue
                        edit_forbidden_parent_ids.add(child_id)
                        stack_ids.append(child_id)

    import_report = {
        "ok": (request.query_params.get("import_ok") or "").strip(),
        "rows": (request.query_params.get("import_rows") or "").strip(),
        "created": (request.query_params.get("import_created") or "").strip(),
        "updated": (request.query_params.get("import_updated") or "").strip(),
        "errors": (request.query_params.get("import_errors") or "").strip(),
    }
    org_sections = [
        {
            **meta,
            "href": build_org_structure_url(meta["id"]),
            "is_active": meta["id"] == selected_org_section,
        }
        for meta in ORG_STRUCTURE_SECTIONS.values()
    ]

    return templates.TemplateResponse(
        "org_structure.html",
        {
            "request": request,
            "user": user,
            "units": ordered_units,
            "parents": ordered_units,
            "unit_type_names": unit_type_names,
            "executors": executors,
            "departments": departments,
            "assignments": assignments,
            "edit_unit": edit_unit,
            "edit_forbidden_parent_ids": edit_forbidden_parent_ids,
            "org_v2_enabled": ORG_STRUCTURE_V2_ENABLED,
            "org_sections": org_sections,
            "selected_org_section": selected_org_section,
            "selected_org_section_meta": ORG_STRUCTURE_SECTIONS.get(selected_org_section),
            "import_report": import_report,
            "can_manage_departments": is_admin(user),
            "assignment_unit_id_filter": assignment_unit_id_int if assignment_unit_id_int is not None else "",
            "assignment_executor_id_filter": assignment_executor_id_int if assignment_executor_id_int is not None else "",
            "assignment_department_id_filter": assignment_department_filter,
            "assignment_unit_q_filter": assignment_unit_lookup,
            "assignment_executor_q_filter": assignment_executor_lookup,
            "assignment_primary_filter": assignment_only_primary,
            "assignment_filters_active": assignment_filters_active,
            "assignments_total_all": assignments_total_all,
            "assignments_total": assignments_total,
            "assignments_page": assignment_page,
            "assignments_total_pages": assignments_total_pages,
        },
    )


@app.post("/web/departments/create")
async def web_departments_create(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
):
    ensure_company_user(user)
    form = await request.form()
    section = infer_org_structure_section(form.get("section"), error=request.query_params.get("error"))
    name = normalize_department_name(form.get("name"))
    is_active = (form.get("is_active") or "1").strip() in {"1", "on", "true", "yes"}
    if not name:
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_empty_name"),
            status_code=HTTP_303_SEE_OTHER,
        )
    exists = (
        db.query(Department.id)
        .filter(Department.company_id == user.company_id, func.lower(Department.name) == name.lower())
        .first()
    )
    if exists:
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_exists"),
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        db.add(Department(company_id=user.company_id, name=name, is_active=is_active))
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url=build_org_structure_url(section), status_code=HTTP_303_SEE_OTHER)


@app.post("/web/departments/{department_id}/update")
async def web_departments_update(
    department_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
):
    ensure_company_user(user)
    section = infer_org_structure_section(request.query_params.get("section"))
    item = db.get(Department, department_id)
    if not item or item.company_id != user.company_id:
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_not_found"),
            status_code=HTTP_303_SEE_OTHER,
        )
    form = await request.form()
    section = infer_org_structure_section(form.get("section") or section)
    name = normalize_department_name(form.get("name"))
    is_active = (form.get("is_active") or "").strip() in {"1", "on", "true", "yes"}
    if not name:
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_empty_name"),
            status_code=HTTP_303_SEE_OTHER,
        )
    exists = (
        db.query(Department.id)
        .filter(
            Department.company_id == user.company_id,
            func.lower(Department.name) == name.lower(),
            Department.id != item.id,
        )
        .first()
    )
    if exists:
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_exists"),
            status_code=HTTP_303_SEE_OTHER,
        )
    item.name = name
    item.is_active = is_active
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url=build_org_structure_url(section), status_code=HTTP_303_SEE_OTHER)


@app.post("/web/departments/{department_id}/delete")
async def web_departments_delete(
    department_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
):
    ensure_company_user(user)
    section = infer_org_structure_section(request.query_params.get("section"))
    form = await request.form()
    section = infer_org_structure_section(form.get("section") or section)
    item = db.get(Department, department_id)
    if not item or item.company_id != user.company_id:
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_not_found"),
            status_code=HTTP_303_SEE_OTHER,
        )
    in_use = any(
        (
            db.query(TicketType.id).filter(TicketType.company_id == user.company_id, TicketType.department_id == item.id).first() is not None,
            db.query(TicketTemplate.id).filter(TicketTemplate.company_id == user.company_id, TicketTemplate.department_id == item.id).first() is not None,
            db.query(UnitAssignment.id).filter(UnitAssignment.company_id == user.company_id, UnitAssignment.department_id == item.id).first() is not None,
            db.query(Ticket.id).filter(Ticket.company_id == user.company_id, Ticket.department_id == item.id).first() is not None,
        )
    )
    if in_use:
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_in_use"),
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        db.delete(item)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_org_structure_url(section, error="department_save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url=build_org_structure_url(section), status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/create")
async def web_org_structure_create(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)

    form = await request.form()
    section = infer_org_structure_section(form.get("section"), error=request.query_params.get("error"))
    name = (form.get("name") or "").strip()
    parent_raw = (form.get("parent_id") or "").strip()
    type_name = (form.get("unit_type_name") or "").strip() or "РЈР·РµР»"
    if not name:
        return RedirectResponse(
            url=build_org_structure_url(section, error="empty_name"),
            status_code=HTTP_303_SEE_OTHER,
        )

    try:
        parent_id = int(parent_raw) if parent_raw else None
    except ValueError:
        return RedirectResponse(
            url=build_org_structure_url(section, error="bad_parent"),
            status_code=HTTP_303_SEE_OTHER,
        )

    if parent_id is not None:
        parent = db.get(OrgUnit, parent_id)
        if not parent or parent.company_id != user.company_id:
            return RedirectResponse(
                url=build_org_structure_url(section, error="parent_not_found"),
                status_code=HTTP_303_SEE_OTHER,
            )

    try:
        unit_type = get_or_create_unit_type(db, user.company_id, type_name)
        item = OrgUnit(
            company_id=user.company_id,
            name=name,
            unit_type_id=unit_type.id,
            parent_id=parent_id,
            is_active=True,
        )
        db.add(item)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_org_structure_url(section, error="create_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url=build_org_structure_url(section), status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/assign")
async def web_org_structure_assign_executor(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)

    form = await request.form()
    section = infer_org_structure_section(form.get("section"), error=request.query_params.get("error"))
    unit_values_raw = [str(v).strip() for v in form.getlist("unit_ids") if str(v).strip()]
    if not unit_values_raw:
        fallback_unit_raw = (form.get("unit_id") or "").strip()
        if fallback_unit_raw:
            unit_values_raw = [fallback_unit_raw]
    executor_raw = (form.get("executor_id") or "").strip()
    department_raw = (form.get("department_id") or "").strip()
    is_primary = (form.get("is_primary") or "").strip() in {"1", "on", "true", "yes"}

    try:
        executor_id = int(executor_raw)
    except ValueError:
        return RedirectResponse(
            url=build_org_structure_url(section, error="assign_bad_input"),
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        department_id = int(department_raw) if department_raw else None
    except ValueError:
        return RedirectResponse(
            url=build_org_structure_url(section, error="assign_bad_input"),
            status_code=HTTP_303_SEE_OTHER,
        )

    unit_ids: list[int] = []
    seen_unit_ids: set[int] = set()
    try:
        for unit_raw in unit_values_raw:
            unit_id = int(unit_raw)
            if unit_id not in seen_unit_ids:
                seen_unit_ids.add(unit_id)
                unit_ids.append(unit_id)
    except ValueError:
        return RedirectResponse(
            url=build_org_structure_url(section, error="assign_bad_input"),
            status_code=HTTP_303_SEE_OTHER,
        )

    if not unit_ids:
        return RedirectResponse(
            url=build_org_structure_url(section, error="assign_bad_input"),
            status_code=HTTP_303_SEE_OTHER,
        )

    executor = db.get(User, executor_id)
    if not executor or executor.company_id != user.company_id or executor.role != Role.executor:
        return RedirectResponse(
            url=build_org_structure_url(section, error="assign_executor_not_found"),
            status_code=HTTP_303_SEE_OTHER,
        )
    if department_id is not None:
        department = db.get(Department, department_id)
        if not department or department.company_id != user.company_id or not department.is_active:
            return RedirectResponse(
                url=build_org_structure_url(section, error="assign_department_not_found"),
                status_code=HTTP_303_SEE_OTHER,
            )

    found_unit_ids = {
        row[0]
        for row in (
            db.query(OrgUnit.id)
            .filter(OrgUnit.company_id == user.company_id, OrgUnit.id.in_(unit_ids))
            .all()
        )
    }
    if len(found_unit_ids) != len(unit_ids):
        return RedirectResponse(
            url=build_org_structure_url(section, error="assign_unit_not_found"),
            status_code=HTTP_303_SEE_OTHER,
        )

    try:
        existing_rows = (
            db.query(UnitAssignment)
            .filter(
                UnitAssignment.company_id == user.company_id,
                UnitAssignment.unit_id.in_(unit_ids),
                UnitAssignment.user_id == executor_id,
                UnitAssignment.role_code == "EXECUTOR",
                department_match_filter(UnitAssignment.department_id, department_id),
            )
            .all()
        )
        existing_by_unit_id = {row.unit_id: row for row in existing_rows}

        for unit_id in unit_ids:
            existing = existing_by_unit_id.get(unit_id)
            if existing:
                existing.is_primary = existing.is_primary or is_primary
                assignment_id = existing.id
            else:
                item = UnitAssignment(
                    company_id=user.company_id,
                    unit_id=unit_id,
                    user_id=executor_id,
                    role_code="EXECUTOR",
                    department_id=department_id,
                    is_primary=is_primary,
                )
                db.add(item)
                db.flush()
                assignment_id = item.id

            if is_primary:
                (
                    db.query(UnitAssignment)
                    .filter(
                        UnitAssignment.company_id == user.company_id,
                        UnitAssignment.unit_id == unit_id,
                        UnitAssignment.role_code == "EXECUTOR",
                        department_match_filter(UnitAssignment.department_id, department_id),
                        UnitAssignment.id != assignment_id,
                    )
                    .update({UnitAssignment.is_primary: False}, synchronize_session=False)
                )

        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_org_structure_url(section, error="assign_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )

    return RedirectResponse(url=build_org_structure_url(section), status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/assign/{assignment_id}/primary")
async def web_org_structure_assignment_primary(
    assignment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)
    form = await request.form()
    section = infer_org_structure_section(form.get("section") or request.query_params.get("section"))

    assignment = db.get(UnitAssignment, assignment_id)
    if not assignment or assignment.company_id != user.company_id or assignment.role_code != "EXECUTOR":
        raise HTTPException(404, "Assignment not found")

    (
        db.query(UnitAssignment)
        .filter(
            UnitAssignment.company_id == user.company_id,
            UnitAssignment.unit_id == assignment.unit_id,
            UnitAssignment.role_code == "EXECUTOR",
            department_match_filter(UnitAssignment.department_id, assignment.department_id),
        )
        .update({UnitAssignment.is_primary: False}, synchronize_session=False)
    )
    assignment.is_primary = True
    db.commit()
    return RedirectResponse(
        url=build_org_structure_url(
            section,
            assignment_department_id=form.get("assignment_department_id"),
            assignment_unit_q=form.get("assignment_unit_q"),
            assignment_executor_q=form.get("assignment_executor_q"),
            assignment_primary=(form.get("assignment_primary") or "").strip() in {"1", "true", "on", "yes"},
            assignment_page=form.get("assignment_page"),
        ),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/org-structure/assign/{assignment_id}/delete")
async def web_org_structure_assignment_delete(
    assignment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)
    form = await request.form()
    section = infer_org_structure_section(form.get("section") or request.query_params.get("section"))

    assignment = db.get(UnitAssignment, assignment_id)
    if not assignment or assignment.company_id != user.company_id or assignment.role_code != "EXECUTOR":
        raise HTTPException(404, "Assignment not found")

    db.delete(assignment)
    db.commit()
    return RedirectResponse(
        url=build_org_structure_url(
            section,
            assignment_department_id=form.get("assignment_department_id"),
            assignment_unit_q=form.get("assignment_unit_q"),
            assignment_executor_q=form.get("assignment_executor_q"),
            assignment_primary=(form.get("assignment_primary") or "").strip() in {"1", "true", "on", "yes"},
            assignment_page=form.get("assignment_page"),
        ),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/org-structure/{unit_id}/update")
async def web_org_structure_update(
    unit_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)
    section = infer_org_structure_section(request.query_params.get("section"), edit_unit_id=str(unit_id))

    item = db.get(OrgUnit, unit_id)
    if not item or item.company_id != user.company_id:
        return RedirectResponse(
            url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_not_found"),
            status_code=HTTP_303_SEE_OTHER,
        )

    form = await request.form()
    section = infer_org_structure_section(form.get("section") or section, edit_unit_id=str(unit_id))
    name = (form.get("name") or "").strip()
    parent_raw = (form.get("parent_id") or "").strip()
    type_name = (form.get("unit_type_name") or "").strip() or "РЈР·РµР»"
    is_active = (form.get("is_active") or "").strip() in {"1", "on", "true", "yes"}

    if not name:
        return RedirectResponse(
            url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_empty_name"),
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        parent_id = int(parent_raw) if parent_raw else None
    except ValueError:
        return RedirectResponse(
            url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_bad_parent"),
            status_code=HTTP_303_SEE_OTHER,
        )

    if parent_id is not None:
        parent = db.get(OrgUnit, parent_id)
        if not parent or parent.company_id != user.company_id:
            return RedirectResponse(
                url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_parent_not_found"),
                status_code=HTTP_303_SEE_OTHER,
            )

    parent_map = build_unit_parent_map(db, user.company_id)
    if would_create_unit_cycle(parent_map, unit_id=unit_id, new_parent_id=parent_id):
        return RedirectResponse(
            url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_cycle"),
            status_code=HTTP_303_SEE_OTHER,
        )

    try:
        unit_type = get_or_create_unit_type(db, user.company_id, type_name)
        item.name = name
        item.parent_id = parent_id
        item.unit_type_id = unit_type.id
        item.is_active = is_active
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )

    return RedirectResponse(url=build_org_structure_url(section), status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/import-csv")
async def web_org_structure_import_csv(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)
    section = infer_org_structure_section(request.query_params.get("section") or "import")

    try:
        raw_bytes = await file.read()
    except Exception:
        return RedirectResponse(
            url=build_org_structure_url(section, error="import_read_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    if not raw_bytes:
        return RedirectResponse(
            url=build_org_structure_url(section, error="import_empty"),
            status_code=HTTP_303_SEE_OTHER,
        )

    text = None
    for enc in ("utf-8-sig", "utf-8", "cp1251"):
        try:
            text = raw_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return RedirectResponse(
            url=build_org_structure_url(section, error="import_encoding"),
            status_code=HTTP_303_SEE_OTHER,
        )

    csv_stream = io.StringIO(text)
    sample = text[:2048]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(csv_stream, dialect=dialect)
    if not reader.fieldnames:
        return RedirectResponse(
            url=build_org_structure_url(section, error="import_headers"),
            status_code=HTTP_303_SEE_OTHER,
        )
    headers = {str(h or "").strip().lower() for h in reader.fieldnames}
    if "path" not in headers:
        return RedirectResponse(
            url=build_org_structure_url(section, error="import_need_path"),
            status_code=HTTP_303_SEE_OTHER,
        )

    existing_units = (
        db.query(OrgUnit.id, OrgUnit.parent_id, OrgUnit.name, OrgUnit.is_active)
        .filter(OrgUnit.company_id == user.company_id)
        .all()
    )
    unit_map: dict[tuple[int | None, str], dict] = {}
    for unit_id, parent_id, name, is_active in existing_units:
        key = (parent_id, (name or "").strip().lower())
        unit_map[key] = {"id": int(unit_id), "is_active": bool(is_active)}

    rows_total = 0
    created_count = 0
    updated_count = 0
    errors_count = 0

    try:
        for raw_row in reader:
            rows_total += 1
            row = {str(k or "").strip().lower(): (v or "").strip() for k, v in raw_row.items()}
            raw_path = row.get("path", "")
            if not raw_path:
                errors_count += 1
                continue

            names = [p.strip() for p in raw_path.split("/") if p.strip()]
            if not names:
                errors_count += 1
                continue
            types = [p.strip() for p in (row.get("types", "")).split("/") if p.strip()]
            active_final = parse_bool_text(row.get("is_active"), True)

            parent_id: int | None = None
            for idx, node_name in enumerate(names):
                key = (parent_id, node_name.lower())
                unit_info = unit_map.get(key)
                if unit_info:
                    parent_id = int(unit_info["id"])
                    continue

                type_name = types[idx] if idx < len(types) else "РЈР·РµР»"
                unit_type = get_or_create_unit_type(db, user.company_id, type_name)
                new_item = OrgUnit(
                    company_id=user.company_id,
                    name=node_name,
                    unit_type_id=unit_type.id,
                    parent_id=parent_id,
                    is_active=True,
                )
                db.add(new_item)
                db.flush()
                unit_map[key] = {"id": int(new_item.id), "is_active": True}
                parent_id = int(new_item.id)
                created_count += 1

            if parent_id is not None:
                final_item = db.get(OrgUnit, parent_id)
                if final_item and bool(final_item.is_active) != active_final:
                    final_item.is_active = active_final
                    updated_count += 1

        db.commit()
    except Exception:
        db.rollback()
        return RedirectResponse(
            url=build_org_structure_url(section, error="import_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )

    return RedirectResponse(
        url=build_org_structure_url(
            section,
            import_ok=True,
            import_rows=rows_total,
            import_created=created_count,
            import_updated=updated_count,
            import_errors=errors_count,
        ),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.get("/web/org-structure/template.csv")
def web_org_structure_template_csv(
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    template_path = Path(__file__).resolve().parent / "org_structure_import_example.csv"
    if not template_path.exists():
        raise HTTPException(404, "Template not found")
    return FileResponse(
        template_path,
        media_type="text/csv; charset=utf-8",
        filename="org_structure_import_example.csv",
    )


@app.post("/web/org-structure/{unit_id}/toggle")
async def web_org_structure_toggle(
    unit_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)
    form = await request.form()
    section = infer_org_structure_section(form.get("section") or request.query_params.get("section"))

    item = db.get(OrgUnit, unit_id)
    if not item or item.company_id != user.company_id:
        raise HTTPException(404, "Org unit not found")
    item.is_active = not bool(item.is_active)
    db.commit()
    return RedirectResponse(url=build_org_structure_url(section), status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/{unit_id}/delete")
async def web_org_structure_delete(
    unit_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)
    form = await request.form()
    section = infer_org_structure_section(form.get("section") or request.query_params.get("section"))

    item = db.get(OrgUnit, unit_id)
    if not item or item.company_id != user.company_id:
        return RedirectResponse(
            url=build_org_structure_url(section, error="delete_not_found"),
            status_code=HTTP_303_SEE_OTHER,
        )

    has_children = (
        db.query(OrgUnit.id)
        .filter(OrgUnit.company_id == user.company_id, OrgUnit.parent_id == unit_id)
        .first()
        is not None
    )
    if has_children:
        return RedirectResponse(
            url=build_org_structure_url(section, error="delete_has_children"),
            status_code=HTTP_303_SEE_OTHER,
        )

    has_assignments = (
        db.query(UnitAssignment.id)
        .filter(UnitAssignment.company_id == user.company_id, UnitAssignment.unit_id == unit_id)
        .first()
        is not None
    )
    if has_assignments:
        return RedirectResponse(
            url=build_org_structure_url(section, error="delete_has_assignments"),
            status_code=HTTP_303_SEE_OTHER,
        )

    has_templates = (
        db.query(TicketTemplate.id)
        .filter(TicketTemplate.company_id == user.company_id, TicketTemplate.scope_unit_id == unit_id)
        .first()
        is not None
    )
    if has_templates:
        return RedirectResponse(
            url=build_org_structure_url(section, error="delete_has_templates"),
            status_code=HTTP_303_SEE_OTHER,
        )

    has_tickets = (
        db.query(Ticket.id)
        .filter(Ticket.company_id == user.company_id, Ticket.target_unit_id == unit_id)
        .first()
        is not None
    )
    if has_tickets:
        return RedirectResponse(
            url=build_org_structure_url(section, error="delete_has_tickets"),
            status_code=HTTP_303_SEE_OTHER,
        )

    has_generation_keys = (
        db.query(TicketGenerationKey.id)
        .filter(TicketGenerationKey.company_id == user.company_id, TicketGenerationKey.target_unit_id == unit_id)
        .first()
        is not None
    )
    if has_generation_keys:
        return RedirectResponse(
            url=build_org_structure_url(section, error="delete_has_generation_keys"),
            status_code=HTTP_303_SEE_OTHER,
        )

    try:
        db.delete(item)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_org_structure_url(section, error="delete_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )

    return RedirectResponse(url=build_org_structure_url(section), status_code=HTTP_303_SEE_OTHER)


@app.get("/web/admin/companies")
def web_admin_companies(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_platform_admin(user):
        raise HTTPException(403, "Only platform admin")

    companies = db.query(Company).order_by(Company.id.desc()).all()
    company_ids = [c.id for c in companies]

    users_count_by_company: dict[int, int] = {}
    org_units_count_by_company: dict[int, int] = {}
    tickets_count_by_company: dict[int, int] = {}

    if company_ids:
        users_count_rows = (
            db.query(User.company_id, func.count(User.id))
            .filter(User.company_id.in_(company_ids))
            .group_by(User.company_id)
            .all()
        )
        users_count_by_company = {int(company_id): int(count_value) for company_id, count_value in users_count_rows if company_id is not None}

        org_units_count_rows = (
            db.query(OrgUnit.company_id, func.count(OrgUnit.id))
            .filter(OrgUnit.company_id.in_(company_ids))
            .group_by(OrgUnit.company_id)
            .all()
        )
        org_units_count_by_company = {
            int(company_id): int(count_value)
            for company_id, count_value in org_units_count_rows
            if company_id is not None
        }

        tickets_count_rows = (
            db.query(Ticket.company_id, func.count(Ticket.id))
            .filter(Ticket.company_id.in_(company_ids))
            .group_by(Ticket.company_id)
            .all()
        )
        tickets_count_by_company = {int(company_id): int(count_value) for company_id, count_value in tickets_count_rows if company_id is not None}

    items = []
    for c in companies:
        items.append(
            {
                "id": c.id,
                "name": c.name,
                "created_at": c.created_at,
                "users_count": users_count_by_company.get(c.id, 0),
                "org_units_count": org_units_count_by_company.get(c.id, 0),
                "tickets_count": tickets_count_by_company.get(c.id, 0),
            }
        )

    return templates.TemplateResponse(
        "admin_companies.html",
        {
            "request": request,
            "user": user,
            "companies": items,
        },
    )


@app.post("/web/admin/companies/{company_id}/delete")
async def web_admin_company_delete(
    company_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_platform_admin(user):
        raise HTTPException(403, "Only platform admin")
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    delete_company_with_data(db, company_id)
    db.commit()
    return RedirectResponse(url="/web/admin/companies", status_code=HTTP_303_SEE_OTHER)


def platform_manageable_roles() -> tuple[Role, ...]:
    return (Role.admin, Role.curator, Role.executor)


@app.get("/web/admin/companies/{company_id}/settings")
def web_admin_company_settings(
    company_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ok: str | None = None,
    err: str | None = None,
):
    if not is_platform_admin(user):
        raise HTTPException(403, "Only platform admin")
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    users = (
        db.query(User.id, User.name, User.email, User.role, User.show_receipts_accounting_mode)
        .filter(
            User.company_id == company_id,
            User.role.in_(platform_manageable_roles()),
        )
        .order_by(User.id.desc())
        .all()
    )
    role_options = [r.value for r in platform_manageable_roles()]

    ok_code = (ok or "").strip().lower()
    err_code = (err or "").strip().lower()
    ok_messages = {
        "company_updated": "Данные компании успешно обновлены.",
        "user_created": "Пользователь успешно создан.",
        "user_updated": "Данные пользователя успешно обновлены.",
        "user_deleted": "Пользователь успешно удален.",
    }
    err_messages = {
        "bad_company_name": "Укажите корректное название компании.",
        "bad_deadline_warning": "Некорректное значение предупреждения о дедлайне.",
        "bad_archive_retention": "Некорректное значение хранения в архиве.",
        "company_name_exists": "Компания с таким названием уже существует.",
        "bad_input": "Проверьте заполнение обязательных полей.",
        "bad_role": "Выбрана недопустимая роль пользователя.",
        "email_exists": "Пользователь с таким email уже существует.",
        "user_not_found": "Пользователь не найден.",
        "delete_blocked": "Нельзя удалить пользователя: есть связанные рабочие данные.",
        "save_failed": "Не удалось сохранить изменения. Повторите попытку.",
        "delete_failed": "Не удалось удалить пользователя. Повторите попытку.",
    }
    return templates.TemplateResponse(
        "admin_company_settings.html",
        {
            "request": request,
            "user": user,
            "company": company,
            "users": users,
            "role_options": role_options,
            "ok": ok_messages.get(ok_code, ""),
            "err": err_messages.get(err_code, ""),
            "min_deadline_soon_warning_minutes": MIN_DEADLINE_SOON_WARNING_MINUTES,
            "max_deadline_soon_warning_minutes": MAX_DEADLINE_SOON_WARNING_MINUTES,
            "min_archive_retention_days": MIN_ARCHIVE_RETENTION_DAYS,
            "max_archive_retention_days": MAX_ARCHIVE_RETENTION_DAYS,
        },
    )


@app.post("/web/admin/companies/{company_id}/update")
async def web_admin_company_settings_update(
    company_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_platform_admin(user):
        raise HTTPException(403, "Only platform admin")
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    form = await request.form()
    name = (form.get("name") or "").strip()
    if not name:
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=bad_company_name",
            status_code=HTTP_303_SEE_OTHER,
        )

    warning_parsed = parse_deadline_soon_warning_minutes(form.get("deadline_soon_warning_minutes"))
    retention_parsed = parse_archive_retention_days(form.get("archive_retention_days_default"))
    if warning_parsed is None:
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=bad_deadline_warning",
            status_code=HTTP_303_SEE_OTHER,
        )
    if retention_parsed is None:
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=bad_archive_retention",
            status_code=HTTP_303_SEE_OTHER,
        )

    duplicate = db.query(Company.id).filter(Company.name == name, Company.id != company_id).first()
    if duplicate:
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=company_name_exists",
            status_code=HTTP_303_SEE_OTHER,
        )

    company.name = name
    company.deadline_soon_warning_minutes = warning_parsed
    company.archive_retention_days_default = retention_parsed
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=save_failed",
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/web/admin/companies/{company_id}/settings?ok=company_updated",
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/admin/companies/{company_id}/users/create")
async def web_admin_company_user_create(
    company_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_platform_admin(user):
        raise HTTPException(403, "Only platform admin")
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    form = await request.form()
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip()
    password = (form.get("password") or "").strip()
    role_raw = (form.get("role") or "").strip().upper()

    if not (name and email and password):
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=bad_input",
            status_code=HTTP_303_SEE_OTHER,
        )
    if role_raw not in {r.value for r in platform_manageable_roles()}:
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=bad_role",
            status_code=HTTP_303_SEE_OTHER,
        )
    role_value = Role(role_raw)
    if db.query(User.id).filter(User.email == email).first():
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=email_exists",
            status_code=HTTP_303_SEE_OTHER,
        )

    item = User(
        email=email,
        name=name,
        password_hash=hash_password(password),
        role=role_value,
        company_id=company_id,
        **normalize_capability_flags(role_value),
    )
    prepare_user_email_verification(item, force_new_token=True)
    try:
        db.add(item)
        db.commit()
        db.refresh(item)
        send_user_verification_email(request, db, item)
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=save_failed",
            status_code=HTTP_303_SEE_OTHER,
        )
    except EmailDeliveryError:
        logger.exception("Could not send verification email to %s", item.email)
    return RedirectResponse(
        url=f"/web/admin/companies/{company_id}/settings?ok=user_created",
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/admin/companies/{company_id}/users/{managed_user_id}/update")
async def web_admin_company_user_update(
    company_id: int,
    managed_user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_platform_admin(user):
        raise HTTPException(403, "Only platform admin")
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    item = db.get(User, managed_user_id)
    if (
        not item
        or item.company_id != company_id
        or item.role not in platform_manageable_roles()
    ):
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=user_not_found",
            status_code=HTTP_303_SEE_OTHER,
        )

    form = await request.form()
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip()
    password = (form.get("password") or "").strip()
    role_raw = (form.get("role") or "").strip().upper()
    if not (name and email):
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=bad_input",
            status_code=HTTP_303_SEE_OTHER,
        )
    if role_raw not in {r.value for r in platform_manageable_roles()}:
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=bad_role",
            status_code=HTTP_303_SEE_OTHER,
        )
    email_owner = db.query(User.id).filter(User.email == email, User.id != item.id).first()
    if email_owner:
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=email_exists",
            status_code=HTTP_303_SEE_OTHER,
        )

    email_changed = (item.email or "").strip() != email
    item.name = name
    item.email = email
    item.role = Role(role_raw)
    capability_flags = normalize_capability_flags(item.role)
    item.show_receipts_accounting_mode = capability_flags["show_receipts_accounting_mode"]
    item.is_assignable_executor = capability_flags["is_assignable_executor"]
    item.can_view_all_tickets = capability_flags["can_view_all_tickets"]
    item.can_create_tickets = capability_flags["can_create_tickets"]
    item.can_close_tickets = capability_flags["can_close_tickets"]
    if password:
        item.password_hash = hash_password(password)
        bump_user_auth_token_version(item)
    if email_changed:
        prepare_user_email_verification(item, force_new_token=True)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=save_failed",
            status_code=HTTP_303_SEE_OTHER,
        )
    if email_changed:
        try:
            send_user_verification_email(request, db, item)
        except EmailDeliveryError:
            logger.exception("Could not send verification email to %s", item.email)
    return RedirectResponse(
        url=f"/web/admin/companies/{company_id}/settings?ok=user_updated",
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/admin/companies/{company_id}/users/{managed_user_id}/delete")
async def web_admin_company_user_delete(
    company_id: int,
    managed_user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_platform_admin(user):
        raise HTTPException(403, "Only platform admin")
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(404, "Company not found")

    item = db.get(User, managed_user_id)
    if (
        not item
        or item.company_id != company_id
        or item.role not in platform_manageable_roles()
    ):
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=user_not_found",
            status_code=HTTP_303_SEE_OTHER,
        )

    # Keep same protection as /web/users: do not delete users with business history.
    has_ticket_refs = db.query(Ticket.id).filter(
        Ticket.company_id == company_id,
        or_(Ticket.created_by == item.id, Ticket.executor_id == item.id, Ticket.archived_by == item.id),
    ).first()
    has_comment_refs = (
        db.query(Comment.id)
        .join(Ticket, Ticket.id == Comment.ticket_id)
        .filter(Ticket.company_id == company_id, Comment.author_id == item.id)
        .first()
    )
    has_attachment_refs = (
        db.query(Attachment.id)
        .join(Ticket, Ticket.id == Attachment.ticket_id)
        .filter(Ticket.company_id == company_id, Attachment.uploader_id == item.id)
        .first()
    )
    has_log_refs = (
        db.query(TicketLog.id)
        .join(Ticket, Ticket.id == TicketLog.ticket_id)
        .filter(Ticket.company_id == company_id, TicketLog.actor_id == item.id)
        .first()
    )
    has_template_refs = db.query(TicketTemplate.id).filter(
        TicketTemplate.company_id == company_id,
        TicketTemplate.default_executor_id == item.id,
    ).first()
    if has_ticket_refs or has_comment_refs or has_attachment_refs or has_log_refs or has_template_refs:
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=delete_blocked",
            status_code=HTTP_303_SEE_OTHER,
        )

    try:
        db.query(UnitAssignment).filter(
            UnitAssignment.company_id == company_id,
            UnitAssignment.user_id == item.id,
        ).delete(synchronize_session=False)
        db.query(TicketWatcher).filter(TicketWatcher.user_id == item.id).delete(synchronize_session=False)
        db.query(TicketWatcher).filter(TicketWatcher.added_by == item.id).update(
            {TicketWatcher.added_by: None},
            synchronize_session=False,
        )
        db.query(PushSubscription).filter(PushSubscription.user_id == item.id).delete(synchronize_session=False)
        db.query(MobileDevice).filter(MobileDevice.user_id == item.id).delete(synchronize_session=False)
        db.query(DeadlineReminderLog).filter(DeadlineReminderLog.user_id == item.id).delete(synchronize_session=False)
        db.query(Notification).filter(Notification.user_id == item.id).delete(synchronize_session=False)
        db.query(RegistrationInvite).filter(
            RegistrationInvite.company_id == company_id,
            RegistrationInvite.used_by == item.id,
        ).update(
            {RegistrationInvite.used_by: None, RegistrationInvite.used_at: None},
            synchronize_session=False,
        )
        db.query(RegistrationInvite).filter(
            RegistrationInvite.company_id == company_id,
            RegistrationInvite.created_by == item.id,
        ).delete(synchronize_session=False)
        db.delete(item)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=delete_failed",
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/web/admin/companies/{company_id}/settings?ok=user_deleted",
        status_code=HTTP_303_SEE_OTHER,
    )


@app.get("/web/pwa-check")
def web_pwa_check(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(
        "pwa_check.html",
        {
            "request": request,
            "user": user,
        },
    )


@app.post("/web/tickets/create")
async def web_create_ticket(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    def create_redirect(error_code: str | None = None) -> RedirectResponse:
        url = "/web?open_create=1"
        if error_code:
            url = f"{url}&create_error={error_code}"
        return RedirectResponse(url=url, status_code=HTTP_303_SEE_OTHER)

    def is_schema_outdated_db_error(exc: Exception) -> bool:
        message = str(exc).lower()
        schema_markers = (
            "no such table",
            "no such column",
            "has no column named",
            "undefined table",
            "undefined column",
        )
        return any(marker in message for marker in schema_markers)

    # ?????????????? ?? ?????????????????????? ?????????? ??????????????????
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)
    if not can_create_company_ticket(user):
        raise HTTPException(403, "Forbidden")

    form = await request.form()

    title = normalize_ticket_title(form.get("title"))
    description = (form.get("description") or "").strip() or None

    if is_ticket_title_too_long(title):
        return create_redirect("title_too_long")

    project_id_raw = (form.get("project_id") or "").strip()
    if not title:
        return create_redirect("missing_required")
    project_id: int | None = None
    if project_id_raw:
        try:
            project_id = int(project_id_raw)
        except ValueError:
            return create_redirect("bad_input")

    if user.role == Role.executor and not getattr(user, "can_view_all_tickets", False):
        executor_id = user.id
    else:
        executor_id_raw = (form.get("executor_id") or "").strip()
        try:
            executor_id = int(executor_id_raw) if executor_id_raw else None
        except ValueError:
            return create_redirect("bad_input")

    ticket_type_id_raw = (form.get("ticket_type_id") or "").strip()
    try:
        ticket_type_id = int(ticket_type_id_raw) if ticket_type_id_raw else None
    except ValueError:
        return create_redirect("bad_input")
    department_id_raw = (form.get("department_id") or "").strip()
    try:
        department_id = int(department_id_raw) if department_id_raw else None
    except ValueError:
        return create_redirect("bad_input")
    target_unit_id_raw = (form.get("target_unit_id") or "").strip()
    target_unit_label_raw = (form.get("target_unit_label") or "").strip()
    try:
        target_unit_id = int(target_unit_id_raw) if target_unit_id_raw else None
    except ValueError:
        return create_redirect("bad_input")
    if ORG_STRUCTURE_V2_ENABLED and target_unit_id is None and target_unit_label_raw:
        target_unit_id = resolve_target_unit_id_from_form_input(db, user.company_id, target_unit_label_raw)
    if ORG_STRUCTURE_V2_ENABLED and target_unit_id is None:
        return create_redirect("target_unit_required")
    if not ORG_STRUCTURE_V2_ENABLED and project_id is None:
        return create_redirect("missing_required")

    watcher_id_values = form.getlist("watcher_user_ids")
    selected_watcher_ids: list[int] = []
    seen_watcher_ids: set[int] = set()
    for raw_value in watcher_id_values:
        value = (raw_value or "").strip()
        if not value:
            continue
        try:
            watcher_id = int(value)
        except ValueError:
            return create_redirect("bad_input")
        if watcher_id in seen_watcher_ids:
            continue
        seen_watcher_ids.add(watcher_id)
        selected_watcher_ids.append(watcher_id)
    if selected_watcher_ids:
        valid_watcher_ids = {
            int(row[0])
            for row in (
                db.query(User.id)
                .filter(
                    User.company_id == user.company_id,
                    User.role.in_([Role.admin, Role.curator, Role.executor]),
                    User.role != Role.platform_admin,
                    User.id.in_(selected_watcher_ids),
                )
                .all()
            )
        }
        if len(valid_watcher_ids) != len(selected_watcher_ids):
            return create_redirect("bad_input")

    deadline = parse_deadline_inputs(form.get("deadline_date"), form.get("deadline_time4"))

    try:
        validate_ticket_links(
            db,
            user.company_id,
            project_id,
            executor_id,
            ticket_type_id,
            target_unit_id,
            None,
            department_id,
        )
        resolved_department_id = resolve_ticket_department_id(
            db,
            company_id=user.company_id,
            ticket_type_id=ticket_type_id,
            department_id=department_id,
        )
        created_tickets: list[Ticket] = []
        if target_unit_id is not None:
            leaf_unit_ids = resolve_scope_leaf_units(db, user.company_id, target_unit_id)
            if not leaf_unit_ids:
                return create_redirect("target_unit_required")
            batch_id = uuid.uuid4().hex
            for leaf_unit_id in leaf_unit_ids:
                resolved_project_id = get_or_create_project_for_org_unit(db, user.company_id, leaf_unit_id)
                resolved_executor_id = (
                    executor_id
                    if executor_id is not None
                    else get_preferred_executor_for_unit(
                        db,
                        user.company_id,
                        leaf_unit_id,
                        department_id=resolved_department_id,
                    )
                )
                t = Ticket(
                    title=title,
                    description=description,
                    deadline=deadline,
                    company_id=user.company_id,
                    executor_id=resolved_executor_id,
                    ticket_type_id=ticket_type_id,
                    department_id=resolved_department_id,
                    target_unit_id=leaf_unit_id,
                    batch_id=batch_id,
                    project_id=resolved_project_id,
                    created_by=user.id,
                )
                db.add(t)
                db.flush()
                ensure_default_ticket_watchers(db, t)
                for watcher_id in selected_watcher_ids:
                    add_ticket_watcher(db, t, watcher_user_id=watcher_id, added_by=user.id)
                add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=LOG_ACTION_CREATED)
                created_tickets.append(t)
        else:
            # ??????????: ???????????? deadline=deadline
            t = Ticket(
                title=title,
                description=description,
                deadline=deadline,
                company_id=user.company_id,
                executor_id=executor_id,
                ticket_type_id=ticket_type_id,
                department_id=resolved_department_id,
                project_id=project_id,
                created_by=user.id,
            )
            db.add(t)
            db.flush()
            ensure_default_ticket_watchers(db, t)
            for watcher_id in selected_watcher_ids:
                add_ticket_watcher(db, t, watcher_user_id=watcher_id, added_by=user.id)
            add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=LOG_ACTION_CREATED)
            created_tickets.append(t)
        db.commit()
    except HTTPException as exc:
        db.rollback()
        detail = str(exc.detail or "").lower()
        if "target unit" in detail:
            return create_redirect("target_unit_required")
        if "title" in detail:
            return create_redirect("title_too_long")
        return create_redirect("bad_input")
    except OperationalError as exc:
        db.rollback()
        logger.exception(
            "Ticket create operational error: user_id=%s company_id=%s role=%s project_id=%s executor_id=%s ticket_type_id=%s target_unit_id=%s",
            user.id,
            user.company_id,
            user.role,
            project_id,
            executor_id,
            ticket_type_id,
            target_unit_id,
        )
        if is_schema_outdated_db_error(exc):
            return create_redirect("schema_outdated")
        return create_redirect("save_failed")
    except SQLAlchemyError:
        db.rollback()
        logger.exception(
            "Ticket create SQLAlchemy error: user_id=%s company_id=%s role=%s project_id=%s executor_id=%s ticket_type_id=%s target_unit_id=%s",
            user.id,
            user.company_id,
            user.role,
            project_id,
            executor_id,
            ticket_type_id,
            target_unit_id,
        )
        return create_redirect("save_failed")
    for created_ticket in created_tickets:
        notify_executor_new_ticket(db, created_ticket, user)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

    return RedirectResponse(url="/web", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/delete")
async def web_delete_ticket(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    t = get_company_ticket_or_404(db, user, ticket_id)
    if not can_delete_ticket(user, t):
        raise HTTPException(403, "Forbidden")

    default_next = "/web/archive" if t.status == TicketStatus.archived else "/web"

    # СѓРґР°Р»СЏРµРј СЃРІСЏР·Р°РЅРЅС‹Рµ Р·Р°РїРёСЃРё РґРѕ СѓРґР°Р»РµРЅРёСЏ Р·Р°СЏРІРєРё (FK РІ Postgres)
    delete_ticket_with_related_data(db, t, remove_files=True)
    db.commit()

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback=default_next)
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/bulk-action")
async def web_tickets_bulk_action(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if is_platform_admin(user):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web")
    action = (form.get("action") or "").strip().lower()
    if action not in TICKET_BULK_ACTION_LABELS:
        return RedirectResponse(
            url=append_query_params(next_url, bulk_error="bad_action"),
            status_code=HTTP_303_SEE_OTHER,
        )

    ticket_ids: list[int] = []
    for raw_ticket_id in form.getlist("ticket_ids"):
        try:
            ticket_id = int((raw_ticket_id or "").strip())
        except (TypeError, ValueError):
            continue
        if ticket_id > 0 and ticket_id not in ticket_ids:
            ticket_ids.append(ticket_id)
    if not ticket_ids:
        return RedirectResponse(
            url=append_query_params(next_url, bulk_error="no_selection"),
            status_code=HTTP_303_SEE_OTHER,
        )

    tickets = (
        db.query(Ticket)
        .filter(Ticket.company_id == user.company_id, Ticket.id.in_(ticket_ids))
        .all()
    )
    tickets_by_id = {int(ticket.id): ticket for ticket in tickets}
    company = db.get(Company, user.company_id) if user.company_id is not None else None
    notifications: list[tuple[Ticket, TicketStatus]] = []
    done_count = 0
    skipped_count = 0

    try:
        for ticket_id in ticket_ids:
            ticket = tickets_by_id.get(ticket_id)
            if ticket is None or not can_access_ticket(user, ticket):
                skipped_count += 1
                continue

            if action == "archive":
                if not can_archive_ticket(user, ticket):
                    skipped_count += 1
                    continue
                old_status = ticket.status
                archive_ticket(db, ticket, actor_id=user.id, company=company)
                notifications.append((ticket, old_status))
                done_count += 1
                continue

            if action == "delete":
                if not can_delete_ticket(user, ticket):
                    skipped_count += 1
                    continue
                delete_ticket_with_related_data(db, ticket, remove_files=True)
                done_count += 1
                continue

            if action == "restore":
                if not can_restore_ticket(user, ticket):
                    skipped_count += 1
                    continue
                old_status = ticket.status
                restore_ticket_from_archive(db, ticket, actor_id=user.id)
                notifications.append((ticket, old_status))
                done_count += 1
                continue

            if action in {"legal_hold_on", "legal_hold_off"}:
                if not can_manage_ticket_legal_hold(user, ticket):
                    skipped_count += 1
                    continue
                hold_enabled = action == "legal_hold_on"
                if bool(ticket.is_legal_hold) == hold_enabled:
                    skipped_count += 1
                    continue
                ticket.is_legal_hold = hold_enabled
                if not hold_enabled:
                    if ticket.retention_days is None:
                        ticket.retention_days = resolve_ticket_archive_retention_days(db, ticket, company)
                    if ticket.archived_at is None:
                        ticket.archived_at = local_now()
                    ticket.delete_at = ticket.archived_at + timedelta(days=ticket.retention_days)
                add_ticket_log(
                    db,
                    ticket_id=ticket.id,
                    actor_id=user.id,
                    action="установлен legal hold" if hold_enabled else "снят legal hold",
                )
                done_count += 1
                continue

            skipped_count += 1

        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=append_query_params(next_url, bulk_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )

    for ticket, old_status in notifications:
        notify_curators_status_changed(db, ticket, actor=user, old_status=old_status)
    if notifications:
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()

    return RedirectResponse(
        url=append_query_params(
            next_url,
            bulk_ok=True,
            bulk_action=action,
            bulk_done=done_count,
            bulk_skipped=skipped_count,
        ),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/tickets/{ticket_id}/status")
async def web_update_status(ticket_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = get_company_ticket_or_404(db, user, ticket_id)

    # РїСЂР°РІР°: РєСѓСЂР°С‚РѕСЂ РІСЃРµРіРґР°, РёСЃРїРѕР»РЅРёС‚РµР»СЊ вЂ” РµСЃР»Рё Р·Р°СЏРІРєР° РµРіРѕ (СЃРѕР·РґР°Р» РёР»Рё РЅР°Р·РЅР°С‡РµРЅР°)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")

    form = await request.form()
    status_raw = (form.get("status") or "").strip()
    if not status_raw:
        raise HTTPException(400, "Missing status")
    if status_raw == TicketStatus.archived.value:
        raise HTTPException(400, "Use archive action")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket must be restored first")

    old_status = t.status
    t.status = TicketStatus(status_raw)
    if t.status != old_status:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=ticket_status_change_log_action(old_status, t.status))
    db.commit()
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()

    now = local_now()
    is_overdue = bool(t.deadline and t.deadline < now and t.status not in FINAL_TICKET_STATUSES)
    company = db.get(Company, user.company_id) if user.company_id is not None else None
    deadline_soon_warning_minutes = get_company_deadline_soon_warning_minutes(company)
    is_deadline_soon = bool(
        t.deadline
        and not is_overdue
        and t.status not in FINAL_TICKET_STATUSES
        and t.deadline <= now + timedelta(minutes=deadline_soon_warning_minutes)
    )

    # РµСЃР»Рё Р·Р°РїСЂРѕСЃ РїСЂРёС€С‘Р» С‡РµСЂРµР· fetch (Accept: application/json) вЂ” РІРµСЂРЅС‘Рј JSON
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return JSONResponse(
            {
                "ok": True,
                "ticket_id": t.id,
                "status": t.status.value,
                "is_overdue": is_overdue,
                "is_deadline_soon": is_deadline_soon,
            }
        )

    # РёРЅР°С‡Рµ РѕР±С‹С‡РЅС‹Р№ СЃС†РµРЅР°СЂРёР№ (РїРµСЂРµР·Р°РіСЂСѓР·РєР°)
    return RedirectResponse(url="/web", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/quick-action")
async def web_ticket_quick_action(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    t = get_company_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")

    form = await request.form()
    action = (form.get("action") or "").strip()
    default_next = "/web/archive" if t.status == TicketStatus.archived else "/web"
    next_url = safe_next(form.get("next"), fallback=default_next)

    old_status = t.status
    old_executor_id = t.executor_id
    changed = False

    if action == "take_in_work":
        if not can_take_ticket_in_work(user, t):
            raise HTTPException(403, "Forbidden")
        if t.executor_id != user.id:
            t.executor_id = user.id
            add_ticket_log(
                db,
                ticket_id=t.id,
                actor_id=user.id,
                action=ticket_field_change_log_action(
                    "исполнителя",
                    _ticket_user_name(db, old_executor_id),
                    _ticket_user_name(db, t.executor_id),
                ),
            )
            changed = True
        if t.status != TicketStatus.in_progress:
            t.status = TicketStatus.in_progress
            add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=ticket_status_change_log_action(old_status, t.status))
            changed = True
    elif action == "complete":
        if not can_close_ticket(user, t):
            raise HTTPException(403, "Forbidden")
        if t.status != TicketStatus.in_progress:
            return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)
        t.status = TicketStatus.done
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=ticket_status_change_log_action(old_status, t.status))
        changed = True
    else:
        raise HTTPException(400, "Unknown quick action")

    if not changed:
        return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)

    ensure_default_ticket_watchers(db, t)
    db.commit()
    db.refresh(t)

    notify_executor_reassigned(db, t, old_executor_id=old_executor_id, actor=user)
    if t.status != old_status:
        notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()

    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/archive")
async def web_archive_ticket(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    t = get_company_ticket_or_404(db, user, ticket_id)
    if not can_archive_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web")
    if t.status == TicketStatus.archived:
        return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)
    company = db.get(Company, user.company_id) if user.company_id is not None else None
    old_status = t.status
    archive_ticket(db, t, actor_id=user.id, company=company)
    db.commit()
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/restore")
async def web_restore_ticket(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    t = get_company_ticket_or_404(db, user, ticket_id)
    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web/archive")
    old_status = t.status
    restore_ticket_from_archive(db, t, actor_id=user.id)
    db.commit()
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/legal-hold")
async def web_ticket_legal_hold(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    t = get_company_ticket_or_404(db, user, ticket_id)
    if t.status != TicketStatus.archived:
        raise HTTPException(400, "Legal hold works only for archived tickets")
    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web/archive")
    hold_enabled = (form.get("is_legal_hold") or "").strip() == "1"
    t.is_legal_hold = hold_enabled
    if not hold_enabled:
        if t.retention_days is None:
            company = db.get(Company, user.company_id) if user.company_id is not None else None
            t.retention_days = resolve_ticket_archive_retention_days(db, t, company)
        if t.archived_at is None:
            t.archived_at = local_now()
        t.delete_at = t.archived_at + timedelta(days=t.retention_days)
    add_ticket_log(
        db,
        ticket_id=t.id,
        actor_id=user.id,
        action="установлен legal hold" if hold_enabled else "снят legal hold",
    )
    db.commit()
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/watchers/self")
async def web_add_self_watcher(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    t = get_company_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    form = await request.form()
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")
    add_ticket_watcher(db, t, watcher_user_id=user.id, added_by=user.id)
    ensure_default_ticket_watchers(db, t)
    db.commit()
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/comments")
async def web_add_comment(ticket_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    form = await request.form()
    text = (form.get("text") or "").strip()
    photo_uploads = normalize_optional_uploaded_files(list(form.getlist("photos")))
    voice_uploads = normalize_optional_uploaded_files(list(form.getlist("voice_messages")))
    attachment_uploads = normalize_optional_uploaded_files(list(form.getlist("attachments")))
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}?tab=overview")

    t = get_company_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    stored_paths: list[str] = []
    try:
        comment, media_items, stored_paths = await create_comment_with_media_async(
            db=db,
            ticket_id=ticket_id,
            author_id=user.id,
            text=text,
            photos=photo_uploads,
            voice_messages=voice_uploads,
            attachments=attachment_uploads,
        )
        db.commit()
        db.refresh(comment)
        for item in media_items:
            db.refresh(item)
    except HTTPException as exc:
        db.rollback()
        for stored_path in stored_paths:
            delete_stored_file(stored_path)
        error_code = "too_large" if exc.status_code == 413 else "invalid"
        return RedirectResponse(
            url=f"/web/tickets/{ticket_id}?tab=overview&comment_error={error_code}",
            status_code=HTTP_303_SEE_OTHER,
        )
    except SQLAlchemyError:
        db.rollback()
        for stored_path in stored_paths:
            delete_stored_file(stored_path)
        return RedirectResponse(
            url=f"/web/tickets/{ticket_id}?tab=overview&comment_error=save_failed",
            status_code=HTTP_303_SEE_OTHER,
        )

    try:
        notify_comment_added(
            db,
            ticket=t,
            author=user,
            comment_text=text,
            photo_count=sum(1 for item in media_items if item.media_kind == "photo"),
            voice_count=sum(1 for item in media_items if item.media_kind == "voice"),
            file_count=sum(1 for item in media_items if item.media_kind == "file"),
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/comments/{comment_id}/delete")
async def web_delete_comment(
    comment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    comment = db.get(Comment, comment_id)
    if not comment:
        raise HTTPException(404, "Comment not found")
    ticket = get_company_ticket_or_404(db, user, comment.ticket_id)
    if not can_access_ticket(user, ticket):
        raise HTTPException(403, "Forbidden")
    if ticket.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")
    if not can_delete_comment(user, comment):
        raise HTTPException(403, "Forbidden")

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket.id}?tab=overview")
    media_items = db.query(CommentMedia).filter(CommentMedia.comment_id == comment.id).all()
    for item in media_items:
        delete_stored_file(item.file_path)
    db.query(CommentMedia).filter(CommentMedia.comment_id == comment.id).delete(synchronize_session=False)
    db.delete(comment)
    db.commit()
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/attachments")
async def web_add_attachment(ticket_id: int, request: Request, files: list[UploadFile] = File(...),
                             db: Session = Depends(get_db), user: User = Depends(get_current_user)):

    t = get_company_ticket_or_404(db, user, ticket_id)

    # Access rules match comments and status updates.
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    saved_attachments: list[Attachment] = []
    for upload in normalize_uploaded_files(files):
        safe_name = make_safe_upload_name(upload.filename, ticket_id=ticket_id)
        object_key = build_attachment_object_key(safe_name)
        stored_path, file_hash, file_size = await store_upload_file_to_storage_async(upload, object_key)
        attachment = create_ticket_attachment_record(
            db=db,
            ticket_id=ticket_id,
            uploader_id=user.id,
            upload=upload,
            stored_path=stored_path,
            file_hash=file_hash,
            file_size=file_size,
        )
        saved_attachments.append(attachment)

    db.commit()
    for attachment in saved_attachments:
        notify_curators_executor_act(db, ticket=t, uploader=user, original_name=attachment.original_name)
    db.commit()

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/attachments/{attachment_id}/delete")
async def web_delete_attachment(
    attachment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    attachment = db.get(Attachment, attachment_id)
    if not attachment:
        raise HTTPException(404, "Attachment not found")
    ticket = get_company_ticket_or_404(db, user, attachment.ticket_id)
    if not can_access_ticket(user, ticket):
        raise HTTPException(403, "Forbidden")
    if ticket.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    can_delete_file = bool(is_manager(user) or (user.role == Role.executor and attachment.uploader_id == user.id))
    if not can_delete_file:
        raise HTTPException(403, "Forbidden")

    delete_stored_file(attachment.file_path)

    db.delete(attachment)
    add_ticket_log(db, ticket_id=ticket.id, actor_id=user.id, action=LOG_ACTION_FILE_DELETED)
    db.commit()

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket.id}")
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.get("/web/tickets/{ticket_id}/edit")
def web_edit_ticket_page(ticket_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = get_company_ticket_or_404(db, user, ticket_id)
    if t.status == TicketStatus.archived:
        return RedirectResponse(url=f"/web/tickets/{ticket_id}", status_code=HTTP_303_SEE_OTHER)

    if not can_edit_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    can_edit_full = can_edit_ticket(user, t)


    projects = (
        db.query(Project.id, Project.name)
        .filter(Project.company_id == user.company_id)
        .order_by(Project.id.desc())
        .all()
    )
    executors = (
        query_assignable_company_users(db, user.company_id)
        .order_by(User.id.desc())
        .all()
    )
    ticket_types = (
        db.query(TicketType.id, TicketType.name, TicketType.is_active, TicketType.department_id)
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.id.desc())
        .all()
    )
    departments = (
        db.query(Department.id, Department.name, Department.is_active)
        .filter(Department.company_id == user.company_id)
        .order_by(Department.name.asc(), Department.id.asc())
        .all()
    )
    next_url = request.query_params.get("next") or f"/web/tickets/{ticket_id}"
    next_url = safe_next(next_url, fallback=f"/web/tickets/{ticket_id}")
    error_code = (request.query_params.get("error") or "").strip().lower()
    if error_code == "title_too_long":
        error_message = f"РќР°Р·РІР°РЅРёРµ СЃР»РёС€РєРѕРј РґР»РёРЅРЅРѕРµ. РњР°РєСЃРёРјСѓРј: {MAX_TICKET_TITLE_LEN} СЃРёРјРІРѕР»РѕРІ."
    else:
        error_message = None


    # РїРѕРґРіРѕС‚РѕРІРёРј РґР°С‚Сѓ/РІСЂРµРјСЏ РґР»СЏ С„РѕСЂРјС‹
    deadline_date = None
    deadline_time4 = None
    if t.deadline:
        # deadline С…СЂР°РЅРёС‚СЃСЏ РІ Р»РѕРєР°Р»СЊРЅРѕРј РІСЂРµРјРµРЅРё, Р±РµР· UTC-СЃРјРµС‰РµРЅРёСЏ
        deadline_date = t.deadline.strftime("%Y-%m-%d")
        deadline_time4 = t.deadline.strftime("%H%M")

    return templates.TemplateResponse(
        "ticket_edit.html",
        {
            "request": request,
            "user": user,
            "t": t,
            "projects": projects,
            "executors": executors,
            "ticket_types": ticket_types,
            "departments": departments,
            "can_edit_full": can_edit_full,
            "deadline_date": deadline_date,
            "deadline_time4": deadline_time4,
            "error": error_message,
            "max_ticket_title_len": MAX_TICKET_TITLE_LEN,
            "next_url": next_url,
            "org_v2_enabled": ORG_STRUCTURE_V2_ENABLED,
        },
    )


@app.post("/web/tickets/{ticket_id}/edit")
async def web_ticket_edit_save(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    t = get_company_ticket_or_404(db, user, ticket_id)

    if not can_edit_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    can_edit_full = is_manager(user)
    can_change_status = can_close_ticket(user, t)
    form = await request.form()
    status_raw = (form.get("status") or "").strip()
    if status_raw == TicketStatus.archived.value:
        raise HTTPException(400, "Use archive action")
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")

    title = normalize_ticket_title(form.get("title"))
    description = (form.get("description") or "").strip()
    project_id_raw = (form.get("project_id") or "").strip()
    executor_id_raw = (form.get("executor_id") or "").strip()
    ticket_type_id_raw = (form.get("ticket_type_id") or "").strip()
    department_id_raw = (form.get("department_id") or "").strip()

    if is_ticket_title_too_long(title):
        edit_url = f"/web/tickets/{ticket_id}/edit?error=title_too_long&next={quote(next_url, safe='')}"
        return RedirectResponse(url=edit_url, status_code=HTTP_303_SEE_OTHER)

    old_deadline = t.deadline
    old_executor_id = t.executor_id
    old_project_id = t.project_id
    old_ticket_type_id = t.ticket_type_id
    old_department_id = t.department_id
    old_status = t.status

    if status_raw and can_change_status:
        try:
            t.status = TicketStatus(status_raw)
        except ValueError:
            pass

    if title:
        t.title = title
    t.description = description

    if can_edit_full:
        try:
            project_id_candidate = int(project_id_raw)
        except ValueError:
            project_id_candidate = None

        try:
            executor_id_candidate = int(executor_id_raw) if executor_id_raw else None
        except ValueError:
            executor_id_candidate = None

        try:
            ticket_type_id_candidate = int(ticket_type_id_raw) if ticket_type_id_raw else None
        except ValueError:
            ticket_type_id_candidate = None
        try:
            department_id_candidate = int(department_id_raw) if department_id_raw else None
        except ValueError:
            department_id_candidate = None

        validate_ticket_links(
            db,
            user.company_id,
            project_id_candidate,
            executor_id_candidate,
            ticket_type_id_candidate,
            None,
            None,
            department_id_candidate,
        )
        resolved_department_id = resolve_ticket_department_id(
            db,
            company_id=user.company_id,
            ticket_type_id=ticket_type_id_candidate,
            department_id=department_id_candidate,
        )

        if project_id_candidate is not None:
            t.project_id = project_id_candidate
        t.executor_id = executor_id_candidate
        t.ticket_type_id = ticket_type_id_candidate
        t.department_id = resolved_department_id

    # Deadline (same parsing logic as create form)
    t.deadline = parse_deadline_inputs(form.get("deadline_date"), form.get("deadline_time4"))

    has_specific_log = False
    if t.deadline != old_deadline:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u0441\u0440\u043e\u043a\u0430",
                _ticket_deadline_text(old_deadline),
                _ticket_deadline_text(t.deadline),
            ),
        )
        has_specific_log = True
    if t.executor_id != old_executor_id:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u0438\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044f",
                _ticket_user_name(db, old_executor_id),
                _ticket_user_name(db, t.executor_id),
            ),
        )
        has_specific_log = True
    if t.project_id != old_project_id:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u043f\u0440\u043e\u0435\u043a\u0442\u0430",
                _ticket_project_name(db, old_project_id),
                _ticket_project_name(db, t.project_id),
            ),
        )
        has_specific_log = True

    if t.ticket_type_id != old_ticket_type_id:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u0442\u0438\u043f\u0430 \u0437\u0430\u044f\u0432\u043a\u0438",
                _ticket_type_name(db, old_ticket_type_id),
                _ticket_type_name(db, t.ticket_type_id),
            ),
        )
        has_specific_log = True
    if t.department_id != old_department_id:
        add_ticket_log(
            db,
            ticket_id=t.id,
            actor_id=user.id,
            action=ticket_field_change_log_action(
                "\u043e\u0442\u0434\u0435\u043b\u0430",
                _department_name(db, old_department_id),
                _department_name(db, t.department_id),
            ),
        )
        has_specific_log = True
    if t.status != old_status:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=ticket_status_change_log_action(old_status, t.status))
        has_specific_log = True

    if not has_specific_log:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action=LOG_ACTION_CHANGED)

    ensure_default_ticket_watchers(db, t)
    db.commit()          # вњ… Р±РµР· СЌС‚РѕРіРѕ РЅРµ СЃРѕС…СЂР°РЅРёС‚СЃСЏ
    db.refresh(t)
    notify_executor_reassigned(db, t, old_executor_id=old_executor_id, actor=user)
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()

    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


# ====== WEB: Receipts ======
@app.get("/web/receipts")
def web_receipts(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    mode: str | None = None,
    status_filter: str | None = None,
    project_id: str | None = None,
    card_id: str | None = None,
    employee_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    edit_id: str | None = None,
):
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)

    can_view_accounting_mode = bool(user.show_receipts_accounting_mode)
    default_receipts_mode = "accounting" if user.role in (Role.admin, Role.curator) else "field"
    mode_value = (mode or "").strip().lower()
    if mode_value not in {"field", "accounting"}:
        mode_value = default_receipts_mode
    if not can_view_accounting_mode:
        mode_value = "field"

    def parse_int(raw: str | None) -> int | None:
        value = (raw or "").strip()
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    project_id_int = parse_int(project_id)
    card_id_int = parse_int(card_id)
    employee_id_int = parse_int(employee_id)
    date_from_value = parse_receipt_date(date_from)
    date_to_value = parse_receipt_date(date_to)
    q_value = (q or "").strip()
    edit_id_int = parse_int(edit_id)

    projects = (
        db.query(Project.id, Project.name)
        .filter(Project.company_id == user.company_id)
        .order_by(Project.name.asc())
        .all()
    )
    cards = (
        db.query(PaymentCard.id, PaymentCard.name, PaymentCard.is_active)
        .filter(PaymentCard.company_id == user.company_id, PaymentCard.owner_user_id == user.id)
        .order_by(PaymentCard.name.asc())
        .all()
    )
    preferred_card_id = None
    if user.preferred_payment_card_id is not None:
        for card in cards:
            if int(card.id) == int(user.preferred_payment_card_id) and bool(card.is_active):
                preferred_card_id = int(card.id)
                break
    employees = (
        db.query(User.id, User.name)
        .filter(User.company_id == user.company_id, User.role != Role.platform_admin)
        .order_by(User.name.asc())
        .all()
    )

    receipts = (
        build_receipts_query(
            db,
            user,
            status_filter=status_filter,
            project_id=project_id_int,
            card_id=card_id_int,
            employee_id=employee_id_int,
            date_from_value=date_from_value,
            date_to_value=date_to_value,
            q=q_value,
        )
        .limit(300)
        .all()
    )
    receipt_ids = [r.id for r in receipts]
    files = (
        db.query(ReceiptFile)
        .filter(ReceiptFile.receipt_id.in_(receipt_ids))
        .order_by(ReceiptFile.id.asc())
        .all()
        if receipt_ids
        else []
    )
    files_by_receipt: dict[int, list[ReceiptFile]] = {}
    for file_row in files:
        files_by_receipt.setdefault(file_row.receipt_id, []).append(file_row)

    projects_by_id = {int(row[0]): row[1] for row in projects}
    cards_by_id = {int(row[0]): row[1] for row in cards}
    visible_card_ids = {int(r.card_id) for r in receipts if getattr(r, "card_id", None) is not None}
    cards_for_display = list(cards)
    if visible_card_ids:
        cards_for_display = (
            db.query(PaymentCard.id, PaymentCard.name, PaymentCard.is_active)
            .filter(PaymentCard.company_id == user.company_id, PaymentCard.id.in_(visible_card_ids))
            .all()
        )
    cards_last4_by_id: dict[int, str] = {}
    for row in cards_for_display:
        card_id_value = int(row[0])
        card_name = str(row[1] or "")
        only_digits = re.sub(r"\D+", "", card_name)
        cards_last4_by_id[card_id_value] = only_digits[-4:] if len(only_digits) >= 4 else card_name or f"#{card_id_value}"
    users_by_id = {int(row[0]): row[1] for row in employees}
    status_options = [s.value for s in ReceiptStatus]

    ok = (request.query_params.get("ok") or "").strip().lower()
    err = (request.query_params.get("err") or "").strip().lower()
    if ok not in {"created", "card_created", "status_updated", "bulk_updated", "updated", "deleted"}:
        ok = ""
    if err not in {"missing_required", "bad_links", "bad_amount", "missing_files", "save_failed", "card_exists", "bad_status"}:
        err = ""

    return templates.TemplateResponse(
        "receipts.html",
        {
            "request": request,
            "user": user,
            "mode": mode_value,
            "receipts": receipts,
            "files_by_receipt": files_by_receipt,
            "projects": projects,
            "cards": cards,
            "employees": employees,
            "projects_by_id": projects_by_id,
            "cards_by_id": cards_by_id,
            "cards_last4_by_id": cards_last4_by_id,
            "users_by_id": users_by_id,
            "status_options": status_options,
            "status_filter": status_filter or "",
            "project_id_filter": project_id_int if project_id_int is not None else "",
            "card_id_filter": card_id_int if card_id_int is not None else "",
            "employee_id_filter": employee_id_int if employee_id_int is not None else "",
            "date_from_filter": date_from_value.isoformat() if date_from_value else "",
            "date_to_filter": date_to_value.isoformat() if date_to_value else "",
            "q_filter": q_value,
            "edit_id": edit_id_int if edit_id_int is not None else 0,
            "ok": ok,
            "err": err,
            "can_manage_cards": is_manager(user),
            "can_manage_status": is_manager(user),
            "can_view_accounting_mode": can_view_accounting_mode,
            "preferred_card_id": preferred_card_id,
        },
    )


@app.post("/web/payment-cards/create")
async def web_payment_cards_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)
    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    name = (form.get("name") or "").strip()
    if not name:
        return RedirectResponse(
            url=build_settings_url(section, card_create_error="missing_required"),
            status_code=HTTP_303_SEE_OTHER,
        )
    exists = (
        db.query(PaymentCard.id)
        .filter(
            PaymentCard.company_id == user.company_id,
            PaymentCard.owner_user_id == user.id,
            func.lower(PaymentCard.name) == name.lower(),
        )
        .first()
    )
    if exists:
        return RedirectResponse(
            url=build_settings_url(section, card_create_error="card_exists"),
            status_code=HTTP_303_SEE_OTHER,
        )
    db.add(PaymentCard(company_id=user.company_id, owner_user_id=user.id, name=name, is_active=True))
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, card_create_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=build_settings_url(section, card_created=True),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/payment-cards/{card_id}/delete")
async def web_payment_cards_delete(
    card_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)
    form = await request.form()
    section = normalize_settings_section(form.get("section") or request.query_params.get("section"))
    card = db.get(PaymentCard, card_id)
    if not card or card.company_id != user.company_id or card.owner_user_id != user.id:
        return RedirectResponse(
            url=build_settings_url(section, card_delete_error="not_found"),
            status_code=HTTP_303_SEE_OTHER,
        )

    used_in_receipts = (
        db.query(Receipt.id)
        .filter(Receipt.company_id == user.company_id, Receipt.card_id == card_id)
        .first()
    )
    used_in_user_defaults = (
        db.query(User.id)
        .filter(User.company_id == user.company_id, User.preferred_payment_card_id == card_id)
        .first()
    )
    if used_in_receipts or used_in_user_defaults:
        return RedirectResponse(
            url=build_settings_url(section, card_delete_error="in_use"),
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        db.delete(card)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=build_settings_url(section, card_delete_error="save_failed"),
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=build_settings_url(section, card_deleted=True),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/receipts/create")
async def web_receipts_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)
    form = await request.form()
    project_id_raw = (form.get("project_id") or "").strip()
    card_id_raw = (form.get("card_id") or "").strip()
    comment = (form.get("comment") or "").strip()
    category = (form.get("category") or "").strip() or None
    supplier = (form.get("supplier") or "").strip() or None
    amount = parse_receipt_amount(form.get("amount"))
    receipt_date = parse_receipt_date(form.get("receipt_date"))
    uploads = [
        item
        for item in form.getlist("files")
        if hasattr(item, "filename") and ((getattr(item, "filename", "") or "").strip())
    ]

    if not project_id_raw or not card_id_raw:
        return RedirectResponse(url="/web/receipts?err=missing_required", status_code=HTTP_303_SEE_OTHER)
    if not uploads:
        return RedirectResponse(url="/web/receipts?err=missing_files&mode=field", status_code=HTTP_303_SEE_OTHER)
    if (form.get("amount") or "").strip() and amount is None:
        return RedirectResponse(url="/web/receipts?err=bad_amount&mode=field", status_code=HTTP_303_SEE_OTHER)

    try:
        project_id = int(project_id_raw)
        card_id = int(card_id_raw)
    except ValueError:
        return RedirectResponse(url="/web/receipts?err=bad_links", status_code=HTTP_303_SEE_OTHER)

    project_row = (
        db.query(Project.id, Project.name)
        .filter(Project.id == project_id, Project.company_id == user.company_id)
        .first()
    )
    card_row = (
        db.query(PaymentCard.id, PaymentCard.name)
        .filter(
            PaymentCard.id == card_id,
            PaymentCard.company_id == user.company_id,
            PaymentCard.owner_user_id == user.id,
            PaymentCard.is_active.is_(True),
        )
        .first()
    )
    if not project_row or not card_row:
        return RedirectResponse(url="/web/receipts?err=bad_links", status_code=HTTP_303_SEE_OTHER)
    project_name = str(project_row[1] or "")
    card_name = str(card_row[1] or "")

    written_paths: list[str] = []
    try:
        receipt = Receipt(
            company_id=user.company_id,
            project_id=project_id,
            card_id=card_id,
            created_by=user.id,
            status=ReceiptStatus.new,
            comment=comment or "",
            amount=amount,
            receipt_date=receipt_date,
            category=category,
            supplier=supplier,
        )
        db.add(receipt)
        db.flush()
        for upload in uploads:
            safe_name = make_safe_upload_name(upload.filename, ticket_id=receipt.id)
            object_key = build_receipt_object_key(safe_name)
            stored_path, file_hash, file_size = await store_upload_file_to_storage_async(upload, object_key)
            written_paths.append(stored_path)
            display_name = build_receipt_original_name(
                receipt_date_value=receipt.receipt_date,
                card_name=card_name,
                project_name=project_name,
                source_filename=upload.filename,
                fallback_card_id=card_id,
            )
            db.add(
                ReceiptFile(
                    receipt_id=receipt.id,
                    uploader_id=user.id,
                    file_path=stored_path,
                    original_name=display_name[:255] or None,
                    file_size_bytes=file_size,
                    file_sha256=file_hash,
                )
            )
        notify_receipt_created(db=db, receipt=receipt, actor=user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        for path in written_paths:
            delete_stored_file(path)
        return RedirectResponse(url="/web/receipts?err=save_failed", status_code=HTTP_303_SEE_OTHER)

    return RedirectResponse(url="/web/receipts?ok=created&mode=field", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/receipts/{receipt_id}/status")
async def web_receipt_update_status(
    receipt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    receipt = get_company_receipt_or_404(db, user, receipt_id)
    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web/receipts")
    status_raw = (form.get("status") or "").strip()
    try:
        new_status = ReceiptStatus(status_raw)
    except ValueError:
        return RedirectResponse(url="/web/receipts?err=bad_status", status_code=HTTP_303_SEE_OTHER)
    receipt.status = new_status
    receipt.updated_at = datetime.utcnow()
    if new_status in (ReceiptStatus.accepted, ReceiptStatus.rejected):
        receipt.processed_at = datetime.utcnow()
        receipt.processed_by = user.id
    else:
        receipt.processed_at = None
        receipt.processed_by = None
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/receipts?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url=f"{next_url}", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/receipts/{receipt_id}/edit")
async def web_receipt_edit(
    receipt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)
    receipt = get_company_receipt_or_404(db, user, receipt_id)
    if not can_access_receipt(user, receipt):
        raise HTTPException(403, "Forbidden")
    if receipt.created_by != user.id:
        raise HTTPException(403, "Forbidden")

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web/receipts?mode=field")
    success_url = f"{next_url}&ok=updated" if "?" in next_url else f"{next_url}?ok=updated"
    project_id_raw = (form.get("project_id") or "").strip()
    card_id_raw = (form.get("card_id") or "").strip()
    comment = (form.get("comment") or "").strip()
    category = (form.get("category") or "").strip() or None
    supplier = (form.get("supplier") or "").strip() or None
    amount = parse_receipt_amount(form.get("amount"))
    receipt_date = parse_receipt_date(form.get("receipt_date"))

    if not project_id_raw or not card_id_raw:
        return RedirectResponse(url="/web/receipts?err=missing_required", status_code=HTTP_303_SEE_OTHER)
    if (form.get("amount") or "").strip() and amount is None:
        return RedirectResponse(url="/web/receipts?err=bad_amount", status_code=HTTP_303_SEE_OTHER)
    try:
        project_id = int(project_id_raw)
        card_id = int(card_id_raw)
    except ValueError:
        return RedirectResponse(url="/web/receipts?err=bad_links", status_code=HTTP_303_SEE_OTHER)

    project_exists = db.query(Project.id).filter(Project.id == project_id, Project.company_id == user.company_id).first()
    card_exists = (
        db.query(PaymentCard.id)
        .filter(
            PaymentCard.id == card_id,
            PaymentCard.company_id == user.company_id,
            PaymentCard.owner_user_id == user.id,
            PaymentCard.is_active.is_(True),
        )
        .first()
    )
    if not project_exists or not card_exists:
        return RedirectResponse(url="/web/receipts?err=bad_links", status_code=HTTP_303_SEE_OTHER)

    receipt.project_id = project_id
    receipt.card_id = card_id
    receipt.comment = comment or ""
    receipt.amount = amount
    receipt.receipt_date = receipt_date
    receipt.category = category
    receipt.supplier = supplier
    receipt.updated_at = datetime.utcnow()
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/receipts?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url=success_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/receipts/{receipt_id}/delete")
async def web_receipt_delete(
    receipt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)
    receipt = get_company_receipt_or_404(db, user, receipt_id)
    if not can_access_receipt(user, receipt):
        raise HTTPException(403, "Forbidden")
    if receipt.created_by != user.id:
        raise HTTPException(403, "Forbidden")

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web/receipts?mode=field")
    success_url = f"{next_url}&ok=deleted" if "?" in next_url else f"{next_url}?ok=deleted"
    files = db.query(ReceiptFile).filter(ReceiptFile.receipt_id == receipt.id).all()
    for file_row in files:
        delete_stored_file(file_row.file_path)
    db.query(ReceiptFile).filter(ReceiptFile.receipt_id == receipt.id).delete(synchronize_session=False)
    db.delete(receipt)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/receipts?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url=success_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/receipts/delete/bulk")
async def web_receipt_bulk_delete(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web/receipts?mode=accounting")
    success_url = f"{next_url}&ok=deleted" if "?" in next_url else f"{next_url}?ok=deleted"

    receipt_ids: list[int] = []
    for raw_id in form.getlist("receipt_ids"):
        try:
            receipt_ids.append(int((raw_id or "").strip()))
        except (TypeError, ValueError):
            continue
    if not receipt_ids:
        return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)

    receipts = (
        db.query(Receipt)
        .filter(Receipt.company_id == user.company_id, Receipt.id.in_(receipt_ids))
        .all()
    )
    if not receipts:
        return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)

    found_ids = [r.id for r in receipts]
    files = db.query(ReceiptFile).filter(ReceiptFile.receipt_id.in_(found_ids)).all()
    for file_row in files:
        delete_stored_file(file_row.file_path)
    db.query(ReceiptFile).filter(ReceiptFile.receipt_id.in_(found_ids)).delete(synchronize_session=False)
    db.query(Receipt).filter(Receipt.id.in_(found_ids)).delete(synchronize_session=False)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/receipts?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url=success_url, status_code=HTTP_303_SEE_OTHER)


@app.post("/web/receipts/status/bulk")
async def web_receipt_bulk_status(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web/receipts")
    status_raw = (form.get("status") or "").strip()
    try:
        new_status = ReceiptStatus(status_raw)
    except ValueError:
        return RedirectResponse(url="/web/receipts?err=bad_status", status_code=HTTP_303_SEE_OTHER)

    receipt_ids: list[int] = []
    for raw_id in form.getlist("receipt_ids"):
        try:
            receipt_ids.append(int((raw_id or "").strip()))
        except (TypeError, ValueError):
            continue
    if not receipt_ids:
        return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)

    receipts = (
        db.query(Receipt)
        .filter(Receipt.company_id == user.company_id, Receipt.id.in_(receipt_ids))
        .all()
    )
    now = datetime.utcnow()
    for receipt in receipts:
        receipt.status = new_status
        receipt.updated_at = now
        if new_status in (ReceiptStatus.accepted, ReceiptStatus.rejected):
            receipt.processed_at = now
            receipt.processed_by = user.id
        else:
            receipt.processed_at = None
            receipt.processed_by = None
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/receipts?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.get("/web/receipt-files/{file_id}")
def web_receipt_file_download(
    file_id: int,
    download: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    file_row = db.get(ReceiptFile, file_id)
    if not file_row:
        raise HTTPException(404, "Receipt file not found")
    receipt = get_company_receipt_or_404(db, user, file_row.receipt_id)
    if not can_access_receipt(user, receipt):
        raise HTTPException(403, "Forbidden")
    display_name = ((file_row.original_name or "").strip() or get_storage_basename(file_row.file_path) or "file")[:255]
    disposition = "attachment" if str(download or "").strip() == "1" else "inline"
    return serve_stored_file_response(file_row.file_path, display_name, disposition, "File not found")


@app.get("/web/receipts/export.xlsx")
def web_receipts_export_xlsx(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = None,
    project_id: str | None = None,
    card_id: str | None = None,
    employee_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
):
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)

    def parse_int(raw: str | None) -> int | None:
        value = (raw or "").strip()
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    receipts = build_receipts_query(
        db,
        user,
        status_filter=status_filter,
        project_id=parse_int(project_id),
        card_id=parse_int(card_id),
        employee_id=parse_int(employee_id),
        date_from_value=parse_receipt_date(date_from),
        date_to_value=parse_receipt_date(date_to),
        q=(q or "").strip(),
    ).all()
    ids = [r.id for r in receipts]
    first_files = {}
    if ids:
        for file_row in db.query(ReceiptFile).filter(ReceiptFile.receipt_id.in_(ids)).order_by(ReceiptFile.id.asc()).all():
            first_files.setdefault(file_row.receipt_id, file_row.id)
    projects = {int(row[0]): row[1] for row in db.query(Project.id, Project.name).filter(Project.company_id == user.company_id).all()}
    cards = {
        int(row[0]): row[1]
        for row in (
            db.query(PaymentCard.id, PaymentCard.name)
            .filter(PaymentCard.company_id == user.company_id, PaymentCard.owner_user_id == user.id)
            .all()
        )
    }
    users = {int(row[0]): row[1] for row in db.query(User.id, User.name).filter(User.company_id == user.company_id).all()}
    base_url = str(request.base_url).rstrip("/")

    try:
        from openpyxl import Workbook  # type: ignore

        wb = Workbook()
        ws = wb.active
        ws.title = "Receipts"
        ws.append(["Дата", "Объект", "Карта", "Сотрудник", "Сумма", "Комментарий", "Статус", "Ссылка на файл"])
        for receipt in receipts:
            file_id = first_files.get(receipt.id)
            file_url = f"{base_url}/web/receipt-files/{file_id}?download=1" if file_id else ""
            ws.append(
                [
                    receipt.receipt_date.isoformat() if receipt.receipt_date else receipt.created_at.date().isoformat(),
                    projects.get(receipt.project_id, f"#{receipt.project_id}"),
                    cards.get(receipt.card_id, f"#{receipt.card_id}"),
                    users.get(receipt.created_by, f"#{receipt.created_by}"),
                    float(receipt.amount) if receipt.amount is not None else None,
                    receipt.comment,
                    receipt_status_label_ru(receipt.status),
                    file_url,
                ]
            )
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
        filename = f"receipts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers=headers,
        )
    except Exception:
        text_buffer = io.StringIO()
        writer = csv.writer(text_buffer, delimiter=";")
        writer.writerow(["Дата", "Объект", "Карта", "Сотрудник", "Сумма", "Комментарий", "Статус", "Ссылка на файл"])
        for receipt in receipts:
            file_id = first_files.get(receipt.id)
            file_url = f"{base_url}/web/receipt-files/{file_id}?download=1" if file_id else ""
            writer.writerow(
                [
                    receipt.receipt_date.isoformat() if receipt.receipt_date else receipt.created_at.date().isoformat(),
                    projects.get(receipt.project_id, f"#{receipt.project_id}"),
                    cards.get(receipt.card_id, f"#{receipt.card_id}"),
                    users.get(receipt.created_by, f"#{receipt.created_by}"),
                    str(receipt.amount or ""),
                    receipt.comment,
                    receipt_status_label_ru(receipt.status),
                    file_url,
                ]
            )
        payload = ("\ufeff" + text_buffer.getvalue()).encode("utf-8")
        filename = f"receipts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return Response(payload, media_type="text/csv; charset=utf-8", headers=headers)


@app.get("/web/receipts/export.zip")
def web_receipts_export_zip(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = None,
    project_id: str | None = None,
    card_id: str | None = None,
    employee_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
):
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)

    def parse_int(raw: str | None) -> int | None:
        value = (raw or "").strip()
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    receipts = build_receipts_query(
        db,
        user,
        status_filter=status_filter,
        project_id=parse_int(project_id),
        card_id=parse_int(card_id),
        employee_id=parse_int(employee_id),
        date_from_value=parse_receipt_date(date_from),
        date_to_value=parse_receipt_date(date_to),
        q=(q or "").strip(),
    ).all()
    if not receipts:
        raise HTTPException(400, "No receipts for selected filters")
    receipt_ids = [r.id for r in receipts]
    files = (
        db.query(ReceiptFile)
        .filter(ReceiptFile.receipt_id.in_(receipt_ids))
        .order_by(ReceiptFile.receipt_id.asc(), ReceiptFile.id.asc())
        .all()
    )
    if not files:
        raise HTTPException(400, "No files for selected receipts")

    cards = {
        int(row[0]): row[1]
        for row in (
            db.query(PaymentCard.id, PaymentCard.name)
            .filter(PaymentCard.company_id == user.company_id, PaymentCard.owner_user_id == user.id)
            .all()
        )
    }
    receipts_by_id = {r.id: r for r in receipts}
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_row in files:
            receipt = receipts_by_id.get(file_row.receipt_id)
            if not receipt:
                continue
            payload_info = read_stored_file_bytes(file_row.file_path)
            if not payload_info:
                continue
            payload, stored_name = payload_info
            ext = Path(file_row.original_name or stored_name).suffix.lower() or ".bin"
            dt_str = (receipt.receipt_date or receipt.created_at.date()).isoformat()
            card_name = sanitize_export_token(cards.get(receipt.card_id, f"card{receipt.card_id}"), max_len=24)
            comment = sanitize_export_token(receipt.comment, max_len=24)
            amount_token = sanitize_export_token(str(receipt.amount or ""), max_len=12)
            arcname = f"{dt_str}_{card_name}_{comment}_{amount_token}_r{receipt.id}_f{file_row.id}{ext}"
            zf.writestr(arcname, payload)
    output.seek(0)
    filename = f"receipts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(output, media_type="application/zip", headers=headers)


# ====== WEB: Projects (legacy redirects) ======
@app.get("/web/projects")
def web_projects(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/projects/create")
async def web_projects_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/projects/{project_id}/delete")
async def web_projects_delete(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)

# ====== WEB: Ticket Types ======
@app.get("/web/ticket-types")
def web_ticket_types(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    ticket_types = (
        db.query(
            TicketType.id,
            TicketType.name,
            TicketType.description,
            TicketType.department_id,
            TicketType.archive_retention_days,
            TicketType.is_active,
            Department.name.label("department_name"),
        )
        .outerjoin(Department, Department.id == TicketType.department_id)
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.id.desc())
        .all()
    )
    departments = (
        db.query(Department.id, Department.name, Department.is_active)
        .filter(Department.company_id == user.company_id)
        .order_by(Department.name.asc(), Department.id.asc())
        .all()
    )
    return templates.TemplateResponse(
        "ticket_types.html",
        {
            "request": request,
            "user": user,
            "ticket_types": ticket_types,
            "departments": departments,
            "can_manage_departments": is_admin(user),
        },
    )

@app.post("/web/ticket-types/create")
async def web_ticket_types_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    form = await request.form()
    name = (form.get("name") or "").strip()
    description = (form.get("description") or "").strip() or None
    department_raw = (form.get("department_id") or "").strip()
    archive_retention_days = parse_archive_retention_days(form.get("archive_retention_days"))
    if (form.get("archive_retention_days") or "").strip() and archive_retention_days is None:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    is_active = (form.get("is_active") or "1").strip() == "1"
    if not name:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    department_id = int(department_raw) if department_raw.isdigit() else None
    if department_raw and department_id is None:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    if department_id is not None:
        department = db.get(Department, department_id)
        if not department or department.company_id != user.company_id:
            return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    exists = (
        db.query(TicketType)
        .filter(TicketType.company_id == user.company_id, TicketType.name == name)
        .first()
    )
    if exists:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    item = TicketType(
        company_id=user.company_id,
        name=name,
        description=description,
        department_id=department_id,
        archive_retention_days=archive_retention_days,
        is_active=is_active,
    )
    db.add(item)
    db.commit()
    return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)

@app.post("/web/ticket-types/{ticket_type_id}/update")
async def web_ticket_types_update(
    ticket_type_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    item = db.get(TicketType, ticket_type_id)
    if not item or item.company_id != user.company_id:
        raise HTTPException(404, "Ticket type not found")

    form = await request.form()
    name = (form.get("name") or "").strip()
    description = (form.get("description") or "").strip() or None
    department_raw = (form.get("department_id") or "").strip()
    archive_retention_days = parse_archive_retention_days(form.get("archive_retention_days"))
    if (form.get("archive_retention_days") or "").strip() and archive_retention_days is None:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    is_active = (form.get("is_active") or "").strip() == "1"
    if not name:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    department_id = int(department_raw) if department_raw.isdigit() else None
    if department_raw and department_id is None:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    if department_id is not None:
        department = db.get(Department, department_id)
        if not department or department.company_id != user.company_id:
            return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)

    exists = (
        db.query(TicketType)
        .filter(
            TicketType.company_id == user.company_id,
            TicketType.name == name,
            TicketType.id != item.id,
        )
        .first()
    )
    if exists:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)

    item.name = name
    item.description = description
    item.department_id = department_id
    item.archive_retention_days = archive_retention_days
    item.is_active = is_active
    db.commit()
    return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)

@app.post("/web/ticket-types/{ticket_type_id}/delete")
async def web_ticket_types_delete(
    ticket_type_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    item = db.get(TicketType, ticket_type_id)
    if not item or item.company_id != user.company_id:
        raise HTTPException(404, "Ticket type not found")

    in_use = db.query(Ticket.id).filter(Ticket.ticket_type_id == item.id).first() is not None
    if in_use:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    db.delete(item)
    db.commit()
    return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)


# ====== WEB: Ticket Templates ======
@app.get("/web/ticket-templates")
def web_ticket_templates(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    items = (
        db.query(TicketTemplate)
        .filter(TicketTemplate.company_id == user.company_id)
        .order_by(TicketTemplate.id.desc())
        .all()
    )
    ticket_types = (
        db.query(TicketType.id, TicketType.name, TicketType.is_active, TicketType.department_id)
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.name.asc())
        .all()
    )
    departments = (
        db.query(Department.id, Department.name, Department.is_active)
        .filter(Department.company_id == user.company_id)
        .order_by(Department.name.asc(), Department.id.asc())
        .all()
    )
    org_units = (
        db.query(OrgUnit.id, OrgUnit.name, OrgUnit.parent_id, OrgUnit.is_active)
        .filter(OrgUnit.company_id == user.company_id)
        .order_by(OrgUnit.id.asc())
        .all()
    )
    executors = (
        query_assignable_company_users(db, user.company_id)
        .order_by(User.name.asc(), User.id.asc())
        .all()
    )
    return templates.TemplateResponse(
        "ticket_templates.html",
        {
            "request": request,
            "user": user,
            "items": items,
            "ticket_types": ticket_types,
            "departments": departments,
            "org_units": org_units,
            "executors": executors,
        },
    )


@app.post("/web/ticket-templates/create")
async def web_ticket_templates_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    form = await request.form()
    name = (form.get("name") or "").strip()
    if not name:
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    try:
        ticket_type_id = int((form.get("ticket_type_id") or "").strip())
    except ValueError:
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    department_raw = (form.get("department_id") or "").strip()
    scope_raw = (form.get("scope_unit_id") or "").strip()
    executor_raw = (form.get("default_executor_id") or "").strip()
    if department_raw and not department_raw.isdigit():
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    department_id = int(department_raw) if department_raw.isdigit() else None
    scope_unit_id = int(scope_raw) if scope_raw.isdigit() else None
    default_executor_id = int(executor_raw) if executor_raw.isdigit() else None
    is_active = (form.get("is_active") or "1").strip() == "1"
    validate_template_links(db, user.company_id, ticket_type_id, department_id, default_executor_id, scope_unit_id)
    resolved_department_id = resolve_ticket_department_id(
        db,
        company_id=user.company_id,
        ticket_type_id=ticket_type_id,
        department_id=department_id,
    )
    exists = (
        db.query(TicketTemplate.id)
        .filter(TicketTemplate.company_id == user.company_id, TicketTemplate.name == name)
        .first()
    )
    if exists:
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    item = TicketTemplate(
        company_id=user.company_id,
        ticket_type_id=ticket_type_id,
        department_id=resolved_department_id,
        name=name,
        title_template=(form.get("title_template") or "").strip() or None,
        description_template=(form.get("description_template") or "").strip() or None,
        default_deadline_rule=parse_template_deadline_rule_from_form(form),
        default_executor_id=default_executor_id,
        scope_unit_id=scope_unit_id,
        is_active=is_active,
    )
    db.add(item)
    db.commit()
    return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/ticket-templates/{template_id}/update")
async def web_ticket_templates_update(
    template_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    item = db.get(TicketTemplate, template_id)
    if not item or item.company_id != user.company_id:
        raise HTTPException(404, "Ticket template not found")
    form = await request.form()
    name = (form.get("name") or "").strip()
    if not name:
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    try:
        ticket_type_id = int((form.get("ticket_type_id") or "").strip())
    except ValueError:
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    department_raw = (form.get("department_id") or "").strip()
    scope_raw = (form.get("scope_unit_id") or "").strip()
    executor_raw = (form.get("default_executor_id") or "").strip()
    if department_raw and not department_raw.isdigit():
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    department_id = int(department_raw) if department_raw.isdigit() else None
    scope_unit_id = int(scope_raw) if scope_raw.isdigit() else None
    default_executor_id = int(executor_raw) if executor_raw.isdigit() else None
    is_active = (form.get("is_active") or "").strip() == "1"
    validate_template_links(db, user.company_id, ticket_type_id, department_id, default_executor_id, scope_unit_id)
    resolved_department_id = resolve_ticket_department_id(
        db,
        company_id=user.company_id,
        ticket_type_id=ticket_type_id,
        department_id=department_id,
    )
    exists = (
        db.query(TicketTemplate.id)
        .filter(
            TicketTemplate.company_id == user.company_id,
            TicketTemplate.name == name,
            TicketTemplate.id != item.id,
        )
        .first()
    )
    if exists:
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    item.ticket_type_id = ticket_type_id
    item.department_id = resolved_department_id
    item.name = name
    item.title_template = (form.get("title_template") or "").strip() or None
    item.description_template = (form.get("description_template") or "").strip() or None
    item.default_deadline_rule = parse_template_deadline_rule_from_form(form)
    item.default_executor_id = default_executor_id
    item.scope_unit_id = scope_unit_id
    item.is_active = is_active
    db.commit()
    return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/ticket-templates/{template_id}/delete")
async def web_ticket_templates_delete(
    template_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    item = db.get(TicketTemplate, template_id)
    if not item or item.company_id != user.company_id:
        raise HTTPException(404, "Ticket template not found")
    try:
        db.query(Ticket).filter(
            Ticket.company_id == user.company_id,
            Ticket.ticket_template_id == item.id,
        ).update({"ticket_template_id": None}, synchronize_session=False)
        db.query(TicketGenerationKey).filter(
            TicketGenerationKey.company_id == user.company_id,
            TicketGenerationKey.ticket_template_id == item.id,
        ).delete(synchronize_session=False)
        db.delete(item)
        db.commit()
        return RedirectResponse(url="/web/ticket-templates", status_code=HTTP_303_SEE_OTHER)
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/ticket-templates?delete_error=1", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/ticket-templates/{template_id}/run")
async def web_ticket_templates_run(
    template_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    item = db.get(TicketTemplate, template_id)
    if not item or item.company_id != user.company_id:
        raise HTTPException(404, "Ticket template not found")

    form = await request.form()
    raw_period_key = (form.get("period_key") or "").strip() or None
    period_key = normalize_period_key(raw_period_key)
    if raw_period_key and period_key is None:
        return RedirectResponse(url="/web/ticket-templates?run_error=bad_period", status_code=HTTP_303_SEE_OTHER)
    created_count, skipped_count, effective_period = create_tickets_from_template(
        db=db,
        template=item,
        actor_id=user.id,
        period_key=period_key,
    )
    db.commit()
    return RedirectResponse(
        url=(
            "/web/ticket-templates"
            f"?run_ok=1&run_created={created_count}&run_skipped={skipped_count}&run_period={quote(effective_period)}"
        ),
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/web/ticket-templates/{template_id}/clear-keys")
async def web_ticket_templates_clear_keys(
    template_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    item = db.get(TicketTemplate, template_id)
    if not item or item.company_id != user.company_id:
        raise HTTPException(404, "Ticket template not found")

    form = await request.form()
    raw_period_key = (form.get("period_key") or "").strip()
    normalized_period_candidate = normalize_period_key(raw_period_key)
    if raw_period_key and normalized_period_candidate is None:
        return RedirectResponse(url="/web/ticket-templates?keys_error=bad_period", status_code=HTTP_303_SEE_OTHER)
    normalized_period = normalized_period_candidate or month_period_key()
    deleted_count = (
        db.query(TicketGenerationKey)
        .filter(
            TicketGenerationKey.company_id == user.company_id,
            TicketGenerationKey.ticket_template_id == item.id,
            TicketGenerationKey.period_key == normalized_period,
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    return RedirectResponse(
        url=(
            "/web/ticket-templates"
            f"?keys_cleared=1&keys_period={quote(normalized_period)}&keys_deleted={int(deleted_count or 0)}"
        ),
        status_code=HTTP_303_SEE_OTHER,
    )

# ====== WEB: Users ======
def manageable_roles_for_web_user_management(actor: User) -> tuple[Role, ...]:
    if actor.role == Role.admin:
        return (Role.curator, Role.executor)
    if actor.role == Role.curator:
        return (Role.executor,)
    return tuple()


def can_manage_company_user(actor: User, target: User) -> bool:
    if actor.company_id != target.company_id:
        return False
    if actor.id == target.id and actor.role in MANAGER_ROLES:
        return True
    return target.role in manageable_roles_for_web_user_management(actor)


@app.get("/web/executors")
def web_executors():
    return RedirectResponse(url="/web/users", status_code=HTTP_303_SEE_OTHER)


@app.get("/web/users")
def web_users(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ok: str | None = None,
    err: str | None = None,
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    allowed_roles = manageable_roles_for_web_user_management(user)
    if not allowed_roles:
        raise HTTPException(403, "Forbidden")
    template_access_levels = manageable_template_access_levels_for_actor(user)
    ensure_default_role_templates(db, user.company_id, template_access_levels)

    users = (
        db.query(
            User.id,
            User.name,
            User.email,
            User.role,
            User.role_label,
            User.is_assignable_executor,
            User.show_receipts_accounting_mode,
            User.can_view_all_tickets,
            User.can_create_tickets,
            User.can_close_tickets,
        )
        .filter(
            User.company_id == user.company_id,
            User.role != Role.platform_admin,
        )
        .order_by(User.id.desc())
        .all()
    )
    visible_users = [u for u in users if u.id == user.id or u.role in allowed_roles]
    role_templates = (
        db.query(RoleTemplate)
        .filter(
            RoleTemplate.company_id == user.company_id,
            RoleTemplate.access_level.in_(template_access_levels),
        )
        .order_by(RoleTemplate.access_level.asc(), RoleTemplate.name.asc(), RoleTemplate.id.asc())
        .all()
    )
    invites = (
        db.query(
            RegistrationInvite.id,
            RegistrationInvite.role,
            RegistrationInvite.token,
            RegistrationInvite.created_at,
            RegistrationInvite.expires_at,
            RegistrationInvite.used_by,
        )
        .filter(
            RegistrationInvite.company_id == user.company_id,
            RegistrationInvite.role.in_(allowed_roles),
        )
        .order_by(RegistrationInvite.id.desc())
        .limit(30)
        .all()
    )
    base_url = str(request.base_url).rstrip("/")
    invite_links = []
    for inv in invites:
        invite_links.append(
            {
                "id": inv.id,
                "role": inv.role.value,
                "url": f"{base_url}/web/register?token={inv.token}",
                "created_at": inv.created_at,
                "expires_at": inv.expires_at,
                "is_used": inv.used_by is not None,
            }
        )
    ok_code = (ok or "").strip().lower()
    err_code = (err or "").strip().lower()
    ok_messages = {
        "created": "Пользователь создан.",
        "updated": "Данные пользователя обновлены.",
        "deleted": "Пользователь удален.",
        "invite_created": "Ссылка приглашения создана.",
        "template_created": "Шаблон роли создан.",
        "template_updated": "Шаблон роли обновлен.",
        "template_deleted": "Шаблон роли удален.",
    }
    err_messages = {
        "bad_input": "Заполните обязательные поля.",
        "bad_role": "Недопустимый уровень доступа.",
        "bad_template": "Шаблон роли не найден или недоступен.",
        "bad_template_input": "Заполните название шаблона и проверьте параметры.",
        "template_name_exists": "Шаблон с таким названием уже существует.",
        "template_not_found": "Шаблон роли не найден.",
        "email_exists": "Пользователь с таким email уже существует.",
        "user_not_found": "Пользователь не найден или недоступен для управления.",
        "save_failed": "Не удалось сохранить изменения.",
        "delete_blocked": "Нельзя удалить пользователя: он уже участвует в заявках или шаблонах.",
        "delete_failed": "Не удалось удалить пользователя.",
        "delete_self": "Свой аккаунт удалить нельзя.",
    }
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "user": user,
            "managed_users": visible_users,
            "role_templates": role_templates,
            "access_level_options": [
                {"value": role.value, "label": access_level_label_ru(role)}
                for role in allowed_roles
            ],
            "invite_links": invite_links,
            "ok_message": ok_messages.get(ok_code, ""),
            "err_message": err_messages.get(err_code, ""),
        },
    )


@app.post("/web/users/invites/create")
async def web_users_invite_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    allowed_roles = manageable_roles_for_web_user_management(user)
    if not allowed_roles:
        raise HTTPException(403, "Forbidden")

    form = await request.form()
    role_raw = (form.get("role") or "").strip().upper()
    expires_days_raw = (form.get("expires_days") or "").strip()
    if user.role == Role.curator:
        role_value = Role.executor
    else:
        if role_raw not in ("CURATOR", "EXECUTOR"):
            return RedirectResponse(url="/web/users?err=bad_role", status_code=HTTP_303_SEE_OTHER)
        role_value = Role(role_raw)
        if role_value not in allowed_roles:
            return RedirectResponse(url="/web/users?err=bad_role", status_code=HTTP_303_SEE_OTHER)

    try:
        expires_days = int(expires_days_raw) if expires_days_raw else 7
    except ValueError:
        expires_days = 7
    expires_days = max(1, min(expires_days, 30))

    invite = RegistrationInvite(
        token=secrets.token_urlsafe(24),
        role=role_value,
        company_id=user.company_id,
        created_by=user.id,
        expires_at=datetime.utcnow() + timedelta(days=expires_days),
    )
    try:
        db.add(invite)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/web/users?ok=invite_created", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/users/templates/create")
async def web_user_role_templates_create(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    allowed_roles = manageable_template_access_levels_for_actor(user)
    if not allowed_roles:
        raise HTTPException(403, "Forbidden")

    form = await request.form()
    name = normalize_role_template_name(form.get("name"))
    role_raw = (form.get("access_level") or "").strip().upper()
    if user.role == Role.curator:
        role_value = Role.executor
    else:
        if role_raw not in {role.value for role in allowed_roles}:
            return RedirectResponse(url="/web/users?err=bad_role", status_code=HTTP_303_SEE_OTHER)
        role_value = Role(role_raw)
    if not name:
        return RedirectResponse(url="/web/users?err=bad_template_input", status_code=HTTP_303_SEE_OTHER)
    exists = (
        db.query(RoleTemplate.id)
        .filter(
            RoleTemplate.company_id == user.company_id,
            func.lower(RoleTemplate.name) == name.lower(),
        )
        .first()
    )
    if exists:
        return RedirectResponse(url="/web/users?err=template_name_exists", status_code=HTTP_303_SEE_OTHER)

    flags = normalize_capability_flags(
        role_value,
        show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
        is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
        can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
        can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
        can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
    )
    try:
        db.add(
            RoleTemplate(
                company_id=user.company_id,
                name=name,
                access_level=role_value,
                **flags,
            )
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/web/users?ok=template_created", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/users/templates/{template_id}/update")
async def web_user_role_templates_update(
    template_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    allowed_roles = manageable_template_access_levels_for_actor(user)
    if not allowed_roles:
        raise HTTPException(403, "Forbidden")

    item = get_manageable_role_template(db, user, template_id, allowed_access_levels=allowed_roles)
    if not item:
        return RedirectResponse(url="/web/users?err=template_not_found", status_code=HTTP_303_SEE_OTHER)

    form = await request.form()
    name = normalize_role_template_name(form.get("name"))
    role_raw = (form.get("access_level") or "").strip().upper()
    if user.role == Role.curator:
        role_value = Role.executor
    else:
        if role_raw not in {role.value for role in allowed_roles}:
            return RedirectResponse(url="/web/users?err=bad_role", status_code=HTTP_303_SEE_OTHER)
        role_value = Role(role_raw)
    if not name:
        return RedirectResponse(url="/web/users?err=bad_template_input", status_code=HTTP_303_SEE_OTHER)
    duplicate = (
        db.query(RoleTemplate.id)
        .filter(
            RoleTemplate.company_id == user.company_id,
            func.lower(RoleTemplate.name) == name.lower(),
            RoleTemplate.id != item.id,
        )
        .first()
    )
    if duplicate:
        return RedirectResponse(url="/web/users?err=template_name_exists", status_code=HTTP_303_SEE_OTHER)

    flags = normalize_capability_flags(
        role_value,
        show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
        is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
        can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
        can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
        can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
    )
    item.name = name
    item.access_level = role_value
    item.show_receipts_accounting_mode = flags["show_receipts_accounting_mode"]
    item.is_assignable_executor = flags["is_assignable_executor"]
    item.can_view_all_tickets = flags["can_view_all_tickets"]
    item.can_create_tickets = flags["can_create_tickets"]
    item.can_close_tickets = flags["can_close_tickets"]
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/web/users?ok=template_updated", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/users/templates/{template_id}/delete")
async def web_user_role_templates_delete(
    template_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    allowed_roles = manageable_template_access_levels_for_actor(user)
    item = get_manageable_role_template(db, user, template_id, allowed_access_levels=allowed_roles)
    if not item:
        return RedirectResponse(url="/web/users?err=template_not_found", status_code=HTTP_303_SEE_OTHER)
    try:
        db.delete(item)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/web/users?ok=template_deleted", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/users/create")
async def web_users_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    form = await request.form()
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip()
    password = (form.get("password") or "").strip()
    role_raw = (form.get("role") or "").strip().upper()
    role_label = normalize_role_label(form.get("role_label"))
    role_template_id = parse_optional_int(form.get("role_template_id"))
    allowed_roles = manageable_roles_for_web_user_management(user)
    if not allowed_roles:
        raise HTTPException(403, "Forbidden")

    if not (name and email and password):
        return RedirectResponse(url="/web/users?err=bad_input", status_code=HTTP_303_SEE_OTHER)
    if db.query(User.id).filter(User.email == email).first():
        return RedirectResponse(url="/web/users?err=email_exists", status_code=HTTP_303_SEE_OTHER)

    template = get_manageable_role_template(db, user, role_template_id, allowed_access_levels=allowed_roles)
    if role_template_id is not None and not template:
        return RedirectResponse(url="/web/users?err=bad_template", status_code=HTTP_303_SEE_OTHER)
    if template:
        role_value = template.access_level
        capability_flags = role_template_payload(template)
    elif user.role == Role.curator:
        role_value = Role.executor
        capability_flags = normalize_capability_flags(
            role_value,
            show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
            is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
            can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
            can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
            can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
        )
    else:
        if role_raw not in {role.value for role in allowed_roles}:
            return RedirectResponse(url="/web/users?err=bad_role", status_code=HTTP_303_SEE_OTHER)
        role_value = Role(role_raw)
        capability_flags = normalize_capability_flags(
            role_value,
            show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
            is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
            can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
            can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
            can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
        )

    u = User(
        email=email,
        name=name,
        password_hash=hash_password(password),
        role=role_value,
        company_id=user.company_id,
        role_label=role_label or (template.name if template else None),
        **capability_flags,
    )
    prepare_user_email_verification(u, force_new_token=True)
    try:
        db.add(u)
        db.commit()
        db.refresh(u)
        send_user_verification_email(request, db, u)
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    except EmailDeliveryError:
        logger.exception("Could not send verification email to %s", u.email)
    return RedirectResponse(url="/web/users?ok=created", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/users/{managed_user_id}/update")
async def web_users_update(
    managed_user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    form = await request.form()
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip()
    password = (form.get("password") or "").strip()
    role_raw = (form.get("role") or "").strip().upper()
    role_label = normalize_role_label(form.get("role_label"))
    role_template_id = parse_optional_int(form.get("role_template_id"))
    if not (name and email):
        return RedirectResponse(url="/web/users?err=bad_input", status_code=HTTP_303_SEE_OTHER)

    item = db.get(User, managed_user_id)
    if not item or not can_manage_company_user(user, item):
        return RedirectResponse(url="/web/users?err=user_not_found", status_code=HTTP_303_SEE_OTHER)

    email_owner = db.query(User.id).filter(User.email == email, User.id != item.id).first()
    if email_owner:
        return RedirectResponse(url="/web/users?err=email_exists", status_code=HTTP_303_SEE_OTHER)

    allowed_template_roles = (item.role,) if item.id == user.id else manageable_roles_for_web_user_management(user)
    template = get_manageable_role_template(
        db,
        user,
        role_template_id,
        allowed_access_levels=allowed_template_roles,
    )
    if role_template_id is not None and not template:
        return RedirectResponse(url="/web/users?err=bad_template", status_code=HTTP_303_SEE_OTHER)
    if item.id == user.id:
        next_role = item.role
        if template and template.access_level != item.role:
            return RedirectResponse(url="/web/users?err=bad_template", status_code=HTTP_303_SEE_OTHER)
    elif user.role == Role.admin:
        if template:
            next_role = template.access_level
        else:
            allowed_roles = manageable_roles_for_web_user_management(user)
            if role_raw not in {role.value for role in allowed_roles}:
                return RedirectResponse(url="/web/users?err=bad_role", status_code=HTTP_303_SEE_OTHER)
            next_role = Role(role_raw)
    else:
        next_role = item.role
        if template and template.access_level != item.role:
            return RedirectResponse(url="/web/users?err=bad_template", status_code=HTTP_303_SEE_OTHER)

    capability_flags = (
        role_template_payload(template)
        if template
        else normalize_capability_flags(
            next_role,
            show_receipts_accounting_mode=parse_bool_text(form.get("show_receipts_accounting_mode"), default=False),
            is_assignable_executor=parse_bool_text(form.get("is_assignable_executor"), default=False),
            can_view_all_tickets=parse_bool_text(form.get("can_view_all_tickets"), default=False),
            can_create_tickets=parse_bool_text(form.get("can_create_tickets"), default=False),
            can_close_tickets=parse_bool_text(form.get("can_close_tickets"), default=False),
        )
    )
    email_changed = (item.email or "").strip() != email
    item.name = name
    item.email = email
    item.role = next_role
    item.role_label = role_label or (template.name if template else None)
    item.show_receipts_accounting_mode = capability_flags["show_receipts_accounting_mode"]
    item.is_assignable_executor = capability_flags["is_assignable_executor"]
    item.can_view_all_tickets = capability_flags["can_view_all_tickets"]
    item.can_create_tickets = capability_flags["can_create_tickets"]
    item.can_close_tickets = capability_flags["can_close_tickets"]
    if password:
        item.password_hash = hash_password(password)
        bump_user_auth_token_version(item)
    if email_changed:
        prepare_user_email_verification(item, force_new_token=True)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=save_failed", status_code=HTTP_303_SEE_OTHER)
    if email_changed:
        try:
            send_user_verification_email(request, db, item)
        except EmailDeliveryError:
            logger.exception("Could not send verification email to %s", item.email)
    return RedirectResponse(url="/web/users?ok=updated", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/users/{managed_user_id}/delete")
async def web_users_delete(
    managed_user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    item = db.get(User, managed_user_id)
    if not item or not can_manage_company_user(user, item):
        return RedirectResponse(url="/web/users?err=user_not_found", status_code=HTTP_303_SEE_OTHER)
    if item.id == user.id:
        return RedirectResponse(url="/web/users?err=delete_self", status_code=HTTP_303_SEE_OTHER)

    # Do not delete users that already have business history in the ticket system.
    has_ticket_refs = db.query(Ticket.id).filter(
        Ticket.company_id == user.company_id,
        or_(Ticket.created_by == item.id, Ticket.executor_id == item.id, Ticket.archived_by == item.id),
    ).first()
    has_comment_refs = (
        db.query(Comment.id)
        .join(Ticket, Ticket.id == Comment.ticket_id)
        .filter(Ticket.company_id == user.company_id, Comment.author_id == item.id)
        .first()
    )
    has_attachment_refs = (
        db.query(Attachment.id)
        .join(Ticket, Ticket.id == Attachment.ticket_id)
        .filter(Ticket.company_id == user.company_id, Attachment.uploader_id == item.id)
        .first()
    )
    has_log_refs = (
        db.query(TicketLog.id)
        .join(Ticket, Ticket.id == TicketLog.ticket_id)
        .filter(Ticket.company_id == user.company_id, TicketLog.actor_id == item.id)
        .first()
    )
    has_template_refs = db.query(TicketTemplate.id).filter(
        TicketTemplate.company_id == user.company_id,
        TicketTemplate.default_executor_id == item.id,
    ).first()
    if has_ticket_refs or has_comment_refs or has_attachment_refs or has_log_refs or has_template_refs:
        return RedirectResponse(url="/web/users?err=delete_blocked", status_code=HTTP_303_SEE_OTHER)

    try:
        db.query(UnitAssignment).filter(
            UnitAssignment.company_id == user.company_id,
            UnitAssignment.user_id == item.id,
        ).delete(synchronize_session=False)
        db.query(TicketWatcher).filter(TicketWatcher.user_id == item.id).delete(synchronize_session=False)
        db.query(TicketWatcher).filter(TicketWatcher.added_by == item.id).update(
            {TicketWatcher.added_by: None},
            synchronize_session=False,
        )
        db.query(PushSubscription).filter(PushSubscription.user_id == item.id).delete(synchronize_session=False)
        db.query(MobileDevice).filter(MobileDevice.user_id == item.id).delete(synchronize_session=False)
        db.query(DeadlineReminderLog).filter(DeadlineReminderLog.user_id == item.id).delete(synchronize_session=False)
        db.query(Notification).filter(Notification.user_id == item.id).delete(synchronize_session=False)
        db.query(RegistrationInvite).filter(
            RegistrationInvite.company_id == user.company_id,
            RegistrationInvite.used_by == item.id,
        ).update(
            {RegistrationInvite.used_by: None, RegistrationInvite.used_at: None},
            synchronize_session=False,
        )
        db.query(RegistrationInvite).filter(
            RegistrationInvite.company_id == user.company_id,
            RegistrationInvite.created_by == item.id,
        ).delete(synchronize_session=False)
        db.delete(item)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=delete_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/web/users?ok=deleted", status_code=HTTP_303_SEE_OTHER)

@app.get("/web/tickets/{ticket_id}")
def web_ticket_detail(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    t = get_company_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if ensure_default_ticket_watchers(db, t):
        db.commit()

    watcher_rows = (
        db.query(TicketWatcher.user_id)
        .filter(TicketWatcher.ticket_id == t.id)
        .order_by(TicketWatcher.created_at.asc(), TicketWatcher.id.asc())
        .all()
    )
    watcher_user_ids = [int(row[0]) for row in watcher_rows]
    is_current_user_watcher = user.id in set(watcher_user_ids)
    default_next = "/web/archive" if t.status == TicketStatus.archived else "/web"
    next_url = safe_next(request.query_params.get("next"), fallback=default_next)
    next_url_encoded = quote(next_url, safe="")
    can_archive = can_archive_ticket(user, t)
    can_restore = is_manager(user) and t.status == TicketStatus.archived

    # РїСЂР°РІР°
    comments = db.query(Comment).filter(Comment.ticket_id == t.id).order_by(Comment.id.asc()).all()
    comment_media_by_comment: dict[int, list[CommentMedia]] = {}
    if comments:
        comment_ids = [comment.id for comment in comments]
        comment_media_items = (
            db.query(CommentMedia)
            .filter(CommentMedia.comment_id.in_(comment_ids))
            .order_by(CommentMedia.id.asc())
            .all()
        )
        for item in comment_media_items:
            comment_media_by_comment.setdefault(item.comment_id, []).append(item)
    attachments = db.query(Attachment).filter(Attachment.ticket_id == t.id).order_by(Attachment.id.asc()).all()
    ticket_logs = db.query(TicketLog).filter(TicketLog.ticket_id == t.id).order_by(TicketLog.id.desc()).all()

    project_row = (
        db.query(Project.id, Project.name)
        .filter(Project.company_id == user.company_id, Project.id == t.project_id)
        .first()
    )
    projects_by_id = {project_row[0]: project_row[1]} if project_row else {}

    ticket_type_row = None
    if t.ticket_type_id is not None:
        ticket_type_row = (
            db.query(TicketType.id, TicketType.name)
            .filter(TicketType.company_id == user.company_id, TicketType.id == t.ticket_type_id)
            .first()
        )
    ticket_types_by_id = {ticket_type_row[0]: ticket_type_row[1]} if ticket_type_row else {}
    departments_by_id: dict[int, str] = {}
    if t.department_id is not None:
        department_row = (
            db.query(Department.id, Department.name)
            .filter(Department.company_id == user.company_id, Department.id == t.department_id)
            .first()
        )
        if department_row:
            departments_by_id = {department_row[0]: department_row[1]}

    relevant_user_ids: set[int] = {t.created_by}
    if t.executor_id is not None:
        relevant_user_ids.add(t.executor_id)
    relevant_user_ids.update(watcher_user_ids)
    relevant_user_ids.update(c.author_id for c in comments if c.author_id is not None)
    relevant_user_ids.update(a.uploader_id for a in attachments if a.uploader_id is not None)
    relevant_user_ids.update(log.actor_id for log in ticket_logs if log.actor_id is not None)

    users_by_id: dict[int, str] = {}
    if relevant_user_ids:
        users = (
            db.query(User.id, User.name)
            .filter(User.company_id == user.company_id, User.id.in_(relevant_user_ids))
            .all()
        )
        users_by_id = {uid: uname for uid, uname in users}

    company = db.get(Company, user.company_id) if user.company_id is not None else None
    deadline_soon_warning_minutes = get_company_deadline_soon_warning_minutes(company)
    now = local_now()
    is_overdue = bool(t.deadline and t.deadline < now and t.status not in FINAL_TICKET_STATUSES)
    is_deadline_soon = bool(
        t.deadline
        and not is_overdue
        and t.status not in FINAL_TICKET_STATUSES
        and t.deadline <= now + timedelta(minutes=deadline_soon_warning_minutes)
    )

    status_labels = {
        "NEW": "\u041d\u043e\u0432\u0430\u044f",
        "IN_PROGRESS": "\u0412 \u0440\u0430\u0431\u043e\u0442\u0435",
        "DONE": "\u0412\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0430",
        "CANCELED": "\u041e\u0442\u043c\u0435\u043d\u0435\u043d\u0430",
        "ARCHIVED": "\u0412 \u0430\u0440\u0445\u0438\u0432\u0435",
    }

    return templates.TemplateResponse(
        "ticket_detail.html",
        {
            "request": request,
            "user": user,
            "t": t,
            "projects_by_id": projects_by_id,
            "ticket_types_by_id": ticket_types_by_id,
            "departments_by_id": departments_by_id,
            "users_by_id": users_by_id,
            "comments": comments,
            "comment_media_by_comment": comment_media_by_comment,
            "attachments": attachments,
            "ticket_logs": ticket_logs,
            "now": now,
            "is_overdue": is_overdue,
            "is_deadline_soon": is_deadline_soon,
            "status_labels": status_labels,
            "next_url": next_url,
            "next_url_encoded": next_url_encoded,
            "can_archive": can_archive,
            "can_restore": can_restore,
            "can_close_ticket": can_close_ticket(user, t),
            "watcher_user_ids": watcher_user_ids,
            "is_current_user_watcher": is_current_user_watcher,
        },
    )


