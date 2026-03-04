from calendar import monthrange
from datetime import datetime, timedelta
import csv
from enum import Enum
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import threading
import time
from typing import Optional
import uuid
from urllib.parse import quote, urlsplit
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, String, Text, DateTime, ForeignKey, Enum as SAEnum, Integer, Boolean, UniqueConstraint, func, or_, cast
from sqlalchemy.exc import SQLAlchemyError
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


# =========================
# РќР°СЃС‚СЂРѕР№РєРё (РїСЂРѕСЃС‚С‹Рµ)
# =========================
JWT_SECRET = (os.getenv("JWT_SECRET") or "").strip()
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be set and contain at least 32 characters")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 РґРЅРµР№
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
ARCHIVE_UPLOAD_SUBDIR = "_archive"
ARCHIVE_UPLOAD_DIR = UPLOAD_DIR / ARCHIVE_UPLOAD_SUBDIR
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", 10 * 1024 * 1024))
ALLOWED_UPLOAD_EXTENSIONS = {
    ext.strip().lower()
    for ext in os.getenv(
        "ALLOWED_UPLOAD_EXTENSIONS",
        ".png,.jpg,.jpeg,.gif,.webp,.pdf,.txt,.doc,.docx,.xls,.xlsx,.zip,.rar",
    ).split(",")
    if ext.strip()
}
PWA_STATIC_DIR = Path(os.getenv("PWA_STATIC_DIR", "./static"))
PUSH_REMINDER_MINUTES = int(os.getenv("PUSH_REMINDER_MINUTES", "60"))
PUSH_REMINDER_POLL_SECONDS = int(os.getenv("PUSH_REMINDER_POLL_SECONDS", "30"))
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "").strip()
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "").strip()
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:admin@example.com").strip()
MAX_TICKET_TITLE_LEN = 255
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
LOCAL_TIME_OFFSET_HOURS = int(os.getenv("LOCAL_TIME_OFFSET_HOURS", "3"))
RL_LOGIN_LIMIT = int(os.getenv("RL_LOGIN_LIMIT", "10"))
RL_LOGIN_WINDOW_SEC = int(os.getenv("RL_LOGIN_WINDOW_SEC", "300"))
RL_REGISTER_LIMIT = int(os.getenv("RL_REGISTER_LIMIT", "8"))
RL_REGISTER_WINDOW_SEC = int(os.getenv("RL_REGISTER_WINDOW_SEC", "3600"))
RL_PUSH_TEST_LIMIT = int(os.getenv("RL_PUSH_TEST_LIMIT", "10"))
RL_PUSH_TEST_WINDOW_SEC = int(os.getenv("RL_PUSH_TEST_WINDOW_SEC", "3600"))
ORG_STRUCTURE_V2_ENABLED = (os.getenv("ORG_STRUCTURE_V2_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"})
TEMPLATE_AUTOGEN_ENABLED = (os.getenv("TEMPLATE_AUTOGEN_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"})
TEMPLATE_AUTOGEN_POLL_SECONDS = max(30, int(os.getenv("TEMPLATE_AUTOGEN_POLL_SECONDS", "300")))
TEXT_REPAIR_ON_START = (os.getenv("TEXT_REPAIR_ON_START", "1").strip().lower() in {"1", "true", "yes", "on"})

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

class TicketStatus(str, Enum):
    new = "NEW"
    in_progress = "IN_PROGRESS"
    done = "DONE"
    canceled = "CANCELED"
    archived = "ARCHIVED"


STATUS_LABELS_RU = {
    TicketStatus.new: "\u041d\u043e\u0432\u0430\u044f",
    TicketStatus.in_progress: "\u0412 \u0440\u0430\u0431\u043e\u0442\u0435",
    TicketStatus.done: "\u0412\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0430",
    TicketStatus.canceled: "\u041e\u0442\u043c\u0435\u043d\u0435\u043d\u0430",
    TicketStatus.archived: "\u0412 \u0430\u0440\u0445\u0438\u0432\u0435",
}

FINAL_TICKET_STATUSES = (TicketStatus.done, TicketStatus.canceled, TicketStatus.archived)
ARCHIVE_SOURCE_STATUSES = (TicketStatus.done, TicketStatus.canceled)


def status_label_ru(value: TicketStatus | str) -> str:
    if isinstance(value, TicketStatus):
        return STATUS_LABELS_RU.get(value, value.value)
    try:
        status_value = TicketStatus(value)
    except ValueError:
        return value
    return STATUS_LABELS_RU.get(status_value, status_value.value)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(SAEnum(Role), index=True)
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"), index=True, default=None)

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
            name="uq_unit_assignments_company_unit_user_role",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    unit_id: Mapped[int] = mapped_column(ForeignKey("org_units.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    role_code: Mapped[str] = mapped_column(String(64), index=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TicketType(Base):
    __tablename__ = "ticket_types"
    __table_args__ = (UniqueConstraint("company_id", "name", name="uq_ticket_types_company_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    archive_retention_days: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TicketTemplate(Base):
    __tablename__ = "ticket_templates"
    __table_args__ = (UniqueConstraint("company_id", "name", name="uq_ticket_templates_company_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    ticket_type_id: Mapped[int] = mapped_column(ForeignKey("ticket_types.id"), index=True)
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

class UserOut(BaseModel):
    id: int
    email: EmailStr
    name: str
    role: Role
    company_id: Optional[int] = None
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
    archive_retention_days: Optional[int] = None
    is_active: bool = True

class TicketTypeUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    archive_retention_days: Optional[int] = None
    is_active: Optional[bool] = None

class TicketTypeOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    archive_retention_days: Optional[int]
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True

class TicketTemplateCreate(BaseModel):
    ticket_type_id: int
    name: str
    title_template: Optional[str] = None
    description_template: Optional[str] = None
    default_deadline_rule: Optional[str] = None
    default_executor_id: Optional[int] = None
    scope_unit_id: Optional[int] = None
    is_active: bool = True

class TicketTemplateUpdate(BaseModel):
    ticket_type_id: Optional[int] = None
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

class CommentOut(BaseModel):
    id: int
    ticket_id: int
    author_id: int
    text: str
    created_at: datetime
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
    changed = add_ticket_watcher(
        db,
        ticket,
        watcher_user_id=ticket.created_by,
        added_by=ticket.created_by,
    ) or changed
    changed = add_ticket_watcher(
        db,
        ticket,
        watcher_user_id=ticket.executor_id,
        added_by=ticket.created_by,
    ) or changed
    return changed


def can_access_ticket(user: User, ticket: Ticket) -> bool:
    if is_platform_admin(user):
        return True
    if is_manager(user):
        return True
    return bool(user.role == Role.executor and (ticket.executor_id == user.id or ticket.created_by == user.id))


def get_api_ticket_or_404(db: Session, user: User, ticket_id: int) -> Ticket:
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if not is_platform_admin(user):
        ensure_company_user(user)
        if ticket.company_id != user.company_id:
            raise HTTPException(403, "Forbidden")
    return ticket


def resolve_attachment_disk_path(raw_path: str | None) -> Path | None:
    raw = (raw_path or "").strip()
    if not raw:
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
    add_ticket_log(db, ticket_id=ticket.id, actor_id=actor_id, action="восстановление из архива")


def delete_ticket_with_related_data(
    db: Session,
    ticket: Ticket,
    remove_files: bool = True,
) -> None:
    attachments = db.query(Attachment).filter(Attachment.ticket_id == ticket.id).all()
    if remove_files:
        for attachment in attachments:
            path = resolve_attachment_disk_path(attachment.file_path)
            if not path:
                continue
            try:
                if path.exists():
                    path.unlink()
            except OSError:
                pass
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
) -> None:
    if project_id is not None:
        project = db.get(Project, project_id)
        if not project or (company_id is not None and project.company_id != company_id):
            raise HTTPException(400, "Project not found")

    if executor_id is not None:
        executor = db.get(User, executor_id)
        if not executor or executor.role != Role.executor:
            raise HTTPException(400, "Executor not found")
        if company_id is not None and executor.company_id != company_id:
            raise HTTPException(400, "Executor not found")

    if ticket_type_id is not None:
        ticket_type = db.get(TicketType, ticket_type_id)
        if not ticket_type or (company_id is not None and ticket_type.company_id != company_id):
            raise HTTPException(400, "Ticket type not found")
        if not ticket_type.is_active:
            raise HTTPException(400, "Ticket type is inactive")

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


def validate_template_links(
    db: Session,
    company_id: int,
    ticket_type_id: int | None,
    default_executor_id: int | None,
    scope_unit_id: int | None,
) -> None:
    if ticket_type_id is not None:
        tt = db.get(TicketType, ticket_type_id)
        if not tt or tt.company_id != company_id:
            raise HTTPException(400, "Ticket type not found")
    if default_executor_id is not None:
        u = db.get(User, default_executor_id)
        if not u or u.company_id != company_id or u.role != Role.executor:
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


def get_preferred_executor_for_unit(db: Session, company_id: int, unit_id: int) -> int | None:
    row = (
        db.query(UnitAssignment.user_id)
        .join(User, User.id == UnitAssignment.user_id)
        .filter(
            UnitAssignment.company_id == company_id,
            UnitAssignment.unit_id == unit_id,
            UnitAssignment.role_code == "EXECUTOR",
            User.company_id == company_id,
            User.role == Role.executor,
        )
        .order_by(UnitAssignment.is_primary.desc(), UnitAssignment.id.asc())
        .first()
    )
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
            else get_preferred_executor_for_unit(db, template.company_id, leaf_unit_id)
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
                add_ticket_log(db, ticket_id=ticket.id, actor_id=actor_id, action="Создание по шаблону")
                if ticket.executor_id and ticket.executor_id != actor_id:
                    send_push_to_user(
                        db=db,
                        user_id=ticket.executor_id,
                        title=f"Новая заявка #{ticket.id}",
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


def make_safe_upload_name(filename: str | None, ticket_id: int | None = None) -> str:
    ext = Path(filename or "").suffix.lower()[:10]
    if not ext or ext not in ALLOWED_UPLOAD_EXTENSIONS:
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


def build_upload_url_from_disk_path(path: Path) -> str:
    upload_root = UPLOAD_DIR.resolve(strict=False)
    resolved = path.resolve(strict=False)
    relative = resolved.relative_to(upload_root).as_posix()
    return f"/uploads/{relative}"


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


def move_attachment_to_archive(attachment: Attachment, ticket_id: int, archived_at: datetime) -> None:
    source = resolve_attachment_disk_path(attachment.file_path)
    if not source or not source.exists() or not source.is_file():
        attachment.archived_at = archived_at
        return
    archive_name = choose_attachment_storage_name(attachment, ticket_id)
    target_dir = ARCHIVE_UPLOAD_DIR / str(ticket_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / archive_name
    shutil.move(str(source), str(target))
    attachment.file_path = build_upload_url_from_disk_path(target)
    attachment.archived_at = archived_at
    enrich_attachment_metadata(attachment, target)


def move_attachment_to_active_storage(attachment: Attachment, ticket_id: int) -> None:
    source = resolve_attachment_disk_path(attachment.file_path)
    if not source or not source.exists() or not source.is_file():
        attachment.archived_at = None
        return
    active_name = choose_attachment_storage_name(attachment, ticket_id)
    target = UPLOAD_DIR / active_name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(target))
    attachment.file_path = build_upload_url_from_disk_path(target)
    attachment.archived_at = None
    enrich_attachment_metadata(attachment, target)


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


def normalize_log_action(action: str | None) -> str:
    raw = (action or "").strip()
    text = fix_mojibake_text(raw).lower()
    merged = f"{raw.lower()} {text}"
    escaped = raw.encode("unicode_escape").decode("ascii").lower()

    escaped_map = {
        "\\u0421\\u0403\\u0420\\u0455\\u0420\\xb7\\u0420\\u0491\\u0420\\xb0\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0420\\u0455 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0421\\u0453": "\u0441\u043e\u0437\u0434\u0430\u043d\u0438\u0435 \u043f\u043e \u0448\u0430\u0431\u043b\u043e\u043d\u0443",
        "\\u0421\\u0403\\u0420\\u0455\\u0420\\xb7\\u0420\\u0491\\u0420\\xb0\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5": "\u0441\u043e\u0437\u0434\u0430\u043d\u0438\u0435",
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u0403\\u0421\\u0402\\u0420\\u0455\\u0420\\u0454\\u0420\\xb0": "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0441\u0440\u043e\u043a\u0430",
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0451\\u0421\\u0403\\u0420\\u0457\\u0420\\u0455\\u0420\\xbb\\u0420\\u0405\\u0420\\u0451\\u0421\\u201a\\u0420\\xb5\\u0420\\xbb\\u0421\\u040f": "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0438\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044f",
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0421\\u0402\\u0420\\u0455\\u0420\\xb5\\u0420\\u0454\\u0421\\u201a\\u0420\\xb0": "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u043f\u0440\u043e\u0435\u043a\u0442\u0430",
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u201a\\u0420\\u0451\\u0420\\u0457\\u0420\\xb0 \\u0420\\xb7\\u0420\\xb0\\u0421\\u040f\\u0420\\u0406\\u0420\\u0454\\u0420\\u0451": "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0442\u0438\u043f\u0430 \u0437\u0430\u044f\u0432\u043a\u0438",
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u2020\\u0420\\xb5\\u0420\\xbb\\u0420\\xb5\\u0420\\u0406\\u0420\\u0455\\u0420\\u0456\\u0420\\u0455 \\u0421\\u0453\\u0420\\xb7\\u0420\\xbb\\u0420\\xb0": "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0446\u0435\u043b\u0435\u0432\u043e\u0433\u043e \u0443\u0437\u043b\u0430",
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0420\\xb0 \\u0420\\xb7\\u0420\\xb0\\u0421\\u040f\\u0420\\u0406\\u0420\\u0454\\u0420\\u0451": "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0448\u0430\u0431\u043b\u043e\u043d\u0430 \u0437\u0430\u044f\u0432\u043a\u0438",
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0420\\u0457\\u0420\\xb5\\u0421\\u0402\\u0420\\u0451\\u0420\\u0455\\u0420\\u0491\\u0420\\xb0 \\u0421\\u20ac\\u0420\\xb0\\u0420\\xb1\\u0420\\xbb\\u0420\\u0455\\u0420\\u0405\\u0420\\xb0": "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u043f\u0435\u0440\u0438\u043e\u0434\u0430 \u0448\u0430\u0431\u043b\u043e\u043d\u0430",
        "\\u0420\\u0451\\u0420\\xb7\\u0420\\u0458\\u0420\\xb5\\u0420\\u0405\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5": "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435",
        "\\u0420\\u0491\\u0420\\u0455\\u0420\\xb1\\u0420\\xb0\\u0420\\u0406\\u0420\\xbb\\u0420\\xb5\\u0420\\u0405\\u0420\\u0451\\u0420\\xb5 \\u0421\\u201e\\u0420\\xb0\\u0420\\u2116\\u0420\\xbb\\u0420\\xb0": "\u0434\u043e\u0431\u0430\u0432\u043b\u0435\u043d\u0438\u0435 \u0444\u0430\u0439\u043b\u0430",
    }
    if escaped in escaped_map:
        return escaped_map[escaped]

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
    k_change = "\u0438\u0437\u043c\u0435\u043d"

    if k_create in merged:
        if k_template in merged:
            return "\u0441\u043e\u0437\u0434\u0430\u043d\u0438\u0435 \u043f\u043e \u0448\u0430\u0431\u043b\u043e\u043d\u0443"
        return "\u0441\u043e\u0437\u0434\u0430\u043d\u0438\u0435"
    if k_deadline in merged:
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0441\u0440\u043e\u043a\u0430"
    if k_executor in merged:
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0438\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044f"
    if k_project in merged:
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u043f\u0440\u043e\u0435\u043a\u0442\u0430"
    if k_type in merged and k_ticket in merged:
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0442\u0438\u043f\u0430 \u0437\u0430\u044f\u0432\u043a\u0438"
    if k_unit in merged:
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0446\u0435\u043b\u0435\u0432\u043e\u0433\u043e \u0443\u0437\u043b\u0430"
    if k_period in merged and k_template in merged:
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u043f\u0435\u0440\u0438\u043e\u0434\u0430 \u0448\u0430\u0431\u043b\u043e\u043d\u0430"
    if k_template in merged:
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0448\u0430\u0431\u043b\u043e\u043d\u0430 \u0437\u0430\u044f\u0432\u043a\u0438"
    if k_file in merged or "file" in merged:
        return "\u0434\u043e\u0431\u0430\u0432\u043b\u0435\u043d\u0438\u0435 \u0444\u0430\u0439\u043b\u0430"
    if k_change in merged:
        return "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435"
    return text or "\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435"


def add_ticket_log(db: Session, ticket_id: int, actor_id: int, action: str) -> None:
    db.add(TicketLog(ticket_id=ticket_id, actor_id=actor_id, action=normalize_log_action(action)))


def push_is_configured() -> bool:
    return bool(PYWEBPUSH_AVAILABLE and VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY and VAPID_SUBJECT)


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


def notify_executor_new_ticket(db: Session, ticket: Ticket, actor: User) -> None:
    if not ticket.executor_id:
        return
    if ticket.executor_id == actor.id:
        return
    send_push_to_user(
        db=db,
        user_id=ticket.executor_id,
        title=f"\u041d\u043e\u0432\u0430\u044f \u0437\u0430\u044f\u0432\u043a\u0430 #{ticket.id}",
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
        title=f"\u0412\u0430\u043c \u043d\u0430\u0437\u043d\u0430\u0447\u0435\u043d\u0430 \u0437\u0430\u044f\u0432\u043a\u0430 #{ticket.id}",
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
            title=f"\u0418\u0437\u043c\u0435\u043d\u0435\u043d \u0441\u0442\u0430\u0442\u0443\u0441 \u0437\u0430\u044f\u0432\u043a\u0438 #{ticket.id}",
            body=f"{actor.name}: {status_label_ru(old_status)} -> {status_label_ru(ticket.status)}",
            url=f"/web/tickets/{ticket.id}",
        )


def notify_comment_added(db: Session, ticket: Ticket, author: User, comment_text: str) -> None:
    short_text = (comment_text or "").strip()
    if len(short_text) > 80:
        short_text = short_text[:77] + "..."

    if ticket.executor_id and ticket.executor_id != author.id:
        send_push_to_user(
            db=db,
            user_id=ticket.executor_id,
            title=f"\u041d\u043e\u0432\u044b\u0439 \u043a\u043e\u043c\u043c\u0435\u043d\u0442\u0430\u0440\u0438\u0439 \u0432 \u0437\u0430\u044f\u0432\u043a\u0435 #{ticket.id}",
            body=short_text or f"{author.name} \u043e\u0441\u0442\u0430\u0432\u0438\u043b \u043a\u043e\u043c\u043c\u0435\u043d\u0442\u0430\u0440\u0438\u0439",
            url=f"/web/tickets/{ticket.id}",
        )

    curator_ids = [
        u.id
        for u in db.query(User).filter(User.role == Role.curator, User.company_id == ticket.company_id).all()
        if u.id != author.id
    ]
    for curator_id in curator_ids:
        send_push_to_user(
            db=db,
            user_id=curator_id,
            title=f"\u041d\u043e\u0432\u044b\u0439 \u043a\u043e\u043c\u043c\u0435\u043d\u0442\u0430\u0440\u0438\u0439 \u0432 \u0437\u0430\u044f\u0432\u043a\u0435 #{ticket.id}",
            body=short_text or f"{author.name} \u043e\u0441\u0442\u0430\u0432\u0438\u043b \u043a\u043e\u043c\u043c\u0435\u043d\u0442\u0430\u0440\u0438\u0439",
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
            title=f"\u0418\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044c \u043f\u0440\u0438\u043a\u0440\u0435\u043f\u0438\u043b \u0430\u043a\u0442 #{ticket.id}",
            body=original_name or "\u0414\u043e\u0431\u0430\u0432\u043b\u0435\u043d \u0444\u0430\u0439\u043b \u0430\u043a\u0442\u0430",
            url=f"/web/tickets/{ticket.id}",
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
                    db.query(Ticket.id, Ticket.executor_id, Ticket.deadline)
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
                        title=f"\u0421\u0440\u043e\u043a \u0437\u0430\u044f\u0432\u043a\u0438 #{t.id} \u0441\u043a\u043e\u0440\u043e \u0438\u0441\u0442\u0435\u0447\u0435\u0442",
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

def create_access_token(subject: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": subject, "exp": exp}, JWT_SECRET, algorithm=ALGORITHM)

def get_current_user(request: Request, token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    final_token = (token or "") or (request.cookies.get("access_token") or "")
    if not final_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(final_token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
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
    return user.role in (Role.admin, Role.curator)


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


def delete_company_with_data(db: Session, company_id: int) -> None:
    ticket_ids = [row[0] for row in db.query(Ticket.id).filter(Ticket.company_id == company_id).all()]
    user_ids = [row[0] for row in db.query(User.id).filter(User.company_id == company_id).all()]

    if ticket_ids:
        attachments = db.query(Attachment).filter(Attachment.ticket_id.in_(ticket_ids)).all()
        for a in attachments:
            path = resolve_attachment_disk_path(a.file_path)
            if not path:
                continue
            try:
                if path.exists():
                    path.unlink()
            except OSError:
                pass

        db.query(Comment).filter(Comment.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        db.query(Attachment).filter(Attachment.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        db.query(TicketLog).filter(TicketLog.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        db.query(TicketWatcher).filter(TicketWatcher.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)
        db.query(DeadlineReminderLog).filter(DeadlineReminderLog.ticket_id.in_(ticket_ids)).delete(synchronize_session=False)

    db.query(Ticket).filter(Ticket.company_id == company_id).delete(synchronize_session=False)
    db.query(Project).filter(Project.company_id == company_id).delete(synchronize_session=False)
    db.query(RegistrationInvite).filter(RegistrationInvite.company_id == company_id).delete(synchronize_session=False)
    db.query(Notification).filter(Notification.company_id == company_id).delete(synchronize_session=False)
    db.query(ArchiveCleanupLog).filter(ArchiveCleanupLog.company_id == company_id).delete(synchronize_session=False)
    if user_ids:
        db.query(PushSubscription).filter(PushSubscription.user_id.in_(user_ids)).delete(synchronize_session=False)
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
        if request.url.path in {"/web/login", "/web/register", "/web/register-company"}:
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
        "camera=(), microphone=(), geolocation=()",
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
    return FileResponse(PWA_STATIC_DIR / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js")
def service_worker():
    return FileResponse(PWA_STATIC_DIR / "sw.js", media_type="application/javascript")


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
    )
    db.add(owner)
    db.commit()
    db.refresh(owner)
    db.refresh(company)
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
    audit_security_event("auth_login", request, success=True, email=email, user_id=user.id)
    return TokenOut(access_token=create_access_token(str(user.id)))

# =========================
# USERS API
# =========================
@app.get("/users/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user

@app.post("/users", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db), _admin: User = Depends(require_role(Role.admin))):
    ensure_company_user(_admin)
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already exists")
    if payload.role not in (Role.curator, Role.executor):
        raise HTTPException(400, "Only CURATOR or EXECUTOR can be created")
    u = User(
        email=payload.email,
        name=payload.name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        company_id=_admin.company_id,
    )
    db.add(u); db.commit(); db.refresh(u)
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
    item = TicketType(
        company_id=_manager.company_id,
        name=name,
        description=(payload.description or "").strip() or None,
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
        payload.default_executor_id,
        payload.scope_unit_id,
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
    next_default_executor_id = incoming.get("default_executor_id", item.default_executor_id)
    next_scope_unit_id = incoming.get("scope_unit_id", item.scope_unit_id)
    validate_template_links(
        db,
        _manager.company_id,
        next_ticket_type_id,
        next_default_executor_id,
        next_scope_unit_id,
    )

    if "ticket_type_id" in incoming:
        item.ticket_type_id = incoming.get("ticket_type_id")
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
    )
    t = Ticket(
        title=title,
        description=payload.description,
        deadline=payload.deadline,
        company_id=user.company_id,
        executor_id=payload.executor_id,
        ticket_type_id=payload.ticket_type_id,
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
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="СЃРѕР·РґР°РЅРёРµ")
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
        if t.executor_id != user.id and t.created_by != user.id:
            raise HTTPException(403, "Forbidden")
        allowed = {"status", "description"}  # РјРѕР¶РЅРѕ СЂР°СЃС€РёСЂРёС‚СЊ
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
    )

    old_deadline = t.deadline
    old_executor_id = t.executor_id
    old_project_id = t.project_id
    old_ticket_type_id = t.ticket_type_id
    old_target_unit_id = t.target_unit_id
    old_template_id = t.ticket_template_id
    old_period_key = t.period_key
    old_status = t.status

    for k, v in incoming.items():
        setattr(t, k, v)

    has_specific_log = False
    if t.deadline != old_deadline:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ СЃСЂРѕРєР°")
        has_specific_log = True
    if t.executor_id != old_executor_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ РёСЃРїРѕР»РЅРёС‚РµР»СЏ")
        has_specific_log = True
    if t.project_id != old_project_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ РїСЂРѕРµРєС‚Р°")
        has_specific_log = True

    if t.ticket_type_id != old_ticket_type_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ С‚РёРїР° Р·Р°СЏРІРєРё")
        has_specific_log = True
    if t.target_unit_id != old_target_unit_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ С†РµР»РµРІРѕРіРѕ СѓР·Р»Р°")
        has_specific_log = True
    if t.ticket_template_id != old_template_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ С€Р°Р±Р»РѕРЅР° Р·Р°СЏРІРєРё")
        has_specific_log = True
    if t.period_key != old_period_key:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ РїРµСЂРёРѕРґР° С€Р°Р±Р»РѕРЅР°")
        has_specific_log = True

    if not has_specific_log:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ")

    ensure_default_ticket_watchers(db, t)
    db.commit(); db.refresh(t)
    notify_executor_reassigned(db, t, old_executor_id=old_executor_id, actor=user)
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()
    return t

@app.post("/tickets/{ticket_id}/comments", response_model=CommentOut)
def add_comment(ticket_id: int, payload: CommentCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = get_api_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    c = Comment(ticket_id=ticket_id, author_id=user.id, text=payload.text)
    db.add(c); db.commit(); db.refresh(c)
    notify_comment_added(db, ticket=t, author=user, comment_text=payload.text)
    db.commit()
    return c

@app.post("/tickets/{ticket_id}/attachments", response_model=AttachmentOut)
def upload_attachment(ticket_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = get_api_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    UPLOAD_DIR.mkdir(exist_ok=True)
    safe_name = make_safe_upload_name(file.filename)
    path = UPLOAD_DIR / safe_name
    write_upload_file(file, path)

    a = Attachment(ticket_id=ticket_id, uploader_id=user.id, file_path=f"/uploads/{safe_name}", original_name=file.filename)
    enrich_attachment_metadata(a, path)
    db.add(a)
    add_ticket_log(db, ticket_id=ticket_id, actor_id=user.id, action="РґРѕР±Р°РІР»РµРЅРёРµ С„Р°Р№Р»Р°")
    db.commit(); db.refresh(a)
    notify_curators_executor_act(db, ticket=t, uploader=user, original_name=file.filename)
    db.commit()
    return a


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
    disk_path = resolve_attachment_disk_path(a.file_path)
    if not disk_path or not disk_path.exists() or not disk_path.is_file():
        raise HTTPException(404, "Attachment file not found")

    display_name = ((a.original_name or "").strip() or disk_path.name)[:255]
    disposition = "attachment" if str(download or "").strip() == "1" else "inline"
    return FileResponse(disk_path, filename=display_name, content_disposition_type=disposition)

# =========================
# WEB UI
# =========================
@app.get("/web/login")
def web_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

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
            {"request": request, "error": "\u0421\u043b\u0438\u0448\u043a\u043e\u043c \u043c\u043d\u043e\u0433\u043e \u043f\u043e\u043f\u044b\u0442\u043e\u043a \u0432\u0445\u043e\u0434\u0430. \u041f\u043e\u043f\u0440\u043e\u0431\u0443\u0439\u0442\u0435 \u043f\u043e\u0437\u0436\u0435."},
            status_code=429,
        )

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        audit_security_event("web_login", request, success=False, email=email, detail="invalid_credentials")
        return templates.TemplateResponse("login.html", {"request": request, "error": "\u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 email \u0438\u043b\u0438 \u043f\u0430\u0440\u043e\u043b\u044c"})

    token = create_access_token(str(user.id))
    resp = RedirectResponse(url="/web", status_code=HTTP_303_SEE_OTHER)

    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    scheme = forwarded_proto or request.url.scheme

    cookie_domain = None
    if host.endswith(".servora.ru") or host == "servora.ru":
        cookie_domain = ".servora.ru"

    resp.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        secure=(scheme == "https"),
        domain=cookie_domain,
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
        )
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

    audit_security_event("web_register", request, success=True, email=email, user_id=user.id)
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "token": "", "role_value": invite.role.value, "error": None, "success": True},
    )

@app.get("/web/logout")
def web_logout():
    resp = RedirectResponse(url="/web/login", status_code=HTTP_303_SEE_OTHER)
    resp.delete_cookie("access_token")
    return resp

def _render_web_tickets_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = None,
    project_id: str | None = None,
    ticket_type_id: str | None = None,
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
    create_enabled = (not archive_mode) and user.role in (Role.admin, Role.curator, Role.executor)
    view_mode_storage_key = "tickets_view_mode_archive" if archive_mode else "tickets_view_mode"
    # 1) tickets СЃ СѓС‡РµС‚РѕРј СЂРѕР»Рё
    base_query = db.query(Ticket).filter(Ticket.company_id == user.company_id)
    if user.role == Role.executor:
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
        db.query(User.id, User.name, User.email)
        .filter(User.company_id == user.company_id, User.role == Role.executor)
        .order_by(User.id.desc())
        .all()
    )
    ticket_types = (
        db.query(TicketType.id, TicketType.name, TicketType.is_active)
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.id.desc())
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
    if target_unit_id_int is not None:
        subtree_unit_ids = resolve_scope_descendant_units(db, user.company_id, target_unit_id_int)
        if subtree_unit_ids:
            filtered_query = filtered_query.filter(Ticket.target_unit_id.in_(subtree_unit_ids))
        else:
            filtered_query = filtered_query.filter(Ticket.id == -1)
    if unit_executor_id_int is not None:
        assigned_unit_ids = [
            int(row[0])
            for row in (
                db.query(UnitAssignment.unit_id)
                .filter(
                    UnitAssignment.company_id == user.company_id,
                    UnitAssignment.user_id == unit_executor_id_int,
                    UnitAssignment.role_code == "EXECUTOR",
                )
                .all()
            )
        ]
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
    if is_manager(user):
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
        or target_unit_id_int is not None
        or unit_executor_id_int is not None
        or (executor_id or "").strip()
        or (q or "").strip()
        or overdue_enabled
        or sort_value != "id_desc"
    )
    create_form_open = create_enabled and (open_create == "1")
    create_error_value = (create_error or "") if create_enabled else ""
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
    if is_manager(user):
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
            "projects": projects,
            "executors": executors,
            "watcher_candidates": users,
            "ticket_types": ticket_types,
            "org_units": org_units,
            "users_by_id": users_by_id,
            "projects_by_id": projects_by_id,
            "ticket_types_by_id": ticket_types_by_id,
            "now": now,
            "now_plus_deadline_warning": now_plus_deadline_warning,
            "deadline_soon_warning_minutes": deadline_soon_warning_minutes,
            "status_filter": status_filter or "",
            "project_id_filter": project_id_int if project_id_int is not None else "",
            "ticket_type_id_filter": ticket_type_id_int if ticket_type_id_int is not None else "",
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
    can_manage_deadline_warning = user.role in (Role.admin, Role.curator)
    can_manage_archive_retention = user.role in (Role.admin, Role.curator)
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
            "can_manage_deadline_warning": can_manage_deadline_warning,
            "can_manage_archive_retention": can_manage_archive_retention,
            "min_deadline_soon_warning_minutes": MIN_DEADLINE_SOON_WARNING_MINUTES,
            "max_deadline_soon_warning_minutes": MAX_DEADLINE_SOON_WARNING_MINUTES,
            "min_archive_retention_days": MIN_ARCHIVE_RETENTION_DAYS,
            "max_archive_retention_days": MAX_ARCHIVE_RETENTION_DAYS,
        },
    )


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
    parsed = parse_deadline_soon_warning_minutes(form.get("deadline_soon_warning_minutes"))
    if parsed is None:
        return RedirectResponse(
            url="/web/settings?deadline_warning_error=bad_value",
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        company.deadline_soon_warning_minutes = parsed
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url="/web/settings?deadline_warning_error=save_failed",
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url="/web/settings?deadline_warning_saved=1", status_code=HTTP_303_SEE_OTHER)


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
    parsed = parse_archive_retention_days(form.get("archive_retention_days_default"))
    if parsed is None:
        return RedirectResponse(
            url="/web/settings?archive_retention_error=bad_value",
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        company.archive_retention_days_default = parsed
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url="/web/settings?archive_retention_error=save_failed",
            status_code=HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url="/web/settings?archive_retention_saved=1", status_code=HTTP_303_SEE_OTHER)


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
    edit_unit_id: str | None = None,
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)

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
        db.query(User.id, User.name, User.email)
        .filter(User.company_id == user.company_id, User.role == Role.executor)
        .order_by(User.name.asc(), User.id.asc())
        .all()
    )
    unit_labels_by_id = {
        int(u["id"]): f"{'- ' * int(u['level'])}{u['name']}" for u in ordered_units
    }
    assignment_rows = (
        db.query(
            UnitAssignment.id,
            UnitAssignment.unit_id,
            UnitAssignment.user_id,
            UnitAssignment.is_primary,
            User.name,
            User.email,
        )
        .join(User, User.id == UnitAssignment.user_id)
        .filter(
            UnitAssignment.company_id == user.company_id,
            UnitAssignment.role_code == "EXECUTOR",
        )
        .order_by(UnitAssignment.unit_id.asc(), UnitAssignment.is_primary.desc(), UnitAssignment.id.asc())
        .all()
    )
    assignments = [
        {
            "id": int(r[0]),
            "unit_id": int(r[1]),
            "user_id": int(r[2]),
            "is_primary": bool(r[3]),
            "user_name": str(r[4] or ""),
            "user_email": str(r[5] or ""),
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

    return templates.TemplateResponse(
        "org_structure.html",
        {
            "request": request,
            "user": user,
            "units": ordered_units,
            "parents": ordered_units,
            "unit_type_names": unit_type_names,
            "executors": executors,
            "assignments": assignments,
            "edit_unit": edit_unit,
            "edit_forbidden_parent_ids": edit_forbidden_parent_ids,
            "org_v2_enabled": ORG_STRUCTURE_V2_ENABLED,
            "import_report": import_report,
        },
    )


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
    name = (form.get("name") or "").strip()
    parent_raw = (form.get("parent_id") or "").strip()
    type_name = (form.get("unit_type_name") or "").strip() or "РЈР·РµР»"
    if not name:
        return RedirectResponse(url="/web/org-structure?error=empty_name", status_code=HTTP_303_SEE_OTHER)

    try:
        parent_id = int(parent_raw) if parent_raw else None
    except ValueError:
        return RedirectResponse(url="/web/org-structure?error=bad_parent", status_code=HTTP_303_SEE_OTHER)

    if parent_id is not None:
        parent = db.get(OrgUnit, parent_id)
        if not parent or parent.company_id != user.company_id:
            return RedirectResponse(url="/web/org-structure?error=parent_not_found", status_code=HTTP_303_SEE_OTHER)

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
        return RedirectResponse(url="/web/org-structure?error=create_failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


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
    unit_values_raw = [str(v).strip() for v in form.getlist("unit_ids") if str(v).strip()]
    if not unit_values_raw:
        fallback_unit_raw = (form.get("unit_id") or "").strip()
        if fallback_unit_raw:
            unit_values_raw = [fallback_unit_raw]
    executor_raw = (form.get("executor_id") or "").strip()
    is_primary = (form.get("is_primary") or "").strip() in {"1", "on", "true", "yes"}

    try:
        executor_id = int(executor_raw)
    except ValueError:
        return RedirectResponse(url="/web/org-structure?error=assign_bad_input", status_code=HTTP_303_SEE_OTHER)

    unit_ids: list[int] = []
    seen_unit_ids: set[int] = set()
    try:
        for unit_raw in unit_values_raw:
            unit_id = int(unit_raw)
            if unit_id not in seen_unit_ids:
                seen_unit_ids.add(unit_id)
                unit_ids.append(unit_id)
    except ValueError:
        return RedirectResponse(url="/web/org-structure?error=assign_bad_input", status_code=HTTP_303_SEE_OTHER)

    if not unit_ids:
        return RedirectResponse(url="/web/org-structure?error=assign_bad_input", status_code=HTTP_303_SEE_OTHER)

    executor = db.get(User, executor_id)
    if not executor or executor.company_id != user.company_id or executor.role != Role.executor:
        return RedirectResponse(url="/web/org-structure?error=assign_executor_not_found", status_code=HTTP_303_SEE_OTHER)

    found_unit_ids = {
        row[0]
        for row in (
            db.query(OrgUnit.id)
            .filter(OrgUnit.company_id == user.company_id, OrgUnit.id.in_(unit_ids))
            .all()
        )
    }
    if len(found_unit_ids) != len(unit_ids):
        return RedirectResponse(url="/web/org-structure?error=assign_unit_not_found", status_code=HTTP_303_SEE_OTHER)

    try:
        existing_rows = (
            db.query(UnitAssignment)
            .filter(
                UnitAssignment.company_id == user.company_id,
                UnitAssignment.unit_id.in_(unit_ids),
                UnitAssignment.user_id == executor_id,
                UnitAssignment.role_code == "EXECUTOR",
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
                        UnitAssignment.id != assignment_id,
                    )
                    .update({UnitAssignment.is_primary: False}, synchronize_session=False)
                )

        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/org-structure?error=assign_failed", status_code=HTTP_303_SEE_OTHER)

    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/assign/{assignment_id}/primary")
def web_org_structure_assignment_primary(
    assignment_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)

    assignment = db.get(UnitAssignment, assignment_id)
    if not assignment or assignment.company_id != user.company_id or assignment.role_code != "EXECUTOR":
        raise HTTPException(404, "Assignment not found")

    (
        db.query(UnitAssignment)
        .filter(
            UnitAssignment.company_id == user.company_id,
            UnitAssignment.unit_id == assignment.unit_id,
            UnitAssignment.role_code == "EXECUTOR",
        )
        .update({UnitAssignment.is_primary: False}, synchronize_session=False)
    )
    assignment.is_primary = True
    db.commit()
    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/assign/{assignment_id}/delete")
def web_org_structure_assignment_delete(
    assignment_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)

    assignment = db.get(UnitAssignment, assignment_id)
    if not assignment or assignment.company_id != user.company_id or assignment.role_code != "EXECUTOR":
        raise HTTPException(404, "Assignment not found")

    db.delete(assignment)
    db.commit()
    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


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

    item = db.get(OrgUnit, unit_id)
    if not item or item.company_id != user.company_id:
        return RedirectResponse(url="/web/org-structure?error=edit_not_found", status_code=HTTP_303_SEE_OTHER)

    form = await request.form()
    name = (form.get("name") or "").strip()
    parent_raw = (form.get("parent_id") or "").strip()
    type_name = (form.get("unit_type_name") or "").strip() or "РЈР·РµР»"
    is_active = (form.get("is_active") or "").strip() in {"1", "on", "true", "yes"}

    if not name:
        return RedirectResponse(
            url=f"/web/org-structure?edit_unit_id={unit_id}&error=edit_empty_name",
            status_code=HTTP_303_SEE_OTHER,
        )
    try:
        parent_id = int(parent_raw) if parent_raw else None
    except ValueError:
        return RedirectResponse(
            url=f"/web/org-structure?edit_unit_id={unit_id}&error=edit_bad_parent",
            status_code=HTTP_303_SEE_OTHER,
        )

    if parent_id is not None:
        parent = db.get(OrgUnit, parent_id)
        if not parent or parent.company_id != user.company_id:
            return RedirectResponse(
                url=f"/web/org-structure?edit_unit_id={unit_id}&error=edit_parent_not_found",
                status_code=HTTP_303_SEE_OTHER,
            )

    parent_map = build_unit_parent_map(db, user.company_id)
    if would_create_unit_cycle(parent_map, unit_id=unit_id, new_parent_id=parent_id):
        return RedirectResponse(
            url=f"/web/org-structure?edit_unit_id={unit_id}&error=edit_cycle",
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
            url=f"/web/org-structure?edit_unit_id={unit_id}&error=edit_failed",
            status_code=HTTP_303_SEE_OTHER,
        )

    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/import-csv")
async def web_org_structure_import_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)

    try:
        raw_bytes = await file.read()
    except Exception:
        return RedirectResponse(url="/web/org-structure?error=import_read_failed", status_code=HTTP_303_SEE_OTHER)
    if not raw_bytes:
        return RedirectResponse(url="/web/org-structure?error=import_empty", status_code=HTTP_303_SEE_OTHER)

    text = None
    for enc in ("utf-8-sig", "utf-8", "cp1251"):
        try:
            text = raw_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return RedirectResponse(url="/web/org-structure?error=import_encoding", status_code=HTTP_303_SEE_OTHER)

    csv_stream = io.StringIO(text)
    sample = text[:2048]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(csv_stream, dialect=dialect)
    if not reader.fieldnames:
        return RedirectResponse(url="/web/org-structure?error=import_headers", status_code=HTTP_303_SEE_OTHER)
    headers = {str(h or "").strip().lower() for h in reader.fieldnames}
    if "path" not in headers:
        return RedirectResponse(url="/web/org-structure?error=import_need_path", status_code=HTTP_303_SEE_OTHER)

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
        return RedirectResponse(url="/web/org-structure?error=import_failed", status_code=HTTP_303_SEE_OTHER)

    return RedirectResponse(
        url=(
            "/web/org-structure"
            f"?import_ok=1&import_rows={rows_total}&import_created={created_count}"
            f"&import_updated={updated_count}&import_errors={errors_count}"
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
def web_org_structure_toggle(
    unit_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)

    item = db.get(OrgUnit, unit_id)
    if not item or item.company_id != user.company_id:
        raise HTTPException(404, "Org unit not found")
    item.is_active = not bool(item.is_active)
    db.commit()
    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/org-structure/{unit_id}/delete")
def web_org_structure_delete(
    unit_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.curator)),
):
    ensure_company_user(user)
    if not ORG_STRUCTURE_V2_ENABLED:
        return RedirectResponse(url="/web/settings", status_code=HTTP_303_SEE_OTHER)

    item = db.get(OrgUnit, unit_id)
    if not item or item.company_id != user.company_id:
        return RedirectResponse(url="/web/org-structure?error=delete_not_found", status_code=HTTP_303_SEE_OTHER)

    has_children = (
        db.query(OrgUnit.id)
        .filter(OrgUnit.company_id == user.company_id, OrgUnit.parent_id == unit_id)
        .first()
        is not None
    )
    if has_children:
        return RedirectResponse(url="/web/org-structure?error=delete_has_children", status_code=HTTP_303_SEE_OTHER)

    has_assignments = (
        db.query(UnitAssignment.id)
        .filter(UnitAssignment.company_id == user.company_id, UnitAssignment.unit_id == unit_id)
        .first()
        is not None
    )
    if has_assignments:
        return RedirectResponse(url="/web/org-structure?error=delete_has_assignments", status_code=HTTP_303_SEE_OTHER)

    has_templates = (
        db.query(TicketTemplate.id)
        .filter(TicketTemplate.company_id == user.company_id, TicketTemplate.scope_unit_id == unit_id)
        .first()
        is not None
    )
    if has_templates:
        return RedirectResponse(url="/web/org-structure?error=delete_has_templates", status_code=HTTP_303_SEE_OTHER)

    has_tickets = (
        db.query(Ticket.id)
        .filter(Ticket.company_id == user.company_id, Ticket.target_unit_id == unit_id)
        .first()
        is not None
    )
    if has_tickets:
        return RedirectResponse(url="/web/org-structure?error=delete_has_tickets", status_code=HTTP_303_SEE_OTHER)

    has_generation_keys = (
        db.query(TicketGenerationKey.id)
        .filter(TicketGenerationKey.company_id == user.company_id, TicketGenerationKey.target_unit_id == unit_id)
        .first()
        is not None
    )
    if has_generation_keys:
        return RedirectResponse(
            url="/web/org-structure?error=delete_has_generation_keys",
            status_code=HTTP_303_SEE_OTHER,
        )

    try:
        db.delete(item)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/org-structure?error=delete_failed", status_code=HTTP_303_SEE_OTHER)

    return RedirectResponse(url="/web/org-structure", status_code=HTTP_303_SEE_OTHER)


@app.get("/web/admin/companies")
def web_admin_companies(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_platform_admin(user):
        raise HTTPException(403, "Only platform admin")

    companies = db.query(Company).order_by(Company.id.desc()).all()
    company_ids = [c.id for c in companies]

    users_count_by_company: dict[int, int] = {}
    projects_count_by_company: dict[int, int] = {}
    tickets_count_by_company: dict[int, int] = {}

    if company_ids:
        users_count_rows = (
            db.query(User.company_id, func.count(User.id))
            .filter(User.company_id.in_(company_ids))
            .group_by(User.company_id)
            .all()
        )
        users_count_by_company = {int(company_id): int(count_value) for company_id, count_value in users_count_rows if company_id is not None}

        projects_count_rows = (
            db.query(Project.company_id, func.count(Project.id))
            .filter(Project.company_id.in_(company_ids))
            .group_by(Project.company_id)
            .all()
        )
        projects_count_by_company = {int(company_id): int(count_value) for company_id, count_value in projects_count_rows if company_id is not None}

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
                "projects_count": projects_count_by_company.get(c.id, 0),
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
        db.query(User.id, User.name, User.email, User.role)
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
    )
    try:
        db.add(item)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=save_failed",
            status_code=HTTP_303_SEE_OTHER,
        )
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

    item.name = name
    item.email = email
    item.role = Role(role_raw)
    if password:
        item.password_hash = hash_password(password)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=f"/web/admin/companies/{company_id}/settings?err=save_failed",
            status_code=HTTP_303_SEE_OTHER,
        )
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
    # РєСѓСЂР°С‚РѕСЂ Рё РёСЃРїРѕР»РЅРёС‚РµР»СЊ РјРѕРіСѓС‚ СЃРѕР·РґР°РІР°С‚СЊ
    if user.role not in (Role.admin, Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")
    ensure_company_user(user)

    form = await request.form()

    title = normalize_ticket_title(form.get("title"))
    description = (form.get("description") or "").strip() or None

    if is_ticket_title_too_long(title):
        return RedirectResponse(url="/web?open_create=1&create_error=title_too_long", status_code=HTTP_303_SEE_OTHER)

    project_id_raw = (form.get("project_id") or "").strip()
    if not title:
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)
    project_id: int | None = None
    if project_id_raw:
        try:
            project_id = int(project_id_raw)
        except ValueError:
            return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)

    executor_id_raw = (form.get("executor_id") or "").strip()
    try:
        executor_id = int(executor_id_raw) if executor_id_raw else None
    except ValueError:
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)

    ticket_type_id_raw = (form.get("ticket_type_id") or "").strip()
    try:
        ticket_type_id = int(ticket_type_id_raw) if ticket_type_id_raw else None
    except ValueError:
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)
    target_unit_id_raw = (form.get("target_unit_id") or "").strip()
    try:
        target_unit_id = int(target_unit_id_raw) if target_unit_id_raw else None
    except ValueError:
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)
    if ORG_STRUCTURE_V2_ENABLED and target_unit_id is None:
        return RedirectResponse(url="/web?open_create=1&create_error=target_unit_required", status_code=HTTP_303_SEE_OTHER)
    if not ORG_STRUCTURE_V2_ENABLED and project_id is None:
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)

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
            return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)
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
            return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)

    # Р•СЃР»Рё СЃРѕР·РґР°С‘С‚ РёСЃРїРѕР»РЅРёС‚РµР»СЊ Рё РЅРµ РІС‹Р±СЂР°Р» РёСЃРїРѕР»РЅРёС‚РµР»СЏ вЂ” РЅР°Р·РЅР°С‡Р°РµРј РЅР° РЅРµРіРѕ
    if user.role == Role.executor and executor_id is None:
        executor_id = user.id

    deadline = parse_deadline_inputs(form.get("deadline_date"), form.get("deadline_time4"))


    try:
        validate_ticket_links(db, user.company_id, project_id, executor_id, ticket_type_id, target_unit_id)
        created_tickets: list[Ticket] = []
        if target_unit_id is not None:
            leaf_unit_ids = resolve_scope_leaf_units(db, user.company_id, target_unit_id)
            if not leaf_unit_ids:
                return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)
            batch_id = uuid.uuid4().hex
            for leaf_unit_id in leaf_unit_ids:
                resolved_project_id = get_or_create_project_for_org_unit(db, user.company_id, leaf_unit_id)
                resolved_executor_id = executor_id if executor_id is not None else get_preferred_executor_for_unit(db, user.company_id, leaf_unit_id)
                t = Ticket(
                    title=title,
                    description=description,
                    deadline=deadline,
                    company_id=user.company_id,
                    executor_id=resolved_executor_id,
                    ticket_type_id=ticket_type_id,
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
                add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="СЃРѕР·РґР°РЅРёРµ")
                created_tickets.append(t)
        else:
            # Р’РђР–РќРћ: РёРјРµРЅРЅРѕ deadline=deadline
            t = Ticket(
                title=title,
                description=description,
                deadline=deadline,
                company_id=user.company_id,
                executor_id=executor_id,
                ticket_type_id=ticket_type_id,
                project_id=project_id,
                created_by=user.id,
            )
            db.add(t)
            db.flush()
            ensure_default_ticket_watchers(db, t)
            for watcher_id in selected_watcher_ids:
                add_ticket_watcher(db, t, watcher_user_id=watcher_id, added_by=user.id)
            add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="СЃРѕР·РґР°РЅРёРµ")
            created_tickets.append(t)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)
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
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived tickets are removed by cleanup job")

    # РїСЂР°РІР°
    if is_manager(user):
        allowed = True
    elif user.role == Role.executor and t.created_by == user.id:
        allowed = True
    else:
        allowed = False

    if not allowed:
        raise HTTPException(403, "Forbidden")

    # СѓРґР°Р»СЏРµРј СЃРІСЏР·Р°РЅРЅС‹Рµ Р·Р°РїРёСЃРё РґРѕ СѓРґР°Р»РµРЅРёСЏ Р·Р°СЏРІРєРё (FK РІ Postgres)
    delete_ticket_with_related_data(db, t, remove_files=True)
    db.commit()

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback="/web")
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


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
    add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ")
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

    t = get_company_ticket_or_404(db, user, ticket_id)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    c = Comment(ticket_id=ticket_id, author_id=user.id, text=text)
    db.add(c); db.commit()
    notify_comment_added(db, ticket=t, author=user, comment_text=text)
    db.commit()

    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)

@app.post("/web/tickets/{ticket_id}/attachments")
async def web_add_attachment(ticket_id: int, request: Request, file: UploadFile = File(...),
                             db: Session = Depends(get_db), user: User = Depends(get_current_user)):

    t = get_company_ticket_or_404(db, user, ticket_id)

    # РїСЂР°РІР° (РєР°Рє Сѓ РєРѕРјРјРµРЅС‚Р°СЂРёРµРІ/СЃС‚Р°С‚СѓСЃРѕРІ)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    safe_name = make_safe_upload_name(file.filename, ticket_id=ticket_id)

    dest_path = UPLOAD_DIR / safe_name
    await write_upload_file_async(file, dest_path)

    # СЃРѕС…СЂР°РЅСЏРµРј РїСѓС‚СЊ РєР°Рє URL (СѓРґРѕР±РЅРѕ РґР»СЏ С€Р°Р±Р»РѕРЅРѕРІ)
    a = Attachment(ticket_id=ticket_id, uploader_id=user.id, file_path=f"/uploads/{safe_name}", original_name=file.filename)
    enrich_attachment_metadata(a, dest_path)
    db.add(a)
    add_ticket_log(db, ticket_id=ticket_id, actor_id=user.id, action="РґРѕР±Р°РІР»РµРЅРёРµ С„Р°Р№Р»Р°")
    db.commit()
    notify_curators_executor_act(db, ticket=t, uploader=user, original_name=file.filename)
    db.commit()

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.get("/web/tickets/{ticket_id}/edit")
def web_edit_ticket_page(ticket_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = get_company_ticket_or_404(db, user, ticket_id)
    if t.status == TicketStatus.archived:
        return RedirectResponse(url=f"/web/tickets/{ticket_id}", status_code=HTTP_303_SEE_OTHER)

    # РїСЂР°РІР° РЅР° РїСЂРѕСЃРјРѕС‚СЂ/СЂРµРґР°РєС‚РёСЂРѕРІР°РЅРёРµ
    if is_manager(user):
        can_edit_full = True
    elif user.role == Role.executor and (t.executor_id == user.id or t.created_by == user.id):
        can_edit_full = True
    else:
        raise HTTPException(403, "Forbidden")


    projects = (
        db.query(Project.id, Project.name)
        .filter(Project.company_id == user.company_id)
        .order_by(Project.id.desc())
        .all()
    )
    executors = (
        db.query(User.id, User.name, User.email)
        .filter(User.company_id == user.company_id, User.role == Role.executor)
        .order_by(User.id.desc())
        .all()
    )
    ticket_types = (
        db.query(TicketType.id, TicketType.name, TicketType.is_active)
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.id.desc())
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
            "t": t,
            "projects": projects,
            "executors": executors,
            "ticket_types": ticket_types,
            "can_edit_full": can_edit_full,
            "deadline_date": deadline_date,
            "deadline_time4": deadline_time4,
            "error": error_message,
            "max_ticket_title_len": MAX_TICKET_TITLE_LEN,
            "next_url": next_url,
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

    # РїСЂР°РІР°: РєСѓСЂР°С‚РѕСЂ вЂ” РІСЃРµРіРґР°, РёСЃРїРѕР»РЅРёС‚РµР»СЊ вЂ” С‚РѕР»СЊРєРѕ СЃРІРѕРё (СЃРѕР·РґР°Р»/РЅР°Р·РЅР°С‡РµРЅ)
    if not can_access_ticket(user, t):
        raise HTTPException(403, "Forbidden")
    if t.status == TicketStatus.archived:
        raise HTTPException(400, "Archived ticket is read-only")

    can_edit_full = is_manager(user)
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

    if is_ticket_title_too_long(title):
        edit_url = f"/web/tickets/{ticket_id}/edit?error=title_too_long&next={quote(next_url, safe='')}"
        return RedirectResponse(url=edit_url, status_code=HTTP_303_SEE_OTHER)

    old_deadline = t.deadline
    old_executor_id = t.executor_id
    old_project_id = t.project_id
    old_ticket_type_id = t.ticket_type_id
    old_status = t.status

    if status_raw:
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

        validate_ticket_links(
            db,
            user.company_id,
            project_id_candidate,
            executor_id_candidate,
            ticket_type_id_candidate,
        )

        if project_id_candidate is not None:
            t.project_id = project_id_candidate
        t.executor_id = executor_id_candidate
        t.ticket_type_id = ticket_type_id_candidate

    # Deadline (same parsing logic as create form)
    t.deadline = parse_deadline_inputs(form.get("deadline_date"), form.get("deadline_time4"))

    has_specific_log = False
    if t.deadline != old_deadline:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ СЃСЂРѕРєР°")
        has_specific_log = True
    if t.executor_id != old_executor_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ РёСЃРїРѕР»РЅРёС‚РµР»СЏ")
        has_specific_log = True
    if t.project_id != old_project_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ РїСЂРѕРµРєС‚Р°")
        has_specific_log = True

    if t.ticket_type_id != old_ticket_type_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ С‚РёРїР° Р·Р°СЏРІРєРё")
        has_specific_log = True

    if not has_specific_log:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="РёР·РјРµРЅРµРЅРёРµ")

    ensure_default_ticket_watchers(db, t)
    db.commit()          # вњ… Р±РµР· СЌС‚РѕРіРѕ РЅРµ СЃРѕС…СЂР°РЅРёС‚СЃСЏ
    db.refresh(t)
    notify_executor_reassigned(db, t, old_executor_id=old_executor_id, actor=user)
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()

    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


# ====== WEB: Projects ======
@app.get("/web/projects")
def web_projects(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    projects = (
        db.query(Project.id, Project.name, Project.description)
        .filter(Project.company_id == user.company_id)
        .order_by(Project.id.desc())
        .all()
    )
    project_deleted = (request.query_params.get("project_deleted") or "").strip() == "1"
    delete_error = (request.query_params.get("delete_error") or "").strip().lower()
    if delete_error not in {"in_use", "not_found", "failed"}:
        delete_error = ""
    return templates.TemplateResponse(
        "projects.html",
        {
            "request": request,
            "projects": projects,
            "project_deleted": project_deleted,
            "delete_error": delete_error,
        },
    )

@app.post("/web/projects/create")
async def web_projects_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    form = await request.form()
    name = (form.get("name") or "").strip()
    description = (form.get("description") or "").strip() or None
    if not name:
        return RedirectResponse(url="/web/projects", status_code=HTTP_303_SEE_OTHER)
    if db.query(Project).filter(Project.name == name, Project.company_id == user.company_id).first():
        return RedirectResponse(url="/web/projects", status_code=HTTP_303_SEE_OTHER)
    p = Project(name=name, description=description, company_id=user.company_id)
    db.add(p); db.commit()
    return RedirectResponse(url="/web/projects", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/projects/{project_id}/delete")
async def web_projects_delete(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_manager(user):
        raise HTTPException(403, "Only admin or curator")
    ensure_company_user(user)
    p = db.get(Project, project_id)
    if not p or p.company_id != user.company_id:
        return RedirectResponse(url="/web/projects?delete_error=not_found", status_code=HTTP_303_SEE_OTHER)

    has_tickets = (
        db.query(Ticket.id)
        .filter(Ticket.company_id == user.company_id, Ticket.project_id == project_id)
        .first()
    )
    if has_tickets:
        return RedirectResponse(url="/web/projects?delete_error=in_use", status_code=HTTP_303_SEE_OTHER)

    try:
        db.delete(p)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/projects?delete_error=failed", status_code=HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/web/projects?project_deleted=1", status_code=HTTP_303_SEE_OTHER)

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
            TicketType.archive_retention_days,
            TicketType.is_active,
        )
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.id.desc())
        .all()
    )
    return templates.TemplateResponse(
        "ticket_types.html",
        {
            "request": request,
            "ticket_types": ticket_types,
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
    archive_retention_days = parse_archive_retention_days(form.get("archive_retention_days"))
    if (form.get("archive_retention_days") or "").strip() and archive_retention_days is None:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    is_active = (form.get("is_active") or "1").strip() == "1"
    if not name:
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
    archive_retention_days = parse_archive_retention_days(form.get("archive_retention_days"))
    if (form.get("archive_retention_days") or "").strip() and archive_retention_days is None:
        return RedirectResponse(url="/web/ticket-types", status_code=HTTP_303_SEE_OTHER)
    is_active = (form.get("is_active") or "").strip() == "1"
    if not name:
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
        db.query(TicketType.id, TicketType.name, TicketType.is_active)
        .filter(TicketType.company_id == user.company_id)
        .order_by(TicketType.name.asc())
        .all()
    )
    org_units = (
        db.query(OrgUnit.id, OrgUnit.name, OrgUnit.parent_id, OrgUnit.is_active)
        .filter(OrgUnit.company_id == user.company_id)
        .order_by(OrgUnit.id.asc())
        .all()
    )
    executors = (
        db.query(User.id, User.name, User.email)
        .filter(User.company_id == user.company_id, User.role == Role.executor)
        .order_by(User.name.asc(), User.id.asc())
        .all()
    )
    return templates.TemplateResponse(
        "ticket_templates.html",
        {
            "request": request,
            "items": items,
            "ticket_types": ticket_types,
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
    scope_raw = (form.get("scope_unit_id") or "").strip()
    executor_raw = (form.get("default_executor_id") or "").strip()
    scope_unit_id = int(scope_raw) if scope_raw.isdigit() else None
    default_executor_id = int(executor_raw) if executor_raw.isdigit() else None
    is_active = (form.get("is_active") or "1").strip() == "1"
    validate_template_links(db, user.company_id, ticket_type_id, default_executor_id, scope_unit_id)
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
    scope_raw = (form.get("scope_unit_id") or "").strip()
    executor_raw = (form.get("default_executor_id") or "").strip()
    scope_unit_id = int(scope_raw) if scope_raw.isdigit() else None
    default_executor_id = int(executor_raw) if executor_raw.isdigit() else None
    is_active = (form.get("is_active") or "").strip() == "1"
    validate_template_links(db, user.company_id, ticket_type_id, default_executor_id, scope_unit_id)
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

    users = (
        db.query(User.id, User.name, User.email, User.role)
        .filter(
            User.company_id == user.company_id,
            User.role.in_(allowed_roles),
        )
        .order_by(User.id.desc())
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
    curators = [u for u in users if u.role == Role.curator]
    executors = [u for u in users if u.role == Role.executor]
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "user": user,
            "curators": curators,
            "executors": executors,
            "invite_links": invite_links,
            "ok": (ok or "").strip(),
            "err": (err or "").strip(),
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
    allowed_roles = manageable_roles_for_web_user_management(user)
    if not allowed_roles:
        raise HTTPException(403, "Forbidden")

    if not (name and email and password):
        return RedirectResponse(url="/web/users?err=bad_input", status_code=HTTP_303_SEE_OTHER)
    if db.query(User.id).filter(User.email == email).first():
        return RedirectResponse(url="/web/users?err=email_exists", status_code=HTTP_303_SEE_OTHER)

    if user.role == Role.curator:
        role_value = Role.executor
    else:
        if role_raw not in ("CURATOR", "EXECUTOR"):
            return RedirectResponse(url="/web/users?err=bad_role", status_code=HTTP_303_SEE_OTHER)
        role_value = Role(role_raw)
        if role_value not in allowed_roles:
            return RedirectResponse(url="/web/users?err=bad_role", status_code=HTTP_303_SEE_OTHER)

    u = User(email=email, name=name, password_hash=hash_password(password), role=role_value, company_id=user.company_id)
    try:
        db.add(u)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=save_failed", status_code=HTTP_303_SEE_OTHER)
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
    if not (name and email):
        return RedirectResponse(url="/web/users?err=bad_input", status_code=HTTP_303_SEE_OTHER)

    item = db.get(User, managed_user_id)
    if not item or not can_manage_company_user(user, item):
        return RedirectResponse(url="/web/users?err=user_not_found", status_code=HTTP_303_SEE_OTHER)

    email_owner = db.query(User.id).filter(User.email == email, User.id != item.id).first()
    if email_owner:
        return RedirectResponse(url="/web/users?err=email_exists", status_code=HTTP_303_SEE_OTHER)

    item.name = name
    item.email = email
    if password:
        item.password_hash = hash_password(password)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url="/web/users?err=save_failed", status_code=HTTP_303_SEE_OTHER)
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
            "users_by_id": users_by_id,
            "comments": comments,
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
            "watcher_user_ids": watcher_user_ids,
            "is_current_user_watcher": is_current_user_watcher,
        },
    )
