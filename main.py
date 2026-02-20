from datetime import datetime, timedelta
from enum import Enum
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Optional
import uuid
from urllib.parse import quote

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, String, Text, DateTime, ForeignKey, Enum as SAEnum, inspect
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
# Настройки (простые)
# =========================
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_later")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 дней
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
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

# =========================
# База данных (SQLite)
# =========================
engine_kwargs = {}
if DB_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DB_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class Base(DeclarativeBase):
    pass

# =========================
# Модели
# =========================
class Role(str, Enum):
    curator = "CURATOR"
    executor = "EXECUTOR"

class TicketStatus(str, Enum):
    new = "NEW"
    in_progress = "IN_PROGRESS"
    done = "DONE"
    canceled = "CANCELED"

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(SAEnum(Role), index=True)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)

class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    deadline: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    status: Mapped[TicketStatus] = mapped_column(SAEnum(TicketStatus), default=TicketStatus.new, index=True)

    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    executor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, default=None)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

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

Base.metadata.create_all(bind=engine)

def ensure_runtime_schema() -> None:
    insp = inspect(engine)
    cols = {c["name"] for c in insp.get_columns("attachments")}
    if "original_name" not in cols:
        with engine.begin() as conn:
            conn.exec_driver_sql("ALTER TABLE attachments ADD COLUMN original_name VARCHAR(255)")

ensure_runtime_schema()

# =========================
# Схемы API
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
    class Config:
        from_attributes = True

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    class Config:
        from_attributes = True

class TicketCreate(BaseModel):
    title: str
    description: Optional[str] = None
    deadline: Optional[datetime] = None
    executor_id: Optional[int] = None
    project_id: int

class TicketUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    deadline: Optional[datetime] = None
    executor_id: Optional[int] = None
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
    created_by: int
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
    created_at: datetime
    class Config:
        from_attributes = True

class PushSubscriptionIn(BaseModel):
    endpoint: str
    keys: dict[str, str]

class PushUnsubscribeIn(BaseModel):
    endpoint: str

# =========================
# Безопасность
# =========================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ВАЖНО: auto_error=False чтобы cookie-логин для веба работал без Bearer
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


def validate_ticket_links(db: Session, project_id: int | None, executor_id: int | None) -> None:
    if project_id is not None and not db.get(Project, project_id):
        raise HTTPException(400, "Project not found")

    if executor_id is not None:
        executor = db.get(User, executor_id)
        if not executor or executor.role != Role.executor:
            raise HTTPException(400, "Executor not found")


def make_safe_upload_name(filename: str | None, ticket_id: int | None = None) -> str:
    ext = Path(filename or "").suffix.lower()[:10]
    if not ext or ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(400, "Unsupported file type")
    prefix = f"{ticket_id}_" if ticket_id is not None else ""
    return f"{prefix}{uuid.uuid4().hex}{ext}"


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


def to_local_dt(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt + timedelta(hours=3)


def format_dt(dt: datetime | None) -> str:
    local_dt = to_local_dt(dt)
    if local_dt is None:
        return "—"

    now_local = to_local_dt(datetime.utcnow())
    if not now_local:
        return local_dt.strftime("%d.%m.%Y %H:%M")

    date_part = local_dt.date()
    now_date = now_local.date()

    if date_part == now_date:
        return local_dt.strftime("Сегодня, %H:%M")
    if date_part == (now_date - timedelta(days=1)):
        return local_dt.strftime("Вчера, %H:%M")
    if date_part == (now_date + timedelta(days=1)):
        return local_dt.strftime("Завтра, %H:%M")

    month_names = {
        1: "янв", 2: "фев", 3: "мар", 4: "апр", 5: "мая", 6: "июн",
        7: "июл", 8: "авг", 9: "сен", 10: "окт", 11: "ноя", 12: "дек",
    }

    if local_dt.year == now_local.year:
        mon = month_names.get(local_dt.month, local_dt.strftime("%m"))
        return f"{local_dt.day} {mon}, {local_dt.strftime('%H:%M')}"

    return local_dt.strftime("%d.%m.%Y %H:%M")




def format_deadline(dt: datetime | None) -> str:
    if dt is None:
        return "—"

    now_local = datetime.now()
    date_part = dt.date()
    now_date = now_local.date()

    if date_part == now_date:
        return dt.strftime("Сегодня, %H:%M")
    if date_part == (now_date - timedelta(days=1)):
        return dt.strftime("Вчера, %H:%M")
    if date_part == (now_date + timedelta(days=1)):
        return dt.strftime("Завтра, %H:%M")

    month_names = {
        1: "янв", 2: "фев", 3: "мар", 4: "апр", 5: "мая", 6: "июн",
        7: "июл", 8: "авг", 9: "сен", 10: "окт", 11: "ноя", 12: "дек",
    }

    if dt.year == now_local.year:
        mon = month_names.get(dt.month, dt.strftime("%m"))
        return f"{dt.day} {mon}, {dt.strftime('%H:%M')}"

    return dt.strftime("%d.%m.%Y %H:%M")
def add_ticket_log(db: Session, ticket_id: int, actor_id: int, action: str) -> None:
    db.add(TicketLog(ticket_id=ticket_id, actor_id=actor_id, action=action))


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
            if status_code in {404, 410}:
                db.delete(sub)
        except Exception:
            results.append({"id": sub.id, "ok": False, "status_code": "error"})
            continue
    return results


def send_push_to_user(db: Session, user_id: int, title: str, body: str, url: str) -> None:
    _ = send_push_to_user_report(db=db, user_id=user_id, title=title, body=body, url=url)


def notify_executor_new_ticket(db: Session, ticket: Ticket, actor: User) -> None:
    if not ticket.executor_id:
        return
    if ticket.executor_id == actor.id:
        return
    send_push_to_user(
        db=db,
        user_id=ticket.executor_id,
        title=f"Новая заявка #{ticket.id}",
        body=ticket.title or "Вам назначили новую заявку",
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
        title=f"Вам назначена заявка #{ticket.id}",
        body=ticket.title or "Заявка назначена на вас",
        url=f"/web/tickets/{ticket.id}",
    )


def notify_curators_status_changed(db: Session, ticket: Ticket, actor: User, old_status: TicketStatus) -> None:
    if old_status == ticket.status:
        return
    curator_ids = [u.id for u in db.query(User).filter(User.role == Role.curator).all() if u.id != actor.id]
    for curator_id in curator_ids:
        send_push_to_user(
            db=db,
            user_id=curator_id,
            title=f"Изменен статус заявки #{ticket.id}",
            body=f"{actor.name}: {old_status.value} -> {ticket.status.value}",
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
            title=f"Новый комментарий в заявке #{ticket.id}",
            body=short_text or f"{author.name} оставил комментарий",
            url=f"/web/tickets/{ticket.id}",
        )

    curator_ids = [u.id for u in db.query(User).filter(User.role == Role.curator).all() if u.id != author.id]
    for curator_id in curator_ids:
        send_push_to_user(
            db=db,
            user_id=curator_id,
            title=f"Новый комментарий в заявке #{ticket.id}",
            body=short_text or f"{author.name} оставил комментарий",
            url=f"/web/tickets/{ticket.id}",
        )


def notify_curators_executor_act(db: Session, ticket: Ticket, uploader: User, original_name: str | None) -> None:
    if uploader.role != Role.executor:
        return
    file_name = (original_name or "").lower()
    if "акт" not in file_name and "act" not in file_name:
        return
    curator_ids = [u.id for u in db.query(User).filter(User.role == Role.curator).all() if u.id != uploader.id]
    for curator_id in curator_ids:
        send_push_to_user(
            db=db,
            user_id=curator_id,
            title=f"Исполнитель прикрепил акт #{ticket.id}",
            body=original_name or "Добавлен файл акта",
            url=f"/web/tickets/{ticket.id}",
        )


def run_deadline_reminders_forever() -> None:
    while True:
        try:
            with SessionLocal() as db:
                now = datetime.now()
                horizon = now + timedelta(seconds=PUSH_REMINDER_POLL_SECONDS)
                q = db.query(Ticket).filter(
                    Ticket.executor_id.is_not(None),
                    Ticket.deadline.is_not(None),
                    Ticket.status.notin_([TicketStatus.done, TicketStatus.canceled]),
                )
                for t in q.all():
                    remind_at = t.deadline - timedelta(minutes=PUSH_REMINDER_MINUTES)
                    if not (now <= remind_at <= horizon):
                        continue
                    reminder_key = f"{t.id}:{t.executor_id}:{int(t.deadline.timestamp())}:{PUSH_REMINDER_MINUTES}"
                    already = db.query(DeadlineReminderLog).filter(
                        DeadlineReminderLog.reminder_key == reminder_key
                    ).first()
                    if already:
                        continue
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
                        title=f"Срок заявки #{t.id} скоро истечет",
                        body=f"До дедлайна осталось {PUSH_REMINDER_MINUTES} минут",
                        url=f"/web/tickets/{t.id}",
                    )
                db.commit()
        except Exception:
            pass
        time.sleep(max(5, PUSH_REMINDER_POLL_SECONDS))


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

# =========================
# Приложение
# =========================
app = FastAPI(title="Tickets Simple + Web UI")

@app.get("/")
def root(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})

@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    if request.url.path.startswith("/web") and request.method in {"POST", "PATCH", "PUT", "DELETE"}:
        if request.url.path == "/web/login":
            return await call_next(request)
        origin = (request.headers.get("origin") or "").strip()
        referer = (request.headers.get("referer") or "").strip()
        forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
        forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
        if forwarded_host:
            scheme = forwarded_proto or "https"
            host = f"{scheme}://{forwarded_host}"
        else:
            host = str(request.base_url).rstrip("/")
        if origin:
            if not origin.startswith(host):
                return JSONResponse(status_code=403, content={"detail": "CSRF blocked"})
        elif referer:
            if not referer.startswith(host):
                return JSONResponse(status_code=403, content={"detail": "CSRF blocked"})
        else:
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
PWA_STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/static", StaticFiles(directory=str(PWA_STATIC_DIR)), name="static")


templates = Jinja2Templates(directory="templates")
templates.env.globals["format_dt"] = format_dt
templates.env.globals["to_local_dt"] = to_local_dt
templates.env.globals["format_deadline"] = format_deadline


@app.on_event("startup")
def app_startup() -> None:
    if push_is_configured():
        threading.Thread(target=run_deadline_reminders_forever, daemon=True).start()



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
def push_test(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not push_is_configured():
        raise HTTPException(503, "Push is not configured")
    report = send_push_to_user_report(
        db=db,
        user_id=user.id,
        title="Тест push",
        body=f"Проверка уведомлений для {user.name}",
        url="/web",
    )
    db.commit()
    ok_count = sum(1 for r in report if r.get("ok"))
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
@app.post("/auth/bootstrap", response_model=UserOut)
def bootstrap_first_curator(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).first():
        raise HTTPException(400, "Bootstrap already done")
    if payload.role != Role.curator:
        raise HTTPException(400, "First user must be CURATOR")

    u = User(email=payload.email, name=payload.name, password_hash=hash_password(payload.password), role=payload.role)
    db.add(u); db.commit(); db.refresh(u)
    return u

@app.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return TokenOut(access_token=create_access_token(str(user.id)))

# =========================
# USERS API
# =========================
@app.get("/users/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user

@app.post("/users", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db), _curator: User = Depends(require_role(Role.curator))):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already exists")
    u = User(email=payload.email, name=payload.name, password_hash=hash_password(payload.password), role=payload.role)
    db.add(u); db.commit(); db.refresh(u)
    return u

# =========================
# PROJECTS API
# =========================
@app.post("/projects", response_model=ProjectOut)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db), _curator: User = Depends(require_role(Role.curator))):
    if db.query(Project).filter(Project.name == payload.name).first():
        raise HTTPException(400, "Project already exists")
    p = Project(name=payload.name, description=payload.description)
    db.add(p); db.commit(); db.refresh(p)
    return p

@app.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db), _u: User = Depends(get_current_user)):
    return db.query(Project).order_by(Project.id.desc()).all()

# =========================
# TICKETS API
# =========================
@app.post("/tickets", response_model=TicketOut)
def create_ticket(payload: TicketCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    validate_ticket_links(db, payload.project_id, payload.executor_id)
    t = Ticket(
        title=payload.title,
        description=payload.description,
        deadline=payload.deadline,
        executor_id=payload.executor_id,
        project_id=payload.project_id,
        created_by=user.id
    )
    db.add(t)
    db.flush()
    add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="создание")
    db.commit()
    db.refresh(t)
    notify_executor_new_ticket(db, t, user)
    db.commit()
    return t

@app.get("/tickets", response_model=list[TicketOut])
def list_tickets(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(Ticket).order_by(Ticket.id.desc())
    if user.role == Role.executor:
        q = q.filter((Ticket.executor_id == user.id) | (Ticket.created_by == user.id))
    return q.all()

@app.patch("/tickets/{ticket_id}", response_model=TicketOut)
def update_ticket(ticket_id: int, patch: TicketUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")

    incoming = patch.model_dump(exclude_unset=True)

    if user.role == Role.executor:
        if t.executor_id != user.id and t.created_by != user.id:
            raise HTTPException(403, "Forbidden")
        allowed = {"status", "description"}  # можно расширить
        incoming = {k: v for k, v in incoming.items() if k in allowed}

    validate_ticket_links(db, incoming.get("project_id"), incoming.get("executor_id"))

    old_deadline = t.deadline
    old_executor_id = t.executor_id
    old_project_id = t.project_id
    old_status = t.status

    for k, v in incoming.items():
        setattr(t, k, v)

    has_specific_log = False
    if t.deadline != old_deadline:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение срока")
        has_specific_log = True
    if t.executor_id != old_executor_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение исполнителя")
        has_specific_log = True
    if t.project_id != old_project_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение проекта")
        has_specific_log = True

    if not has_specific_log:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение")

    db.commit(); db.refresh(t)
    notify_executor_reassigned(db, t, old_executor_id=old_executor_id, actor=user)
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()
    return t

@app.post("/tickets/{ticket_id}/comments", response_model=CommentOut)
def add_comment(ticket_id: int, payload: CommentCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")
    if user.role == Role.executor and t.executor_id != user.id and t.created_by != user.id:
        raise HTTPException(403, "Forbidden")

    c = Comment(ticket_id=ticket_id, author_id=user.id, text=payload.text)
    db.add(c); db.commit(); db.refresh(c)
    notify_comment_added(db, ticket=t, author=user, comment_text=payload.text)
    db.commit()
    return c

@app.post("/tickets/{ticket_id}/attachments", response_model=AttachmentOut)
def upload_attachment(ticket_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")
    if user.role == Role.executor and t.executor_id != user.id and t.created_by != user.id:
        raise HTTPException(403, "Forbidden")

    UPLOAD_DIR.mkdir(exist_ok=True)
    safe_name = make_safe_upload_name(file.filename)
    path = UPLOAD_DIR / safe_name
    write_upload_file(file, path)

    a = Attachment(ticket_id=ticket_id, uploader_id=user.id, file_path=str(path), original_name=file.filename)
    db.add(a)
    add_ticket_log(db, ticket_id=ticket_id, actor_id=user.id, action="добавление файла")
    db.commit(); db.refresh(a)
    notify_curators_executor_act(db, ticket=t, uploader=user, original_name=file.filename)
    db.commit()
    return a

# =========================
# WEB UI
# =========================
@app.get("/web/login")
def web_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/web/login")
async def web_login(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = form.get("email")
    password = form.get("password")

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный email или пароль"})

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
    return resp

@app.get("/web/logout")
def web_logout():
    resp = RedirectResponse(url="/web/login", status_code=HTTP_303_SEE_OTHER)
    resp.delete_cookie("access_token")
    return resp

@app.get("/web")
def web_tickets(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = None,
    project_id: str | None = None,
    executor_id: str | None = None,   # <-- ДОБАВИЛИ
    q: str | None = None,
    only_overdue: str | None = None,
    sort: str | None = None,
    view_mode: str | None = None,
    open_create: str | None = None,
    page: int = 1,
):
    # 1) tickets с учетом роли
    if user.role == Role.executor:
        tickets = list(
            db.query(Ticket)
            .filter((Ticket.executor_id == user.id) | (Ticket.created_by == user.id))
            .order_by(Ticket.id.desc())
            .all()
        )
    else:
        tickets = list(db.query(Ticket).order_by(Ticket.id.desc()).all())

    # 2) данные для UI
    projects = db.query(Project).order_by(Project.id.desc()).all()
    users = db.query(User).order_by(User.id.desc()).all()
    executors = db.query(User).filter(User.role == Role.executor).order_by(User.id.desc()).all()

    users_by_id = {u.id: f"{u.name}" for u in users}
    projects_by_id = {p.id: p.name for p in projects}

    # 3) фильтры
    project_id_int: int | None = None
    if project_id is not None and str(project_id).strip() != "":
        try:
            project_id_int = int(project_id)
        except ValueError:
            project_id_int = None

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

    if status_filter:
        tickets = [t for t in tickets if t.status.value == status_filter]

    if project_id_int is not None:
        tickets = [t for t in tickets if t.project_id == project_id_int]

    # Фильтр по исполнителю — только куратор
    if user.role == Role.curator:
        if executor_none:
            tickets = [t for t in tickets if t.executor_id is None]
        elif executor_id_int is not None:
            tickets = [t for t in tickets if t.executor_id == executor_id_int]

    if q:
        q_lower = q.lower()
        tickets = [
            t for t in tickets
            if (t.title and q_lower in t.title.lower()) or (t.description and q_lower in t.description.lower())
            or (t.description is None and False)
        ]

    now = datetime.now()
    now_plus_24h = now + timedelta(hours=24)

        # только просроченные
    overdue_enabled = (only_overdue == "1")
    if overdue_enabled:
        tickets = [
            t for t in tickets
            if t.deadline and t.deadline < now and t.status not in (TicketStatus.done, TicketStatus.canceled)
        ]

        # сортировка
    sort_value = (sort or "").strip() or "id_desc"
    raw_view_mode = (view_mode or "").strip().lower()
    if user.role == Role.curator:
        view_mode_value = "cards" if raw_view_mode == "cards" else "table"
    else:
        view_mode_value = "cards"

    if sort_value == "deadline_asc":
        tickets.sort(key=lambda t: (t.deadline is None, t.deadline or datetime.max, -t.id))
    elif sort_value == "deadline_desc":
        tickets.sort(key=lambda t: (t.deadline is None, t.deadline or datetime.min, t.id), reverse=True)
    elif sort_value == "status":
        tickets.sort(key=lambda t: (t.status.value, -(t.deadline.timestamp() if t.deadline else 10**18), -t.id))
    elif sort_value == "id_asc":
        tickets.sort(key=lambda t: t.id)
    else:  # id_desc
        tickets.sort(key=lambda t: t.id, reverse=True)

    status_labels = {
        "NEW": "Новая",
        "IN_PROGRESS": "В работе",
        "DONE": "Выполнена",
        "CANCELED": "Отменена",
    }

    # Дашборд по текущему списку tickets (после фильтров)
    total_count = len(tickets)
    counts_by_status = {"NEW": 0, "IN_PROGRESS": 0, "DONE": 0, "CANCELED": 0}
    overdue_count = 0

    for t in tickets:
        code = t.status.value
        if code in counts_by_status:
            counts_by_status[code] += 1

        if t.deadline and t.deadline < now and code not in ("DONE", "CANCELED"):
            overdue_count += 1


    filters_form_open = bool(
        (status_filter or "").strip()
        or project_id_int is not None
        or (executor_id or "").strip()
        or (q or "").strip()
        or overdue_enabled
        or sort_value != "id_desc"
    )
    create_form_open = (open_create == "1")
    current_list_url = request.url.path
    if request.url.query:
        current_list_url = f"{current_list_url}?{request.url.query}"
    current_list_url_encoded = quote(current_list_url, safe="")

    # Пагинация
    per_page = 10
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    tickets = tickets[start:end]

    return templates.TemplateResponse(
        "tickets.html",
        {
            "request": request,
            "user": user,
            "tickets": tickets,
            "projects": projects,
            "executors": executors,
            "users_by_id": users_by_id,
            "projects_by_id": projects_by_id,
            "now": now,
            "now_plus_24h": now_plus_24h,
            "status_filter": status_filter or "",
            "project_id_filter": project_id_int if project_id_int is not None else "",
            "executor_id_filter": executor_id or "",  # <-- ДОБАВИЛИ (строка!)
            "q": q or "",
            "only_overdue": "1" if overdue_enabled else "",
            "sort": sort_value,
            "view_mode": view_mode_value,
            "status_labels": status_labels,
            "total_count": total_count,
            "counts_by_status": counts_by_status,
            "overdue_count": overdue_count,
            "filters_form_open": filters_form_open,
            "create_form_open": create_form_open,
            "current_list_url": current_list_url,
            "current_list_url_encoded": current_list_url_encoded,
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1,

        },
    )


@app.post("/web/tickets/create")
async def web_create_ticket(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # куратор и исполнитель могут создавать
    if user.role not in (Role.curator, Role.executor):
        raise HTTPException(403, "Forbidden")

    form = await request.form()

    title = (form.get("title") or "").strip()
    description = (form.get("description") or "").strip() or None

    project_id_raw = (form.get("project_id") or "").strip()
    if not title or not project_id_raw:
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)
    try:
        project_id = int(project_id_raw)
    except ValueError:
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)

    executor_id_raw = (form.get("executor_id") or "").strip()
    try:
        executor_id = int(executor_id_raw) if executor_id_raw else None
    except ValueError:
        return RedirectResponse(url="/web?open_create=1", status_code=HTTP_303_SEE_OTHER)

    # Если создаёт исполнитель и не выбрал исполнителя — назначаем на него
    if user.role == Role.executor and executor_id is None:
        executor_id = user.id

        # ---- СРОК (date + HHMM) ----
    deadline = None
    deadline_date = (form.get("deadline_date") or "").strip()   # YYYY-MM-DD
    time4 = (form.get("deadline_time4") or "").strip()          # 1-4 цифры

    # если дату выбрали, а время не ввели — ставим текущее время
    if deadline_date and not time4:
        time4 = datetime.now().strftime("%H%M")

    if deadline_date and time4:
        time4 = "".join(ch for ch in time4 if ch.isdigit())[:4]
        if time4:
            if len(time4) <= 2:
                hh = min(23, int(time4))
                mm = 0
                time4_fixed = f"{hh:02d}{mm:02d}"
            else:
                time4_fixed = time4.zfill(4)

            try:
                hh = min(23, int(time4_fixed[:2]))
                mm = min(59, int(time4_fixed[2:]))
                deadline = datetime.strptime(deadline_date, "%Y-%m-%d").replace(hour=hh, minute=mm)
            except ValueError:
                deadline = None


    validate_ticket_links(db, project_id, executor_id)

    # ВАЖНО: именно deadline=deadline
    t = Ticket(
        title=title,
        description=description,
        deadline=deadline,
        executor_id=executor_id,
        project_id=project_id,
        created_by=user.id,
    )
    db.add(t)
    db.flush()
    add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="создание")
    db.commit()
    notify_executor_new_ticket(db, t, user)
    db.commit()

    return RedirectResponse(url="/web", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/delete")
def web_delete_ticket(ticket_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")

    # права
    if user.role == Role.curator:
        allowed = True
    elif user.role == Role.executor and t.created_by == user.id:
        allowed = True
    else:
        allowed = False

    if not allowed:
        raise HTTPException(403, "Forbidden")

    # удаляем связанные записи (комментарии/вложения)
    db.query(Comment).filter(Comment.ticket_id == ticket_id).delete(synchronize_session=False)
    db.query(Attachment).filter(Attachment.ticket_id == ticket_id).delete(synchronize_session=False)

    db.delete(t)
    db.commit()

    return RedirectResponse(url="/web", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/status")
async def web_update_status(ticket_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")

    # права: куратор всегда, исполнитель — если заявка его (создал или назначена)
    if user.role == Role.curator:
        allowed = True
    elif user.role == Role.executor and (t.executor_id == user.id or t.created_by == user.id):
        allowed = True
    else:
        allowed = False
    if not allowed:
        raise HTTPException(403, "Forbidden")

    form = await request.form()
    status_raw = (form.get("status") or "").strip()
    if not status_raw:
        raise HTTPException(400, "Missing status")

    old_status = t.status
    t.status = TicketStatus(status_raw)
    add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение")
    db.commit()
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()

    now = datetime.now()
    is_overdue = bool(t.deadline and t.deadline < now and t.status not in (TicketStatus.done, TicketStatus.canceled))

    # если запрос пришёл через fetch (Accept: application/json) — вернём JSON
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return JSONResponse(
            {
                "ok": True,
                "ticket_id": t.id,
                "status": t.status.value,
                "is_overdue": is_overdue,
            }
        )

    # иначе обычный сценарий (перезагрузка)
    return RedirectResponse(url="/web", status_code=HTTP_303_SEE_OTHER)


@app.post("/web/tickets/{ticket_id}/comments")
async def web_add_comment(ticket_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    form = await request.form()
    
    text = (form.get("text") or "").strip()

    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")

    if user.role == Role.executor and t.executor_id != user.id and t.created_by != user.id:
        raise HTTPException(403, "Forbidden")

    c = Comment(ticket_id=ticket_id, author_id=user.id, text=text)
    db.add(c); db.commit()
    notify_comment_added(db, ticket=t, author=user, comment_text=text)
    db.commit()

    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)

@app.post("/web/tickets/{ticket_id}/attachments")
async def web_add_attachment(ticket_id: int, request: Request, file: UploadFile = File(...),
                             db: Session = Depends(get_db), user: User = Depends(get_current_user)):

    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")

    # права (как у комментариев/статусов)
    if user.role == Role.curator:
        allowed = True
    elif user.role == Role.executor and (t.executor_id == user.id or t.created_by == user.id):
        allowed = True
    else:
        allowed = False
    if not allowed:
        raise HTTPException(403, "Forbidden")

    safe_name = make_safe_upload_name(file.filename, ticket_id=ticket_id)

    dest_path = UPLOAD_DIR / safe_name
    await write_upload_file_async(file, dest_path)

    # сохраняем путь как URL (удобно для шаблонов)
    a = Attachment(ticket_id=ticket_id, uploader_id=user.id, file_path=f"/uploads/{safe_name}", original_name=file.filename)
    db.add(a)
    add_ticket_log(db, ticket_id=ticket_id, actor_id=user.id, action="добавление файла")
    db.commit()
    notify_curators_executor_act(db, ticket=t, uploader=user, original_name=file.filename)
    db.commit()

    form = await request.form()
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")
    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)


@app.get("/web/tickets/{ticket_id}/edit")
def web_edit_ticket_page(ticket_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")

    # права на просмотр/редактирование
    if user.role == Role.curator:
        can_edit_full = True
    elif user.role == Role.executor and (t.executor_id == user.id or t.created_by == user.id):
        can_edit_full = True
    else:
        raise HTTPException(403, "Forbidden")


    projects = db.query(Project).order_by(Project.id.desc()).all()
    executors = db.query(User).filter(User.role == Role.executor).order_by(User.id.desc()).all()
    next_url = request.query_params.get("next") or f"/web/tickets/{ticket_id}"
    next_url = safe_next(next_url, fallback=f"/web/tickets/{ticket_id}")


    # подготовим дату/время для формы
    deadline_date = None
    deadline_time4 = None
    if t.deadline:
        # deadline хранится в локальном времени, без UTC-смещения
        deadline_date = t.deadline.strftime("%Y-%m-%d")
        deadline_time4 = t.deadline.strftime("%H%M")

    return templates.TemplateResponse(
        "ticket_edit.html",
        {
            "request": request,
            "t": t,
            "projects": projects,
            "executors": executors,
            "can_edit_full": can_edit_full,
            "deadline_date": deadline_date,
            "deadline_time4": deadline_time4,
            "error": None,
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
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")

    # права: куратор — всегда, исполнитель — только свои (создал/назначен)
    if user.role == Role.curator:
        allowed = True
    elif user.role == Role.executor and (t.executor_id == user.id or t.created_by == user.id):
        allowed = True
    else:
        allowed = False
    if not allowed:
        raise HTTPException(403, "Forbidden")

    can_edit_full = (user.role == Role.curator)
    form = await request.form()
    status_raw = (form.get("status") or "").strip()
    next_url = safe_next(form.get("next"), fallback=f"/web/tickets/{ticket_id}")

    title = (form.get("title") or "").strip()
    description = (form.get("description") or "").strip()
    project_id_raw = (form.get("project_id") or "").strip()
    executor_id_raw = (form.get("executor_id") or "").strip()

    old_deadline = t.deadline
    old_executor_id = t.executor_id
    old_project_id = t.project_id
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

        validate_ticket_links(db, project_id_candidate, executor_id_candidate)

        if project_id_candidate is not None:
            t.project_id = project_id_candidate
        t.executor_id = executor_id_candidate

    # срок (как у создания)
    deadline = None
    deadline_date = (form.get("deadline_date") or "").strip()
    time4 = (form.get("deadline_time4") or "").strip()

    if deadline_date and not time4:
        time4 = datetime.now().strftime("%H%M")

    if deadline_date and time4:
        time4 = "".join(ch for ch in time4 if ch.isdigit())[:4]
        if time4:
            if len(time4) <= 2:
                hh = min(23, int(time4))
                mm = 0
                time4_fixed = f"{hh:02d}{mm:02d}"
            else:
                time4_fixed = time4.zfill(4)

            try:
                hh = min(23, int(time4_fixed[:2]))
                mm = min(59, int(time4_fixed[2:]))
                deadline = datetime.strptime(deadline_date, "%Y-%m-%d").replace(hour=hh, minute=mm)
            except ValueError:
                deadline = None

    t.deadline = deadline

    has_specific_log = False
    if t.deadline != old_deadline:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение срока")
        has_specific_log = True
    if t.executor_id != old_executor_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение исполнителя")
        has_specific_log = True
    if t.project_id != old_project_id:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение проекта")
        has_specific_log = True

    if not has_specific_log:
        add_ticket_log(db, ticket_id=t.id, actor_id=user.id, action="изменение")

    db.commit()          # ✅ без этого не сохранится
    db.refresh(t)
    notify_executor_reassigned(db, t, old_executor_id=old_executor_id, actor=user)
    notify_curators_status_changed(db, t, actor=user, old_status=old_status)
    db.commit()

    return RedirectResponse(url=next_url, status_code=HTTP_303_SEE_OTHER)





    # описание может менять и куратор и исполнитель (если разрешено)
    t.description = (form.get("description") or "").strip() or None

        # срок (дата + HHMM) — "человеческая" интерпретация
    deadline = None
    deadline_date = (form.get("deadline_date") or "").strip()   # YYYY-MM-DD
    time4 = (form.get("deadline_time4") or "").strip()   
        # если дату выбрали, а время не ввели — ставим текущее время
    if deadline_date and not time4:
        time4 = datetime.now().strftime("%H%M")

       # 1-4 цифры

    if deadline_date and time4:
        time4 = "".join(ch for ch in time4 if ch.isdigit())[:4]
        if time4:
            if len(time4) <= 2:
                # 9 -> 09:00, 12 -> 12:00
                hh = min(23, int(time4))
                mm = 0
                time4_fixed = f"{hh:02d}{mm:02d}"
            else:
                # 930 -> 09:30, 1234 -> 12:34
                time4_fixed = time4.zfill(4)

            try:
                hh = min(23, int(time4_fixed[:2]))
                mm = min(59, int(time4_fixed[2:]))
                deadline = datetime.strptime(deadline_date, "%Y-%m-%d").replace(hour=hh, minute=mm)
            except ValueError:
                deadline = None


    t.deadline = deadline

    if can_edit_full:
        # полное редактирование только куратор
        t.title = (form.get("title") or "").strip() or t.title

        project_id_raw = (form.get("project_id") or "").strip()
        if project_id_raw:
            t.project_id = int(project_id_raw)

        executor_id_raw = (form.get("executor_id") or "").strip()
        t.executor_id = int(executor_id_raw) if executor_id_raw else None

        status_raw = (form.get("status") or "").strip()
        if status_raw:
            t.status = TicketStatus(status_raw)

    db.commit()
    return RedirectResponse(url="/web", status_code=HTTP_303_SEE_OTHER)


# ====== WEB: Projects ======
@app.get("/web/projects")
def web_projects(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != Role.curator:
        raise HTTPException(403, "Only curator")
    projects = db.query(Project).order_by(Project.id.desc()).all()
    return templates.TemplateResponse("projects.html", {"request": request, "projects": projects})

@app.post("/web/projects/create")
async def web_projects_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != Role.curator:
        raise HTTPException(403, "Only curator")
    form = await request.form()
    name = (form.get("name") or "").strip()
    description = (form.get("description") or "").strip() or None
    if not name:
        return RedirectResponse(url="/web/projects", status_code=HTTP_303_SEE_OTHER)
    if db.query(Project).filter(Project.name == name).first():
        return RedirectResponse(url="/web/projects", status_code=HTTP_303_SEE_OTHER)
    p = Project(name=name, description=description)
    db.add(p); db.commit()
    return RedirectResponse(url="/web/projects", status_code=HTTP_303_SEE_OTHER)

# ====== WEB: Users (Executors) ======
@app.get("/web/users")
def web_users(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != Role.curator:
        raise HTTPException(403, "Only curator")
    users = db.query(User).order_by(User.id.desc()).all()
    return templates.TemplateResponse("users.html", {"request": request, "users": users})

@app.post("/web/users/create")
async def web_users_create(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != Role.curator:
        raise HTTPException(403, "Only curator")
    form = await request.form()
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip()
    password = (form.get("password") or "").strip()
    if not (name and email and password):
        return RedirectResponse(url="/web/users", status_code=HTTP_303_SEE_OTHER)
    if db.query(User).filter(User.email == email).first():
        return RedirectResponse(url="/web/users", status_code=HTTP_303_SEE_OTHER)

    u = User(email=email, name=name, password_hash=hash_password(password), role=Role.executor)
    db.add(u); db.commit()
    return RedirectResponse(url="/web/users", status_code=HTTP_303_SEE_OTHER)

@app.get("/web/tickets/{ticket_id}")
def web_ticket_detail(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")

    # права
    if user.role == Role.curator:
        allowed = True
    elif user.role == Role.executor and (t.executor_id == user.id or t.created_by == user.id):
        allowed = True
    else:
        allowed = False
    if not allowed:
        raise HTTPException(403, "Forbidden")

    projects = db.query(Project).order_by(Project.id.desc()).all()
    users = db.query(User).order_by(User.id.desc()).all()
    executors = db.query(User).filter(User.role == Role.executor).order_by(User.id.desc()).all()

    users_by_id = {u.id: f"{u.name}" for u in users}
    projects_by_id = {p.id: p.name for p in projects}

    comments = db.query(Comment).filter(Comment.ticket_id == t.id).order_by(Comment.id.asc()).all()
    attachments = db.query(Attachment).filter(Attachment.ticket_id == t.id).order_by(Attachment.id.asc()).all()
    ticket_logs = db.query(TicketLog).filter(TicketLog.ticket_id == t.id).order_by(TicketLog.id.desc()).all()

    now = datetime.now()
    is_overdue = bool(t.deadline and t.deadline < now and t.status.value not in ("DONE", "CANCELED"))
    is_deadline_soon = bool(
        t.deadline
        and not is_overdue
        and t.status.value not in ("DONE", "CANCELED")
        and t.deadline <= now + timedelta(hours=24)
    )

    status_labels = {
        "NEW": "Новая",
        "IN_PROGRESS": "В работе",
        "DONE": "Выполнена",
        "CANCELED": "Отменена",
    }

    return templates.TemplateResponse(
        "ticket_detail.html",
        {
            "request": request,
            "user": user,
            "t": t,
            "projects_by_id": projects_by_id,
            "users_by_id": users_by_id,
            "executors": executors,
            "comments": comments,
            "attachments": attachments,
            "ticket_logs": ticket_logs,
            "now": now,
            "is_overdue": is_overdue,
            "is_deadline_soon": is_deadline_soon,
            "status_labels": status_labels,
        },
    )



