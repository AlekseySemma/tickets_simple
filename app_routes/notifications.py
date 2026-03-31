from datetime import datetime, timedelta
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse


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


def infer_notification_kind(fix_mojibake_text, title: str | None, body: str | None, url: str | None) -> str:
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


def register_notification_routes(
    app,
    *,
    get_db,
    get_current_user,
    ensure_company_user,
    templates,
    Notification,
    func,
    fix_mojibake_text,
    http_303_see_other,
):
    @app.get("/web/notifications")
    def web_notifications(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
        status_filter: str | None = None,
        kind_filter: str | None = None,
        q: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ):
        ensure_company_user(user)
        base_query = db.query(Notification).filter(Notification.user_id == user.id)

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

        items = []
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
            item_kind = infer_notification_kind(fix_mojibake_text, item.title, item.body, item.url)
            setattr(item, "kind", item_kind)
            if kind_value != "all" and item_kind != kind_value:
                continue
            searchable_url = (item.url or "").lower()
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
        db=Depends(get_db),
        user=Depends(get_current_user),
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
        db=Depends(get_db),
        user=Depends(get_current_user),
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
        return RedirectResponse(url="/web/notifications", status_code=http_303_see_other)

    @app.post("/web/notifications/delete-all")
    def web_notifications_delete_all(
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ensure_company_user(user)
        db.query(Notification).filter(Notification.user_id == user.id).delete(synchronize_session=False)
        db.commit()
        return RedirectResponse(url="/web/notifications", status_code=http_303_see_other)

    @app.post("/web/notifications/{notification_id}/delete")
    def web_notifications_delete_one(
        notification_id: int,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ensure_company_user(user)
        item = db.get(Notification, notification_id)
        if not item or item.user_id != user.id:
            raise HTTPException(404, "Notification not found")
        db.delete(item)
        db.commit()
        return RedirectResponse(url="/web/notifications", status_code=http_303_see_other)

    @app.get("/web/notifications/{notification_id}/open")
    def web_notifications_open(
        notification_id: int,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        ensure_company_user(user)
        item = db.get(Notification, notification_id)
        if not item or item.user_id != user.id:
            raise HTTPException(404, "Notification not found")
        if not item.is_read:
            item.is_read = True
            item.read_at = datetime.utcnow()
            db.commit()
        return RedirectResponse(url=safe_notification_target(item.url), status_code=http_303_see_other)
