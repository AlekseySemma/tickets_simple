from datetime import datetime

from fastapi import Depends, HTTPException, Request


def register_push_mobile_routes(
    app,
    *,
    get_db,
    get_current_user,
    get_client_ip,
    hit_rate_limit,
    audit_security_event,
    push_is_configured,
    mobile_push_is_configured,
    send_push_to_user_report,
    send_mobile_push_to_user_report,
    normalize_mobile_platform,
    get_vapid_public_key,
    push_subscription_model,
    mobile_device_model,
    push_subscription_in_model,
    push_unsubscribe_in_model,
    mobile_device_register_in_model,
    mobile_device_unregister_in_model,
    rl_push_test_limit,
    rl_push_test_window_sec,
):
    @app.get("/api/push/public-key")
    def push_public_key(user=Depends(get_current_user)):
        if not push_is_configured():
            raise HTTPException(503, "Push is not configured")
        return {"publicKey": get_vapid_public_key(), "enabled": True, "user_id": user.id}

    @app.post("/api/push/subscribe")
    def push_subscribe(payload: push_subscription_in_model, db=Depends(get_db), user=Depends(get_current_user)):
        endpoint = (payload.endpoint or "").strip()
        p256dh = (payload.keys.get("p256dh") or "").strip()
        auth = (payload.keys.get("auth") or "").strip()
        if not endpoint or not p256dh or not auth:
            raise HTTPException(400, "Invalid subscription payload")

        existing = db.query(push_subscription_model).filter(push_subscription_model.endpoint == endpoint).first()
        if existing:
            existing.user_id = user.id
            existing.p256dh = p256dh
            existing.auth = auth
            existing.updated_at = datetime.utcnow()
        else:
            db.add(
                push_subscription_model(
                    user_id=user.id,
                    endpoint=endpoint,
                    p256dh=p256dh,
                    auth=auth,
                )
            )
        db.commit()
        return {"ok": True}

    @app.post("/api/push/unsubscribe")
    def push_unsubscribe(payload: push_unsubscribe_in_model, db=Depends(get_db), user=Depends(get_current_user)):
        endpoint = (payload.endpoint or "").strip()
        if endpoint:
            db.query(push_subscription_model).filter(
                push_subscription_model.user_id == user.id,
                push_subscription_model.endpoint == endpoint,
            ).delete(synchronize_session=False)
            db.commit()
        return {"ok": True}

    @app.post("/api/push/test")
    def push_test(request: Request, db=Depends(get_db), user=Depends(get_current_user)):
        limited_user, _ = hit_rate_limit(f"push-test-user:{user.id}", rl_push_test_limit, rl_push_test_window_sec)
        limited_ip, _ = hit_rate_limit(f"push-test-ip:{get_client_ip(request)}", rl_push_test_limit * 2, rl_push_test_window_sec)
        if limited_user or limited_ip:
            audit_security_event("push_test", request, success=False, user_id=user.id, detail="rate_limited")
            raise HTTPException(status_code=429, detail="Too many push test requests")
        if not push_is_configured():
            audit_security_event("push_test", request, success=False, user_id=user.id, detail="push_not_configured")
            raise HTTPException(503, "Push is not configured")
        report = send_push_to_user_report(
            db=db,
            user_id=user.id,
            title="Тест push",
            body=f"Проверка уведомлений для {user.name}",
            url="/web",
        )
        db.commit()
        ok_count = sum(1 for row in report if row.get("ok"))
        audit_security_event(
            "push_test",
            request,
            success=True,
            user_id=user.id,
            detail=f"sent={ok_count}/{len(report)}",
        )
        return {"ok": True, "sent": ok_count, "total": len(report), "report": report}

    @app.get("/api/push/debug")
    def push_debug(db=Depends(get_db), user=Depends(get_current_user)):
        subs = (
            db.query(push_subscription_model)
            .filter(push_subscription_model.user_id == user.id)
            .order_by(push_subscription_model.updated_at.desc())
            .all()
        )
        items = []
        for item in subs:
            endpoint = item.endpoint or ""
            masked = endpoint[:42] + ("..." if len(endpoint) > 42 else "")
            items.append(
                {
                    "id": item.id,
                    "endpoint": masked,
                    "updated_at": item.updated_at.isoformat() if item.updated_at else None,
                    "created_at": item.created_at.isoformat() if item.created_at else None,
                }
            )
        return {"user_id": user.id, "count": len(subs), "subscriptions": items}

    @app.post("/api/push/reset")
    def push_reset(db=Depends(get_db), user=Depends(get_current_user)):
        deleted = (
            db.query(push_subscription_model)
            .filter(push_subscription_model.user_id == user.id)
            .delete(synchronize_session=False)
        )
        db.commit()
        return {"ok": True, "deleted": int(deleted)}

    @app.post("/api/mobile/devices/register")
    def mobile_device_register(
        payload: mobile_device_register_in_model,
        db=Depends(get_db),
        user=Depends(get_current_user),
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
            db.query(mobile_device_model)
            .filter(mobile_device_model.platform == platform, mobile_device_model.device_id == device_id)
            .first()
        )
        existing_by_token = db.query(mobile_device_model).filter(mobile_device_model.token == token).first()

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
                mobile_device_model(
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
        payload: mobile_device_unregister_in_model,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        platform = normalize_mobile_platform(payload.platform)
        if not platform:
            raise HTTPException(400, "Unsupported mobile platform")

        query = db.query(mobile_device_model).filter(
            mobile_device_model.user_id == user.id,
            mobile_device_model.platform == platform,
        )
        token = (payload.token or "").strip()
        device_id = (payload.device_id or "").strip()
        if device_id:
            query = query.filter(mobile_device_model.device_id == device_id)
        elif token:
            query = query.filter(mobile_device_model.token == token)
        else:
            raise HTTPException(400, "Device token or device id is required")

        deleted = query.delete(synchronize_session=False)
        db.commit()
        return {"ok": True, "deleted": int(deleted)}

    @app.get("/api/mobile/devices/debug")
    def mobile_devices_debug(db=Depends(get_db), user=Depends(get_current_user)):
        devices = (
            db.query(mobile_device_model)
            .filter(mobile_device_model.user_id == user.id)
            .order_by(mobile_device_model.updated_at.desc())
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
    def mobile_push_test(request: Request, db=Depends(get_db), user=Depends(get_current_user)):
        limited_user, _ = hit_rate_limit(f"mobile-push-test-user:{user.id}", rl_push_test_limit, rl_push_test_window_sec)
        limited_ip, _ = hit_rate_limit(f"mobile-push-test-ip:{get_client_ip(request)}", rl_push_test_limit * 2, rl_push_test_window_sec)
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
