import os

from fastapi import Depends, Request
from fastapi.responses import FileResponse


def public_company_registration_enabled() -> bool:
    return (os.getenv("PUBLIC_COMPANY_REGISTRATION_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"})


def register_public_routes(
    app,
    *,
    templates,
    pwa_static_dir,
    get_current_user,
):
    @app.get("/")
    def root(request: Request):
        return templates.TemplateResponse(
            request,
            "landing.html",
            {
                "request": request,
                "public_company_registration_enabled": public_company_registration_enabled(),
            },
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/manifest.webmanifest")
    def pwa_manifest():
        return FileResponse(
            pwa_static_dir / "manifest.webmanifest",
            media_type="application/manifest+json",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

    @app.get("/favicon.ico")
    def favicon():
        return FileResponse(
            pwa_static_dir / "favicon.ico",
            media_type="image/x-icon",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

    @app.get("/sw.js")
    def service_worker():
        return FileResponse(
            pwa_static_dir / "sw.js",
            media_type="application/javascript",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

    @app.get("/web/pwa-check")
    def web_pwa_check(request: Request, user=Depends(get_current_user)):
        return templates.TemplateResponse(
            request,
            "pwa_check.html",
            {
                "request": request,
                "user": user,
            },
        )
