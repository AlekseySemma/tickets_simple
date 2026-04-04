import os
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("JWT_SECRET", "x" * 40)
os.environ.setdefault("SKIP_MIGRATION_CHECK", "1")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import main  # noqa: E402

main.engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
main.SessionLocal = sessionmaker(bind=main.engine, autocommit=False, autoflush=False)
main.TEXT_REPAIR_ON_START = False
main.TEMPLATE_AUTOGEN_ENABLED = False
main.push_is_configured = lambda: False
main.run_archive_cleanup_forever = lambda: None


class PublicRoutesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        cls.client_cm = TestClient(main.app)
        cls.client = cls.client_cm.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_cm.__exit__(None, None, None)

    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        with main.RATE_LIMIT_LOCK:
            main.RATE_LIMIT_BUCKETS.clear()
        self.client.cookies.clear()

    def seed_verified_user(self) -> None:
        with main.SessionLocal() as db:
            company = main.Company(name="PWA Co")
            db.add(company)
            db.flush()
            user = main.User(
                email="pwa@example.com",
                name="PWA User",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.commit()

    def login_web(self) -> None:
        response = self.client.post(
            "/web/login",
            data={"email": "pwa@example.com", "password": "secret123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_root_renders_landing_page(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Servora", response.text)

    def test_health_returns_ok(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_pwa_assets_are_served_with_expected_headers(self):
        manifest = self.client.get("/manifest.webmanifest")
        favicon = self.client.get("/favicon.ico")
        service_worker = self.client.get("/sw.js")

        self.assertEqual(manifest.status_code, 200)
        self.assertEqual(manifest.headers.get("cache-control"), "no-cache, no-store, must-revalidate")
        self.assertEqual(manifest.headers.get("content-type"), "application/manifest+json")
        self.assertEqual(favicon.status_code, 200)
        self.assertTrue((favicon.headers.get("content-type") or "").startswith("image/x-icon"))
        self.assertEqual(service_worker.status_code, 200)
        self.assertTrue((service_worker.headers.get("content-type") or "").startswith("application/javascript"))

    def test_pwa_check_requires_authentication(self):
        response = self.client.get("/web/pwa-check", follow_redirects=False)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/web/login")

    def test_pwa_check_renders_for_authenticated_user(self):
        self.seed_verified_user()
        self.login_web()

        response = self.client.get("/web/pwa-check")

        self.assertEqual(response.status_code, 200)
        self.assertIn("PWA Diagnostic", response.text)
        self.assertIn("PWA User", response.text)


if __name__ == "__main__":
    unittest.main()
