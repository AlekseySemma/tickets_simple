import os
import types
import unittest

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
main.run_archive_cleanup_forever = lambda: None


class _DummyRequest:
    def __init__(self, user_agent: str):
        self.headers = {"user-agent": user_agent}


class PushSupportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)

    def setUp(self):
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        main._FIREBASE_APP = None

    def test_android_request_detection_and_platform_normalization(self):
        request = _DummyRequest("Mozilla/5.0 ServoraAndroidApp/1.0")

        self.assertTrue(main.is_native_android_app_request(request))
        self.assertEqual(main.normalize_mobile_platform("ANDROID"), "android")
        self.assertEqual(main.normalize_mobile_platform("ios"), "")

    def test_send_push_to_user_report_drops_gone_subscription(self):
        class GonePushError(Exception):
            def __init__(self):
                self.response = types.SimpleNamespace(status_code=410)

        with main.SessionLocal() as db:
            company = main.Company(name="Push Support Co")
            db.add(company)
            db.flush()
            user = main.User(
                email="push-support@example.com",
                name="Push Support",
                password_hash=main.hash_password("secret123"),
                role=main.Role.admin,
                company_id=company.id,
                email_verified=True,
            )
            db.add(user)
            db.flush()
            db.add(
                main.PushSubscription(
                    user_id=user.id,
                    endpoint="https://push.example.test/410",
                    p256dh="p256dh-key",
                    auth="auth-key",
                )
            )
            db.commit()

            original_push_func = main._push_support.webpush_func
            original_push_exc = main._push_support.webpush_exception_cls
            original_push_check = main._push_support.push_is_configured
            original_main_push_check = main.push_is_configured
            main.push_is_configured = lambda: True
            main._push_support.push_is_configured = lambda: True
            main._push_support.webpush_func = lambda **kwargs: (_ for _ in ()).throw(GonePushError())
            main._push_support.webpush_exception_cls = GonePushError
            try:
                report = main.send_push_to_user_report(
                    db=db,
                    user_id=user.id,
                    title="Test",
                    body="Body",
                    url="/web",
                )
                db.commit()
            finally:
                main._push_support.webpush_func = original_push_func
                main._push_support.webpush_exception_cls = original_push_exc
                main._push_support.push_is_configured = original_push_check
                main.push_is_configured = original_main_push_check

        self.assertEqual(report, [{"id": 1, "ok": False, "status_code": 410}])
        with main.SessionLocal() as db:
            self.assertEqual(db.query(main.PushSubscription).count(), 0)


if __name__ == "__main__":
    unittest.main()
