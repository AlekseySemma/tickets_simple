import os
import unittest
from datetime import datetime

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


class TemplateHelpersTest(unittest.TestCase):
    def test_normalize_period_key_valid(self):
        self.assertEqual(main.normalize_period_key("2026-02"), "2026-02")

    def test_normalize_period_key_invalid(self):
        self.assertIsNone(main.normalize_period_key("2026-13"))
        self.assertIsNone(main.normalize_period_key("202602"))
        self.assertIsNone(main.normalize_period_key("abc"))

    def test_render_template_value(self):
        value = main.render_template_value("TO {period} {unit_name}", "2026-02", "Store-1")
        self.assertEqual(value, "TO 2026-02 Store-1")

    def test_resolve_deadline_by_rule(self):
        base = datetime(2026, 2, 1, 10, 0)
        plus_day = main.resolve_deadline_by_rule("+1d", now_dt=base)
        plus_hours = main.resolve_deadline_by_rule("+5h", now_dt=base)
        self.assertEqual(plus_day, datetime(2026, 2, 2, 10, 0))
        self.assertEqual(plus_hours, datetime(2026, 2, 1, 15, 0))

    def test_resolve_deadline_dom_rule(self):
        base = datetime(2026, 2, 1, 10, 0)
        dom_26 = main.resolve_deadline_by_rule("dom:26", now_dt=base)
        dom_31 = main.resolve_deadline_by_rule("dom:31", now_dt=base)
        self.assertEqual(dom_26, datetime(2026, 2, 26, 23, 59))
        self.assertEqual(dom_31, datetime(2026, 2, 28, 23, 59))

    def test_ticket_title_notification_preview_truncates_to_30_chars(self):
        preview = main.ticket_title_notification_preview("12345678901234567890123456789012345", ticket_id=42)
        self.assertEqual(preview, "123456789012345678901234567...")
        self.assertEqual(len(preview), 30)

    def test_ticket_title_notification_preview_falls_back_to_ticket_id(self):
        self.assertEqual(main.ticket_title_notification_preview("", ticket_id=42), "заявка #42")

    def test_truncate_ticket_title_limits_length(self):
        title = main.truncate_ticket_title("  " + ("X" * 300) + "  ")
        self.assertEqual(title, "X" * main.MAX_TICKET_TITLE_LEN)


if __name__ == "__main__":
    unittest.main()
