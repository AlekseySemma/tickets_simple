import os
import unittest
from datetime import datetime

os.environ.setdefault("JWT_SECRET", "x" * 40)
os.environ.setdefault("SKIP_MIGRATION_CHECK", "1")

import main  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
