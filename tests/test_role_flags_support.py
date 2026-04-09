import os
import unittest

os.environ.setdefault("JWT_SECRET", "x" * 40)
os.environ.setdefault("SKIP_MIGRATION_CHECK", "1")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import main  # noqa: E402


class RoleFlagsSupportTests(unittest.TestCase):
    def test_normalizers_trim_and_limit(self):
        self.assertEqual(main.normalize_role_label("  Team   Lead "), "Team Lead")
        self.assertEqual(main.normalize_role_template_name("  Basic   Template "), "Basic Template")
        self.assertIsNone(main.normalize_role_label("   "))

    def test_normalize_capability_flags_applies_role_defaults(self):
        executor_flags = main.normalize_capability_flags(main.Role.executor)
        self.assertTrue(executor_flags["is_assignable_executor"])
        self.assertFalse(executor_flags["show_receipts_accounting_mode"])

        curator_flags = main.normalize_capability_flags(main.Role.curator)
        self.assertTrue(curator_flags["can_view_all_tickets"])
        self.assertTrue(curator_flags["can_create_tickets"])
        self.assertTrue(curator_flags["can_close_tickets"])

        platform_flags = main.normalize_capability_flags(main.Role.platform_admin)
        self.assertFalse(platform_flags["is_assignable_executor"])
        self.assertFalse(platform_flags["can_view_all_tickets"])


if __name__ == "__main__":
    unittest.main()
