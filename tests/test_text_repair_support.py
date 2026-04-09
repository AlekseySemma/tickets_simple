import os
import unittest

os.environ.setdefault("JWT_SECRET", "x" * 40)
os.environ.setdefault("SKIP_MIGRATION_CHECK", "1")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import main  # noqa: E402


class TextRepairSupportTests(unittest.TestCase):
    def test_fix_mojibake_text_handles_empty_and_plain_text(self):
        self.assertEqual(main.fix_mojibake_text(None), "")
        self.assertEqual(main.fix_mojibake_text("Привет"), "Привет")

    def test_fix_mojibake_text_repairs_common_mojibake(self):
        self.assertEqual(main.fix_mojibake_text("Ð¢ÐµÑÑ"), "Тест")


if __name__ == "__main__":
    unittest.main()
