import os
import unittest

os.environ.setdefault("JWT_SECRET", "x" * 40)
os.environ.setdefault("SKIP_MIGRATION_CHECK", "1")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import main  # noqa: E402


class LogActionNormalizationTests(unittest.TestCase):
    def test_normalize_valid_create_action(self):
        value = main.normalize_log_action(main.LOG_ACTION_CREATED)
        self.assertEqual(value, main.LOG_ACTION_CREATED)

    def test_normalize_question_marks_to_generic_change(self):
        value = main.normalize_log_action("???? ?????")
        self.assertEqual(value, main.LOG_ACTION_CHANGED)

    def test_normalize_empty_action_to_generic_change(self):
        value = main.normalize_log_action("")
        self.assertEqual(value, main.LOG_ACTION_CHANGED)


if __name__ == "__main__":
    unittest.main()
