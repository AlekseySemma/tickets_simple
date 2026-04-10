import os
import unittest

os.environ.setdefault("JWT_SECRET", "x" * 40)
os.environ.setdefault("SKIP_MIGRATION_CHECK", "1")
os.environ.setdefault("DATABASE_URL", "sqlite://")

from app_support.time_support import utc_now_naive


class TimeSupportTests(unittest.TestCase):
    def test_utc_now_naive_returns_naive_datetime(self):
        value = utc_now_naive()

        self.assertIsNone(value.tzinfo)


if __name__ == "__main__":
    unittest.main()
