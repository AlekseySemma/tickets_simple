import os
import unittest
from datetime import datetime

from fastapi import HTTPException

os.environ.setdefault("JWT_SECRET", "x" * 40)
os.environ.setdefault("SKIP_MIGRATION_CHECK", "1")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import main  # noqa: E402


class UiSupportTests(unittest.TestCase):
    def test_settings_and_org_urls(self):
        self.assertEqual(main.normalize_settings_section("Receipts"), "receipts")
        self.assertEqual(
            main.build_settings_url("receipts", preferred_card_saved=True),
            "/web/settings?section=receipts&preferred_card_saved=1",
        )
        self.assertEqual(main.normalize_org_structure_section("executors"), "executors")
        self.assertEqual(
            main.build_org_structure_url("nodes", edit_unit_id=7),
            "/web/org-structure?section=nodes&edit_unit_id=7",
        )

    def test_infer_org_structure_section(self):
        self.assertEqual(main.infer_org_structure_section(error="import_empty"), "import")
        self.assertEqual(main.infer_org_structure_section(edit_unit_id="5"), "nodes")
        self.assertEqual(main.infer_org_structure_section(assignment_executor_id="12"), "executors")

    def test_retention_and_warning_parsers(self):
        self.assertEqual(
            main.parse_deadline_soon_warning_minutes(str(main.MIN_DEADLINE_SOON_WARNING_MINUTES)),
            main.MIN_DEADLINE_SOON_WARNING_MINUTES,
        )
        self.assertIsNone(main.parse_deadline_soon_warning_minutes("bad"))
        self.assertEqual(
            main.parse_archive_retention_days(str(main.MIN_ARCHIVE_RETENTION_DAYS)),
            main.MIN_ARCHIVE_RETENTION_DAYS,
        )
        self.assertIsNone(main.parse_archive_retention_days("999999"))

    def test_datetime_and_deadline_helpers(self):
        base = datetime(2026, 4, 9, 10, 15)
        local_dt = main.to_local_dt(base)
        self.assertEqual(local_dt.hour, base.hour + main.LOCAL_TIME_OFFSET_HOURS)
        parsed = main.parse_deadline_inputs("2026-04-10", "930")
        self.assertEqual(parsed, datetime(2026, 4, 10, 9, 30))
        self.assertIn("09:30", main.format_deadline(datetime(2026, 4, 10, 9, 30)))

    def test_ticket_type_archive_retention_validation(self):
        self.assertEqual(
            main.normalize_ticket_type_archive_retention_days(main.MIN_ARCHIVE_RETENTION_DAYS),
            main.MIN_ARCHIVE_RETENTION_DAYS,
        )
        with self.assertRaises(HTTPException):
            main.normalize_ticket_type_archive_retention_days(main.MAX_ARCHIVE_RETENTION_DAYS + 1)


if __name__ == "__main__":
    unittest.main()
