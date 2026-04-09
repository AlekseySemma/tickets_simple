class UiSupport:
    def __init__(
        self,
        *,
        datetime_cls,
        timedelta_cls,
        re_module,
        urlencode_func,
        http_exception_cls,
        local_time_offset_hours: int,
        min_deadline_soon_warning_minutes: int,
        max_deadline_soon_warning_minutes: int,
        default_deadline_soon_warning_minutes: int,
        min_archive_retention_days: int,
        max_archive_retention_days: int,
        default_archive_retention_days: int,
        settings_sections,
        org_structure_sections,
        org_structure_import_errors,
        org_structure_node_errors,
        org_structure_executor_errors,
    ):
        self.datetime_cls = datetime_cls
        self.timedelta_cls = timedelta_cls
        self.re_module = re_module
        self.urlencode_func = urlencode_func
        self.http_exception_cls = http_exception_cls
        self.local_time_offset_hours = int(local_time_offset_hours)
        self.min_deadline_soon_warning_minutes = int(min_deadline_soon_warning_minutes)
        self.max_deadline_soon_warning_minutes = int(max_deadline_soon_warning_minutes)
        self.default_deadline_soon_warning_minutes = int(default_deadline_soon_warning_minutes)
        self.min_archive_retention_days = int(min_archive_retention_days)
        self.max_archive_retention_days = int(max_archive_retention_days)
        self.default_archive_retention_days = int(default_archive_retention_days)
        self.settings_sections = set(settings_sections)
        self.org_structure_sections = set(org_structure_sections)
        self.org_structure_import_errors = set(org_structure_import_errors)
        self.org_structure_node_errors = set(org_structure_node_errors)
        self.org_structure_executor_errors = set(org_structure_executor_errors)

    def to_local_dt(self, dt):
        if dt is None:
            return None
        return dt + self.timedelta_cls(hours=self.local_time_offset_hours)

    def local_now(self):
        return self.datetime_cls.utcnow() + self.timedelta_cls(hours=self.local_time_offset_hours)

    def clamp_deadline_soon_warning_minutes(self, value: int) -> int:
        return max(
            self.min_deadline_soon_warning_minutes,
            min(self.max_deadline_soon_warning_minutes, int(value)),
        )

    def parse_deadline_soon_warning_minutes(self, raw: str | None) -> int | None:
        raw_value = (raw or "").strip()
        if not raw_value:
            return None
        if not self.re_module.fullmatch(r"\d+", raw_value):
            return None
        parsed = int(raw_value)
        if (
            parsed < self.min_deadline_soon_warning_minutes
            or parsed > self.max_deadline_soon_warning_minutes
        ):
            return None
        return parsed

    def get_company_deadline_soon_warning_minutes(self, company) -> int:
        if not company or company.deadline_soon_warning_minutes is None:
            return self.default_deadline_soon_warning_minutes
        return self.clamp_deadline_soon_warning_minutes(company.deadline_soon_warning_minutes)

    def clamp_archive_retention_days(self, value: int) -> int:
        return max(
            self.min_archive_retention_days,
            min(self.max_archive_retention_days, int(value)),
        )

    def parse_archive_retention_days(self, raw: str | None) -> int | None:
        raw_value = (raw or "").strip()
        if not raw_value:
            return None
        if not self.re_module.fullmatch(r"\d+", raw_value):
            return None
        parsed = int(raw_value)
        if parsed < self.min_archive_retention_days or parsed > self.max_archive_retention_days:
            return None
        return parsed

    def get_company_archive_retention_days(self, company) -> int:
        if not company or company.archive_retention_days_default is None:
            return self.default_archive_retention_days
        return self.clamp_archive_retention_days(company.archive_retention_days_default)

    def normalize_settings_section(self, raw: str | None) -> str:
        value = (raw or "").strip().lower()
        if value in self.settings_sections:
            return value
        return ""

    def build_settings_url(self, section: str | None = None, **params: object) -> str:
        items: list[tuple[str, str]] = []
        normalized_section = self.normalize_settings_section(section)
        if normalized_section:
            items.append(("section", normalized_section))
        for key, value in params.items():
            if value is None or value is False or value == "":
                continue
            items.append((key, "1" if value is True else str(value)))
        if not items:
            return "/web/settings"
        return f"/web/settings?{self.urlencode_func(items)}"

    def normalize_org_structure_section(self, raw: str | None) -> str:
        value = (raw or "").strip().lower()
        if value in self.org_structure_sections:
            return value
        return ""

    def infer_org_structure_section(
        self,
        raw: str | None = None,
        *,
        error: str | None = None,
        import_ok: str | None = None,
        edit_unit_id: str | None = None,
        assignment_unit_id: str | None = None,
        assignment_executor_id: str | None = None,
        assignment_department_id: str | None = None,
        assignment_unit_q: str | None = None,
        assignment_executor_q: str | None = None,
        assignment_primary: str | None = None,
        assignment_page: int | None = None,
    ) -> str:
        normalized = self.normalize_org_structure_section(raw)
        if normalized:
            return normalized
        error_code = (error or "").strip().lower()
        if (import_ok or "").strip() == "1" or error_code in self.org_structure_import_errors:
            return "import"
        if (edit_unit_id or "").strip() or error_code in self.org_structure_node_errors:
            return "nodes"
        has_assignment_context = any(
            (
                (assignment_unit_id or "").strip(),
                (assignment_executor_id or "").strip(),
                (assignment_department_id or "").strip(),
                (assignment_unit_q or "").strip(),
                (assignment_executor_q or "").strip(),
                (assignment_primary or "").strip(),
                (assignment_page or 1) > 1,
            )
        )
        if has_assignment_context or error_code in self.org_structure_executor_errors:
            return "executors"
        return "nodes"

    def build_org_structure_url(self, section: str | None = None, **params: object) -> str:
        items: list[tuple[str, str]] = []
        normalized_section = self.normalize_org_structure_section(section)
        if normalized_section:
            items.append(("section", normalized_section))
        for key, value in params.items():
            if value is None or value is False or value == "":
                continue
            items.append((key, "1" if value is True else str(value)))
        if not items:
            return "/web/org-structure"
        return f"/web/org-structure?{self.urlencode_func(items)}"

    def normalize_ticket_type_archive_retention_days(self, value: int | None) -> int | None:
        if value is None:
            return None
        parsed = int(value)
        if parsed < self.min_archive_retention_days or parsed > self.max_archive_retention_days:
            raise self.http_exception_cls(
                422,
                f"archive_retention_days must be between {self.min_archive_retention_days} and {self.max_archive_retention_days}",
            )
        return parsed

    def format_dt(self, dt) -> str:
        local_dt = self.to_local_dt(dt)
        if local_dt is None:
            return "-"

        now_local = self.to_local_dt(self.datetime_cls.utcnow())
        if not now_local:
            return local_dt.strftime("%d.%m.%Y %H:%M")

        date_part = local_dt.date()
        now_date = now_local.date()

        if date_part == now_date:
            return local_dt.strftime("Сегодня, %H:%M")
        if date_part == (now_date - self.timedelta_cls(days=1)):
            return local_dt.strftime("Вчера, %H:%M")
        if date_part == (now_date + self.timedelta_cls(days=1)):
            return local_dt.strftime("Завтра, %H:%M")

        month_names = {
            1: "янв",
            2: "фев",
            3: "мар",
            4: "апр",
            5: "мая",
            6: "июн",
            7: "июл",
            8: "авг",
            9: "сен",
            10: "окт",
            11: "ноя",
            12: "дек",
        }

        if local_dt.year == now_local.year:
            mon = month_names.get(local_dt.month, local_dt.strftime("%m"))
            return f"{local_dt.day} {mon}, {local_dt.strftime('%H:%M')}"

        return local_dt.strftime("%d.%m.%Y %H:%M")

    def format_deadline(self, dt) -> str:
        if dt is None:
            return "-"

        now_local = self.local_now()
        date_part = dt.date()
        now_date = now_local.date()

        if date_part == now_date:
            return dt.strftime("Сегодня, %H:%M")
        if date_part == (now_date - self.timedelta_cls(days=1)):
            return dt.strftime("Вчера, %H:%M")
        if date_part == (now_date + self.timedelta_cls(days=1)):
            return dt.strftime("Завтра, %H:%M")

        month_names = {
            1: "янв",
            2: "фев",
            3: "мар",
            4: "апр",
            5: "мая",
            6: "июн",
            7: "июл",
            8: "авг",
            9: "сен",
            10: "окт",
            11: "ноя",
            12: "дек",
        }

        if dt.year == now_local.year:
            mon = month_names.get(dt.month, dt.strftime("%m"))
            return f"{dt.day} {mon}, {dt.strftime('%H:%M')}"

        return dt.strftime("%d.%m.%Y %H:%M")

    def parse_deadline_inputs(self, deadline_date_raw: str | None, deadline_time4_raw: str | None):
        deadline_date = (deadline_date_raw or "").strip()
        time4 = (deadline_time4_raw or "").strip()
        if not deadline_date:
            return None

        if not time4:
            time4 = self.local_now().strftime("%H%M")

        time4 = "".join(ch for ch in time4 if ch.isdigit())[:4]
        if not time4:
            return None

        if len(time4) <= 2:
            hh = min(23, int(time4))
            mm = 0
            time4_fixed = f"{hh:02d}{mm:02d}"
        else:
            time4_fixed = time4.zfill(4)

        try:
            hh = min(23, int(time4_fixed[:2]))
            mm = min(59, int(time4_fixed[2:]))
            return self.datetime_cls.strptime(deadline_date, "%Y-%m-%d").replace(hour=hh, minute=mm)
        except ValueError:
            return None
