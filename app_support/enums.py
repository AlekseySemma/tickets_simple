from enum import Enum


class Role(str, Enum):
    platform_admin = "PLATFORM_ADMIN"
    admin = "ADMIN"
    curator = "CURATOR"
    executor = "EXECUTOR"


MANAGER_ROLES = (Role.admin, Role.curator)
COMPANY_ACCESS_LEVELS = (Role.admin, Role.curator, Role.executor)
ACCESS_LEVEL_LABELS_RU = {
    Role.platform_admin: "Платформенный админ",
    Role.admin: "Владелец",
    Role.curator: "Куратор",
    Role.executor: "Сотрудник",
}
MAX_ROLE_LABEL_LEN = 80
MAX_ROLE_TEMPLATE_NAME_LEN = 80
DEFAULT_ROLE_TEMPLATE_PRESETS = (
    {
        "name": "Куратор",
        "access_level": Role.curator,
        "is_assignable_executor": False,
        "show_receipts_accounting_mode": True,
        "can_view_all_tickets": True,
        "can_create_tickets": True,
        "can_close_tickets": True,
    },
    {
        "name": "Исполнитель",
        "access_level": Role.executor,
        "is_assignable_executor": True,
        "show_receipts_accounting_mode": False,
        "can_view_all_tickets": False,
        "can_create_tickets": True,
        "can_close_tickets": True,
    },
    {
        "name": "Старший исполнитель",
        "access_level": Role.executor,
        "is_assignable_executor": True,
        "show_receipts_accounting_mode": True,
        "can_view_all_tickets": True,
        "can_create_tickets": True,
        "can_close_tickets": True,
    },
)


class TicketStatus(str, Enum):
    new = "NEW"
    in_progress = "IN_PROGRESS"
    done = "DONE"
    canceled = "CANCELED"
    archived = "ARCHIVED"


class ReceiptStatus(str, Enum):
    new = "NEW"
    in_processing = "IN_PROCESSING"
    accepted = "ACCEPTED"
    rejected = "REJECTED"


STATUS_LABELS_RU = {
    TicketStatus.new: "Новая",
    TicketStatus.in_progress: "В работе",
    TicketStatus.done: "Выполнена",
    TicketStatus.canceled: "Отменена",
    TicketStatus.archived: "В архиве",
}
FINAL_TICKET_STATUSES = (TicketStatus.done, TicketStatus.canceled, TicketStatus.archived)
ARCHIVE_SOURCE_STATUSES = (TicketStatus.done, TicketStatus.canceled)
RECEIPT_STATUS_LABELS_RU = {
    ReceiptStatus.new: "Новый",
    ReceiptStatus.in_processing: "В обработке",
    ReceiptStatus.accepted: "Принят",
    ReceiptStatus.rejected: "Отклонён",
}


def status_label_ru(value: TicketStatus | str) -> str:
    if isinstance(value, TicketStatus):
        return STATUS_LABELS_RU.get(value, value.value)
    try:
        status_value = TicketStatus(value)
    except ValueError:
        return str(value)
    return STATUS_LABELS_RU.get(status_value, status_value.value)


def receipt_status_label_ru(value: ReceiptStatus | str) -> str:
    if isinstance(value, ReceiptStatus):
        return RECEIPT_STATUS_LABELS_RU.get(value, value.value)
    try:
        status_value = ReceiptStatus(value)
    except ValueError:
        return str(value)
    return RECEIPT_STATUS_LABELS_RU.get(status_value, status_value.value)


def ticket_status_change_log_action(old_status: TicketStatus | str, new_status: TicketStatus | str) -> str:
    old_label = status_label_ru(old_status)
    new_label = status_label_ru(new_status)
    return f"Изменение статуса: {old_label} -> {new_label}"


def access_level_label_ru(value: Role | str) -> str:
    if isinstance(value, Role):
        return ACCESS_LEVEL_LABELS_RU.get(value, value.value)
    try:
        role_value = Role(value)
    except ValueError:
        return str(value)
    return ACCESS_LEVEL_LABELS_RU.get(role_value, role_value.value)

