from fastapi import HTTPException

from .enums import ARCHIVE_SOURCE_STATUSES, MANAGER_ROLES, Role, TicketStatus


def is_assignable_executor_user(user: object | None) -> bool:
    if not user:
        return False
    role_value = getattr(user, "role", None)
    if role_value == Role.platform_admin:
        return False
    return bool(getattr(user, "is_assignable_executor", False))


def is_admin(user) -> bool:
    return getattr(user, "role", None) == Role.admin


def is_manager(user) -> bool:
    return getattr(user, "role", None) in MANAGER_ROLES


def is_platform_admin(user) -> bool:
    return getattr(user, "role", None) == Role.platform_admin


def ensure_company_user(user) -> None:
    if is_platform_admin(user):
        return
    if getattr(user, "company_id", None) is None:
        raise HTTPException(403, "Company is not assigned")


def can_archive_ticket(user, ticket) -> bool:
    if getattr(ticket, "status", None) not in ARCHIVE_SOURCE_STATUSES:
        return False
    if is_manager(user):
        return True
    if getattr(user, "role", None) != Role.executor:
        return False
    if getattr(user, "can_view_all_tickets", False):
        return True
    return bool(getattr(ticket, "created_by", None) == getattr(user, "id", None))


def can_view_all_company_tickets(user) -> bool:
    return bool(is_manager(user) or getattr(user, "can_view_all_tickets", False))


def can_create_company_ticket(user) -> bool:
    if is_platform_admin(user):
        return False
    if is_manager(user):
        return True
    return bool(getattr(user, "role", None) == Role.executor and getattr(user, "can_create_tickets", True))


def can_close_ticket(user, ticket) -> bool:
    if is_manager(user):
        return True
    if getattr(user, "role", None) != Role.executor or not getattr(user, "can_close_tickets", True):
        return False
    if getattr(user, "can_view_all_tickets", False):
        return True
    return bool(getattr(ticket, "executor_id", None) == getattr(user, "id", None) or getattr(ticket, "created_by", None) == getattr(user, "id", None))


def can_edit_ticket(user, ticket) -> bool:
    if is_manager(user):
        return True
    return bool(getattr(user, "role", None) == Role.executor and (getattr(ticket, "executor_id", None) == getattr(user, "id", None) or getattr(ticket, "created_by", None) == getattr(user, "id", None)))


def can_delete_ticket(user, ticket) -> bool:
    if getattr(ticket, "status", None) == TicketStatus.archived:
        return is_manager(user)
    if is_manager(user):
        return True
    if getattr(user, "role", None) != Role.executor:
        return False
    if getattr(user, "can_view_all_tickets", False):
        return True
    return bool(getattr(ticket, "created_by", None) == getattr(user, "id", None))


def can_restore_ticket(user, ticket) -> bool:
    return bool(is_manager(user) and getattr(ticket, "status", None) == TicketStatus.archived)


def can_manage_ticket_legal_hold(user, ticket) -> bool:
    return bool(is_manager(user) and getattr(ticket, "status", None) == TicketStatus.archived)


def can_delete_comment(user, comment) -> bool:
    if is_manager(user):
        return True
    return bool(getattr(comment, "author_id", None) == getattr(user, "id", None))


def can_access_ticket(user, ticket) -> bool:
    if is_platform_admin(user):
        return True
    if can_view_all_company_tickets(user):
        return True
    return bool(getattr(user, "role", None) == Role.executor and (getattr(ticket, "executor_id", None) == getattr(user, "id", None) or getattr(ticket, "created_by", None) == getattr(user, "id", None)))


def can_take_ticket_in_work(user, ticket) -> bool:
    if getattr(ticket, "status", None) != TicketStatus.new:
        return False
    if not can_access_ticket(user, ticket):
        return False
    if not is_assignable_executor_user(user):
        return False
    return getattr(ticket, "executor_id", None) is None or getattr(ticket, "executor_id", None) == getattr(user, "id", None)


def can_access_receipt(user, receipt) -> bool:
    if is_platform_admin(user):
        return True
    if is_manager(user):
        return True
    return bool(getattr(user, "role", None) == Role.executor and getattr(receipt, "created_by", None) == getattr(user, "id", None))

