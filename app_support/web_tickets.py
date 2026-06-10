from datetime import timedelta

from fastapi.responses import RedirectResponse


def render_web_tickets_page(
    *,
    request,
    db,
    user,
    status_filter,
    project_id,
    ticket_type_id,
    department_id,
    executor_id,
    target_unit_id,
    unit_executor_id,
    q,
    only_overdue,
    sort_ticket_type_id,
    sort,
    view_mode,
    open_create,
    create_error,
    page,
    page_size,
    archive_mode,
    is_platform_admin,
    ensure_company_user,
    get_company_deadline_soon_warning_minutes,
    can_create_company_ticket,
    query_assignable_company_users,
    resolve_scope_descendant_units,
    local_now,
    is_manager,
    templates,
    or_,
    cast,
    case,
    string_type,
    company_model,
    ticket_model,
    project_model,
    user_model,
    role_enum,
    ticket_type_model,
    department_model,
    org_unit_model,
    unit_assignment_model,
    ticket_status_enum,
    final_ticket_statuses,
    bulk_action_labels,
    max_ticket_title_len,
    org_structure_v2_enabled,
    http_303_see_other,
):
    if is_platform_admin(user):
        return RedirectResponse(url="/web/admin/companies", status_code=http_303_see_other)
    ensure_company_user(user)
    company = db.get(company_model, user.company_id) if user.company_id is not None else None
    deadline_soon_warning_minutes = get_company_deadline_soon_warning_minutes(company)
    list_path = "/web/archive" if archive_mode else "/web"
    page_title = "Архив заявок" if archive_mode else "Заявки"
    empty_text = "В архиве пока нет заявок." if archive_mode else "Заявок пока нет."
    status_filter_options = ["ARCHIVED"] if archive_mode else ["NEW", "IN_PROGRESS", "DONE", "CANCELED"]
    create_enabled = (not archive_mode) and can_create_company_ticket(user)
    view_mode_storage_key = "tickets_view_mode_archive" if archive_mode else "tickets_view_mode"

    base_query = db.query(ticket_model).filter(ticket_model.company_id == user.company_id)
    if user.role == role_enum.executor and not getattr(user, "can_view_all_tickets", False):
        base_query = base_query.filter(or_(ticket_model.executor_id == user.id, ticket_model.created_by == user.id))
    if archive_mode:
        base_query = base_query.filter(ticket_model.status == ticket_status_enum.archived)
    else:
        base_query = base_query.filter(ticket_model.status != ticket_status_enum.archived)

    projects = (
        db.query(project_model.id, project_model.name)
        .filter(project_model.company_id == user.company_id)
        .order_by(project_model.id.desc())
        .all()
    )
    users = (
        db.query(user_model.id, user_model.name, user_model.email)
        .filter(
            user_model.company_id == user.company_id,
            user_model.role.in_([role_enum.admin, role_enum.curator, role_enum.executor]),
            user_model.role != role_enum.platform_admin,
        )
        .order_by(user_model.id.desc())
        .all()
    )
    executors = query_assignable_company_users(db, user.company_id).order_by(user_model.id.desc()).all()
    ticket_types = (
        db.query(ticket_type_model.id, ticket_type_model.name, ticket_type_model.is_active, ticket_type_model.department_id)
        .filter(ticket_type_model.company_id == user.company_id)
        .order_by(ticket_type_model.id.desc())
        .all()
    )
    departments = (
        db.query(department_model.id, department_model.name, department_model.is_active)
        .filter(department_model.company_id == user.company_id)
        .order_by(department_model.name.asc(), department_model.id.asc())
        .all()
    )
    org_unit_rows = (
        db.query(org_unit_model.id, org_unit_model.name, org_unit_model.parent_id)
        .filter(org_unit_model.company_id == user.company_id, org_unit_model.is_active.is_(True))
        .order_by(org_unit_model.id.asc())
        .all()
    )
    by_parent: dict[int | None, list[tuple[int, str]]] = {}
    for unit_id, unit_name, parent_id in org_unit_rows:
        by_parent.setdefault(parent_id, []).append((int(unit_id), str(unit_name or "").strip()))
    for siblings in by_parent.values():
        siblings.sort(key=lambda item: (item[1].lower(), item[0]))

    org_units: list[dict[str, int | str]] = []
    stack: list[tuple[int, str, int, list[bool], bool]] = []
    roots = by_parent.get(None, [])
    for idx in range(len(roots) - 1, -1, -1):
        root_id, root_name = roots[idx]
        stack.append((root_id, root_name, 0, [], idx == len(roots) - 1))
    while stack:
        current_id, current_name, depth, ancestor_has_next, is_last = stack.pop()
        if depth > 0:
            tree_name = f"{'- ' * depth}{current_name}"
            short_name = f"{'- ' * depth}{current_name}"
        else:
            tree_name = current_name
            short_name = current_name
        org_units.append(
            {
                "id": current_id,
                "name": tree_name,
                "tree_name": tree_name,
                "short_name": short_name,
            }
        )
        children = by_parent.get(current_id, [])
        if depth == 0:
            child_ancestor_has_next: list[bool] = []
        else:
            child_ancestor_has_next = ancestor_has_next + [not is_last]
        for idx in range(len(children) - 1, -1, -1):
            child_id, child_name = children[idx]
            child_is_last = idx == len(children) - 1
            stack.append((child_id, child_name, depth + 1, child_ancestor_has_next, child_is_last))
    org_units_by_id = {int(item["id"]): str(item["short_name"]) for item in org_units}

    users_by_id = {item.id: f"{item.name}" for item in users}
    projects_by_id = {item.id: item.name for item in projects}
    ticket_types_by_id = {item.id: item.name for item in ticket_types}
    departments_by_id = {item.id: item.name for item in departments}

    project_id_int = _parse_optional_int(project_id)
    ticket_type_id_int = _parse_optional_int(ticket_type_id)
    sort_ticket_type_id_int = _parse_optional_int(sort_ticket_type_id)
    department_id_int = _parse_optional_int(department_id)
    target_unit_id_int = _parse_optional_int(target_unit_id)
    unit_executor_id_int = _parse_optional_int(unit_executor_id)

    executor_id_int: int | None = None
    executor_none = False
    if executor_id is not None and str(executor_id).strip() != "":
        if str(executor_id).strip() == "__none__":
            executor_none = True
        else:
            executor_id_int = _parse_optional_int(executor_id)

    filtered_query = base_query
    if status_filter:
        try:
            status_enum = ticket_status_enum(status_filter)
            if archive_mode and status_enum != ticket_status_enum.archived:
                filtered_query = filtered_query.filter(ticket_model.id == -1)
            else:
                filtered_query = filtered_query.filter(ticket_model.status == status_enum)
        except ValueError:
            filtered_query = filtered_query.filter(ticket_model.id == -1)

    if project_id_int is not None:
        filtered_query = filtered_query.filter(ticket_model.project_id == project_id_int)
    if ticket_type_id_int is not None:
        filtered_query = filtered_query.filter(ticket_model.ticket_type_id == ticket_type_id_int)
    if department_id_int is not None:
        filtered_query = filtered_query.filter(ticket_model.department_id == department_id_int)
    if target_unit_id_int is not None:
        subtree_unit_ids = resolve_scope_descendant_units(db, user.company_id, target_unit_id_int)
        if subtree_unit_ids:
            filtered_query = filtered_query.filter(ticket_model.target_unit_id.in_(subtree_unit_ids))
        else:
            filtered_query = filtered_query.filter(ticket_model.id == -1)
    if unit_executor_id_int is not None:
        assignment_query = (
            db.query(unit_assignment_model.unit_id)
            .filter(
                unit_assignment_model.company_id == user.company_id,
                unit_assignment_model.user_id == unit_executor_id_int,
                unit_assignment_model.role_code == "EXECUTOR",
            )
        )
        if department_id_int is not None:
            assignment_query = assignment_query.filter(unit_assignment_model.department_id == department_id_int)
        assigned_unit_ids = [int(row[0]) for row in assignment_query.all()]
        if assigned_unit_ids:
            filtered_query = filtered_query.filter(ticket_model.target_unit_id.in_(assigned_unit_ids))
        else:
            filtered_query = filtered_query.filter(ticket_model.id == -1)

    if is_manager(user):
        if executor_none:
            filtered_query = filtered_query.filter(ticket_model.executor_id.is_(None))
        elif executor_id_int is not None:
            filtered_query = filtered_query.filter(ticket_model.executor_id == executor_id_int)

    if q:
        q_value = q.strip()
        if q_value:
            pattern = f"%{q_value}%"
            filtered_query = filtered_query.filter(
                or_(
                    ticket_model.title.ilike(pattern),
                    ticket_model.description.ilike(pattern),
                    cast(ticket_model.id, string_type).ilike(pattern),
                )
            )

    now = local_now()
    now_plus_deadline_warning = now + timedelta(minutes=deadline_soon_warning_minutes)

    overdue_enabled = only_overdue == "1"
    if archive_mode:
        overdue_enabled = False
    if overdue_enabled:
        filtered_query = filtered_query.filter(
            ticket_model.deadline.is_not(None),
            ticket_model.deadline < now,
            ticket_model.status.notin_(list(final_ticket_statuses)),
        )

    sort_value = (sort or "").strip() or "id_desc"
    if sort_ticket_type_id_int not in ticket_types_by_id:
        sort_ticket_type_id_int = None
    raw_view_mode = (view_mode or "").strip().lower()
    can_switch_view_mode = user.role in (role_enum.admin, role_enum.curator, role_enum.executor)
    if can_switch_view_mode:
        if user.role == role_enum.executor:
            view_mode_value = "table" if raw_view_mode == "table" else "cards"
        else:
            view_mode_value = "cards" if raw_view_mode == "cards" else "table"
    else:
        view_mode_value = "cards"

    total_count = filtered_query.count()

    tickets_query = filtered_query
    priority_order = []
    if sort_ticket_type_id_int is not None:
        priority_order.append(
            case(
                (ticket_model.ticket_type_id == sort_ticket_type_id_int, 0),
                else_=1,
            ).asc()
        )
    if sort_value == "deadline_asc":
        tickets_query = tickets_query.order_by(
            *priority_order,
            ticket_model.deadline.is_(None).asc(),
            ticket_model.deadline.asc(),
            ticket_model.id.desc(),
        )
    elif sort_value == "deadline_desc":
        tickets_query = tickets_query.order_by(
            *priority_order,
            ticket_model.deadline.is_(None).desc(),
            ticket_model.deadline.desc(),
            ticket_model.id.desc(),
        )
    elif sort_value == "title_asc":
        tickets_query = tickets_query.order_by(
            *priority_order,
            ticket_model.title.asc(),
            ticket_model.id.desc(),
        )
    elif sort_value == "status":
        tickets_query = tickets_query.order_by(
            *priority_order,
            ticket_model.status.asc(),
            ticket_model.deadline.is_(None).desc(),
            ticket_model.deadline.desc(),
            ticket_model.id.desc(),
        )
    elif sort_value == "id_asc":
        tickets_query = tickets_query.order_by(*priority_order, ticket_model.id.asc())
    else:
        tickets_query = tickets_query.order_by(*priority_order, ticket_model.id.desc())

    status_labels = {
        "NEW": "Новая",
        "IN_PROGRESS": "В работе",
        "DONE": "Выполнена",
        "CANCELED": "Отменена",
        "ARCHIVED": "В архиве",
    }

    filters_form_open = bool(
        (status_filter or "").strip()
        or project_id_int is not None
        or ticket_type_id_int is not None
        or department_id_int is not None
        or sort_ticket_type_id_int is not None
        or target_unit_id_int is not None
        or unit_executor_id_int is not None
        or (executor_id or "").strip()
        or (q or "").strip()
        or overdue_enabled
        or sort_value != "id_desc"
    )
    create_form_open = create_enabled and (open_create == "1")
    create_error_value = (create_error or "") if create_enabled else ""
    bulk_action_value = (request.query_params.get("bulk_action") or "").strip().lower()
    if bulk_action_value not in bulk_action_labels:
        bulk_action_value = ""
    bulk_error_value = (request.query_params.get("bulk_error") or "").strip().lower()
    if bulk_error_value not in {"no_selection", "bad_action", "save_failed"}:
        bulk_error_value = ""

    bulk_done_count = _parse_non_negative_int(request.query_params.get("bulk_done"))
    bulk_skipped_count = _parse_non_negative_int(request.query_params.get("bulk_skipped"))
    bulk_notice = ""
    bulk_notice_level = "success"
    if (request.query_params.get("bulk_ok") or "").strip() == "1" and bulk_action_value:
        bulk_notice = (
            f"Массовое действие «{bulk_action_labels[bulk_action_value]}»: "
            f"выполнено {bulk_done_count}"
        )
        if bulk_skipped_count:
            bulk_notice += f", пропущено {bulk_skipped_count}"
            bulk_notice_level = "warning" if bulk_done_count else "danger"
    elif bulk_error_value == "no_selection":
        bulk_notice = "Выберите хотя бы одну заявку."
        bulk_notice_level = "warning"
    elif bulk_error_value == "bad_action":
        bulk_notice = "Выберите корректное действие для отмеченных заявок."
        bulk_notice_level = "warning"
    elif bulk_error_value == "save_failed":
        bulk_notice = "Не удалось выполнить массовое действие. Попробуйте еще раз."
        bulk_notice_level = "danger"

    if archive_mode:
        bulk_actions = []
        if is_manager(user):
            bulk_actions = [
                {"id": "restore", "label": "Восстановить"},
                {"id": "legal_hold_on", "label": "Включить Legal hold"},
                {"id": "legal_hold_off", "label": "Снять Legal hold"},
                {"id": "delete", "label": "Удалить навсегда"},
            ]
    else:
        bulk_actions = []
        if bool(getattr(user, "is_assignable_executor", False)):
            bulk_actions.append({"id": "take_in_work", "label": "Взять в работу"})
        if is_manager(user) or (user.role == role_enum.executor and bool(getattr(user, "can_close_tickets", True))):
            bulk_actions.append({"id": "complete", "label": "Выполнена"})
        bulk_actions.extend(
            [
                {"id": "archive", "label": "В архив"},
                {"id": "delete", "label": "Удалить"},
            ]
        )
    page_size_options = (10, 20, 30, 50, 100)
    page_size_raw = (page_size or "").strip() if page_size is not None else ""
    if not page_size_raw:
        page_size_raw = (request.cookies.get("tickets_page_size") or "").strip()
    try:
        per_page = int(page_size_raw) if page_size_raw else 10
    except ValueError:
        per_page = 10
    if per_page not in page_size_options:
        per_page = 10
    reset_filters_url = list_path
    if can_switch_view_mode:
        reset_filters_url = f"{list_path}?view_mode={view_mode_value}&page_size={per_page}"
    current_list_url = request.url.path
    if request.url.query:
        current_list_url = f"{current_list_url}?{request.url.query}"

    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    tickets = tickets_query.offset(start).limit(per_page).all()

    response = templates.TemplateResponse(
        request,
        "tickets.html",
        {
            "request": request,
            "user": user,
            "tickets": tickets,
            "list_path": list_path,
            "page_title": page_title,
            "empty_text": empty_text,
            "is_archive_page": archive_mode,
            "create_enabled": create_enabled,
            "status_filter_options": status_filter_options,
            "reset_filters_url": reset_filters_url,
            "active_list_path": "/web",
            "archive_list_path": "/web/archive",
            "view_mode_storage_key": view_mode_storage_key,
            "can_switch_view_mode": can_switch_view_mode,
            "projects": projects,
            "executors": executors,
            "watcher_candidates": users,
            "ticket_types": ticket_types,
            "departments": departments,
            "org_units": org_units,
            "users_by_id": users_by_id,
            "projects_by_id": projects_by_id,
            "ticket_types_by_id": ticket_types_by_id,
            "departments_by_id": departments_by_id,
            "target_unit_filter_label": (
                f'{org_units_by_id[target_unit_id_int]} (#{target_unit_id_int})'
                if target_unit_id_int in org_units_by_id
                else ""
            ),
            "ticket_card_fields": {
                "department": bool(getattr(user, "ticket_card_show_department", True)),
                "executor": bool(getattr(user, "ticket_card_show_executor", True)),
                "creator": bool(getattr(user, "ticket_card_show_creator", True)),
            },
            "now": now,
            "now_plus_deadline_warning": now_plus_deadline_warning,
            "deadline_soon_warning_minutes": deadline_soon_warning_minutes,
            "status_filter": status_filter or "",
            "project_id_filter": project_id_int if project_id_int is not None else "",
            "ticket_type_id_filter": ticket_type_id_int if ticket_type_id_int is not None else "",
            "sort_ticket_type_id_filter": sort_ticket_type_id_int if sort_ticket_type_id_int is not None else "",
            "department_id_filter": department_id_int if department_id_int is not None else "",
            "target_unit_id_filter": target_unit_id_int if target_unit_id_int is not None else "",
            "unit_executor_id_filter": unit_executor_id_int if unit_executor_id_int is not None else "",
            "executor_id_filter": executor_id or "",
            "q": q or "",
            "only_overdue": "1" if overdue_enabled else "",
            "sort": sort_value,
            "view_mode": view_mode_value,
            "page_size": per_page,
            "page_size_options": page_size_options,
            "status_labels": status_labels,
            "total_count": total_count,
            "filters_form_open": filters_form_open,
            "create_form_open": create_form_open,
            "create_error": create_error_value,
            "bulk_actions": bulk_actions,
            "bulk_notice": bulk_notice,
            "bulk_notice_level": bulk_notice_level,
            "max_ticket_title_len": max_ticket_title_len,
            "current_list_url": current_list_url,
            "current_list_url_encoded": _quote(current_list_url),
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1,
            "org_v2_enabled": org_structure_v2_enabled,
        },
    )
    response.set_cookie(
        "tickets_page_size",
        str(per_page),
        max_age=60 * 60 * 24 * 365,
        httponly=False,
        samesite="lax",
        path="/",
    )
    return response


def _parse_optional_int(raw_value: str | None) -> int | None:
    if raw_value is None:
        return None
    value = str(raw_value).strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_non_negative_int(raw_value: str | None) -> int:
    try:
        parsed = int((raw_value or "").strip())
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


def _quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")
