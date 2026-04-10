import csv
import io
from pathlib import Path

from fastapi import Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse


def register_org_structure_routes(
    app,
    *,
    get_db,
    get_current_user,
    require_role,
    ensure_company_user,
    is_admin,
    is_manager,
    infer_org_structure_section,
    build_org_structure_url,
    normalize_department_name,
    parse_bool_text,
    department_match_filter,
    query_assignable_company_users,
    resolve_target_unit_id_from_form_input,
    resolve_executor_id_from_form_input,
    build_unit_parent_map,
    would_create_unit_cycle,
    get_or_create_unit_type,
    org_structure_v2_enabled,
    org_structure_sections,
    templates,
    func,
    or_,
    company_model,
    user_model,
    department_model,
    unit_type_model,
    org_unit_model,
    unit_assignment_model,
    ticket_type_model,
    ticket_template_model,
    ticket_model,
    ticket_generation_key_model,
    role_enum,
    http_303_see_other,
    sqlalchemy_error,
):
    @app.get("/web/projects")
    def web_projects(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        return RedirectResponse(url="/web/org-structure", status_code=http_303_see_other)

    @app.post("/web/projects/create")
    async def web_projects_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        return RedirectResponse(url="/web/org-structure", status_code=http_303_see_other)

    @app.post("/web/projects/{project_id}/delete")
    async def web_projects_delete(
        project_id: int,
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if not is_manager(user):
            raise HTTPException(403, "Only admin or curator")
        ensure_company_user(user)
        return RedirectResponse(url="/web/org-structure", status_code=http_303_see_other)

    @app.get("/web/org-structure")
    def web_org_structure(
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
        section: str | None = None,
        edit_unit_id: str | None = None,
        assignment_unit_id: str | None = None,
        assignment_executor_id: str | None = None,
        assignment_department_id: str | None = None,
        assignment_unit_q: str | None = None,
        assignment_executor_q: str | None = None,
        assignment_primary: str | None = None,
        assignment_page: int = 1,
    ):
        ensure_company_user(user)
        org_v2 = bool(org_structure_v2_enabled())
        if not org_v2:
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)

        selected_org_section = infer_org_structure_section(
            section,
            error=request.query_params.get("error"),
            import_ok=request.query_params.get("import_ok"),
            edit_unit_id=edit_unit_id,
            assignment_unit_id=assignment_unit_id,
            assignment_executor_id=assignment_executor_id,
            assignment_department_id=assignment_department_id,
            assignment_unit_q=assignment_unit_q,
            assignment_executor_q=assignment_executor_q,
            assignment_primary=assignment_primary,
            assignment_page=assignment_page,
        )

        rows = (
            db.query(
                org_unit_model.id,
                org_unit_model.name,
                org_unit_model.parent_id,
                org_unit_model.unit_type_id,
                org_unit_model.is_active,
                unit_type_model.name,
            )
            .join(unit_type_model, unit_type_model.id == org_unit_model.unit_type_id)
            .filter(org_unit_model.company_id == user.company_id)
            .order_by(org_unit_model.id.asc())
            .all()
        )
        items = [
            {
                "id": row[0],
                "name": row[1],
                "parent_id": row[2],
                "unit_type_id": row[3],
                "is_active": bool(row[4]),
                "unit_type_name": row[5],
            }
            for row in rows
        ]
        by_parent: dict[int | None, list[dict]] = {}
        for item in items:
            by_parent.setdefault(item["parent_id"], []).append(item)
        for siblings in by_parent.values():
            siblings.sort(key=lambda x: (x["name"].lower(), x["id"]))

        ordered_units: list[dict] = []
        stack: list[tuple[dict, int]] = []
        for root in reversed(by_parent.get(None, [])):
            stack.append((root, 0))
        while stack:
            node, level = stack.pop()
            ordered_units.append(
                {
                    "id": node["id"],
                    "name": node["name"],
                    "parent_id": node["parent_id"],
                    "unit_type_name": node["unit_type_name"],
                    "is_active": node["is_active"],
                    "level": level,
                }
            )
            for child in reversed(by_parent.get(node["id"], [])):
                stack.append((child, level + 1))

        type_names = (
            db.query(unit_type_model.name)
            .filter(unit_type_model.company_id == user.company_id, unit_type_model.is_active.is_(True))
            .order_by(unit_type_model.name.asc())
            .all()
        )
        unit_type_names = [row[0] for row in type_names] or ["\u0423\u0437\u0435\u043b"]
        executors = query_assignable_company_users(db, user.company_id).order_by(
            user_model.name.asc(), user_model.id.asc()
        ).all()
        departments = (
            db.query(department_model.id, department_model.name, department_model.is_active)
            .filter(department_model.company_id == user.company_id)
            .order_by(department_model.name.asc(), department_model.id.asc())
            .all()
        )

        unit_children_by_id: dict[int, list[int]] = {}
        for item in items:
            parent_id = item["parent_id"]
            if parent_id is not None:
                unit_children_by_id.setdefault(int(parent_id), []).append(int(item["id"]))
        unit_labels_by_id = {
            int(unit["id"]): f"{'- ' * int(unit['level'])}{unit['name']}" for unit in ordered_units
        }

        assignment_unit_id_int = int(assignment_unit_id) if (assignment_unit_id or "").strip().isdigit() else None
        assignment_executor_id_int = (
            int(assignment_executor_id) if (assignment_executor_id or "").strip().isdigit() else None
        )
        assignment_department_filter = (assignment_department_id or "").strip()
        assignment_unit_lookup = " ".join((assignment_unit_q or "").split()).strip()
        assignment_executor_lookup = " ".join((assignment_executor_q or "").split()).strip()
        resolved_unit_id_from_lookup = (
            resolve_target_unit_id_from_form_input(db, user.company_id, assignment_unit_lookup)
            if assignment_unit_lookup
            else None
        )
        resolved_executor_id_from_lookup = (
            resolve_executor_id_from_form_input(db, user.company_id, assignment_executor_lookup)
            if assignment_executor_lookup
            else None
        )
        if assignment_unit_id_int is None and resolved_unit_id_from_lookup is not None:
            assignment_unit_id_int = resolved_unit_id_from_lookup
        if assignment_executor_id_int is None and resolved_executor_id_from_lookup is not None:
            assignment_executor_id_int = resolved_executor_id_from_lookup

        assignment_unit_query = assignment_unit_lookup.lower() if assignment_unit_id_int is None else ""
        assignment_executor_query = assignment_executor_lookup.lower() if assignment_executor_id_int is None else ""
        assignment_department_id_int = (
            int(assignment_department_filter) if assignment_department_filter.isdigit() else None
        )
        assignment_without_department = assignment_department_filter == "__none__"
        assignment_only_primary = (assignment_primary or "").strip() in {"1", "true", "on", "yes"}

        filtered_unit_ids: set[int] | None = None
        if assignment_unit_id_int is not None and assignment_unit_id_int in unit_labels_by_id:
            filtered_unit_ids = set()
            stack_ids = [assignment_unit_id_int]
            while stack_ids:
                current_id = stack_ids.pop()
                if current_id in filtered_unit_ids:
                    continue
                filtered_unit_ids.add(current_id)
                stack_ids.extend(unit_children_by_id.get(current_id, []))

        assignment_query = (
            db.query(
                unit_assignment_model.id,
                unit_assignment_model.unit_id,
                unit_assignment_model.user_id,
                unit_assignment_model.department_id,
                unit_assignment_model.is_primary,
                department_model.name,
                user_model.name,
                user_model.email,
            )
            .join(user_model, user_model.id == unit_assignment_model.user_id)
            .outerjoin(department_model, department_model.id == unit_assignment_model.department_id)
            .filter(
                unit_assignment_model.company_id == user.company_id,
                unit_assignment_model.role_code == "EXECUTOR",
            )
        )
        assignments_total_all = assignment_query.count()
        if filtered_unit_ids is not None:
            assignment_query = assignment_query.filter(unit_assignment_model.unit_id.in_(sorted(filtered_unit_ids)))
        if assignment_unit_query:
            matched_unit_ids = [
                int(unit["id"])
                for unit in ordered_units
                if assignment_unit_query in str(unit["name"] or "").strip().lower()
                or assignment_unit_query in unit_labels_by_id.get(int(unit["id"]), "").lower()
            ]
            if matched_unit_ids:
                assignment_query = assignment_query.filter(unit_assignment_model.unit_id.in_(matched_unit_ids))
            else:
                assignment_query = assignment_query.filter(unit_assignment_model.id == -1)
        if assignment_executor_id_int is not None:
            assignment_query = assignment_query.filter(unit_assignment_model.user_id == assignment_executor_id_int)
        if assignment_executor_query:
            assignment_query = assignment_query.filter(
                or_(
                    func.lower(user_model.name).like(f"%{assignment_executor_query}%"),
                    func.lower(user_model.email).like(f"%{assignment_executor_query}%"),
                )
            )
        if assignment_without_department:
            assignment_query = assignment_query.filter(unit_assignment_model.department_id.is_(None))
        elif assignment_department_id_int is not None:
            assignment_query = assignment_query.filter(unit_assignment_model.department_id == assignment_department_id_int)
        if assignment_only_primary:
            assignment_query = assignment_query.filter(unit_assignment_model.is_primary.is_(True))

        assignment_filters_active = bool(
            assignment_unit_id_int is not None
            or assignment_executor_id_int is not None
            or assignment_department_filter
            or bool(assignment_unit_query)
            or bool(assignment_executor_query)
            or assignment_only_primary
        )
        assignments_total = assignment_query.count()
        assignments_per_page = 40
        assignments_total_pages = max(1, (assignments_total + assignments_per_page - 1) // assignments_per_page)
        assignment_page = max(1, min(assignment_page, assignments_total_pages))
        assignment_rows = (
            assignment_query
            .order_by(
                unit_assignment_model.unit_id.asc(),
                unit_assignment_model.is_primary.desc(),
                unit_assignment_model.id.asc(),
            )
            .offset((assignment_page - 1) * assignments_per_page)
            .limit(assignments_per_page)
            .all()
        )
        assignments = [
            {
                "id": int(row[0]),
                "unit_id": int(row[1]),
                "user_id": int(row[2]),
                "department_id": int(row[3]) if row[3] is not None else None,
                "is_primary": bool(row[4]),
                "department_name": str(row[5] or "").strip() or "\u0411\u0435\u0437 \u043e\u0442\u0434\u0435\u043b\u0430",
                "user_name": str(row[6] or ""),
                "user_email": str(row[7] or ""),
                "unit_label": unit_labels_by_id.get(int(row[1]), f"Unit #{int(row[1])}"),
            }
            for row in assignment_rows
        ]

        edit_unit = None
        edit_forbidden_parent_ids: set[int] = set()
        if edit_unit_id and edit_unit_id.strip():
            try:
                edit_id_int = int(edit_unit_id)
            except ValueError:
                edit_id_int = None
            if edit_id_int is not None:
                found = next((unit for unit in ordered_units if int(unit["id"]) == edit_id_int), None)
                if found:
                    edit_unit = {
                        "id": int(found["id"]),
                        "name": str(found["name"]),
                        "parent_id": found["parent_id"],
                        "unit_type_name": str(found["unit_type_name"]),
                        "is_active": bool(found["is_active"]),
                    }
                    edit_forbidden_parent_ids.add(edit_unit["id"])
                    stack_ids = [edit_unit["id"]]
                    children_by_parent: dict[int, list[int]] = {}
                    for unit in ordered_units:
                        parent_id = unit["parent_id"]
                        if parent_id is None:
                            continue
                        children_by_parent.setdefault(int(parent_id), []).append(int(unit["id"]))
                    while stack_ids:
                        current_id = stack_ids.pop()
                        for child_id in children_by_parent.get(current_id, []):
                            if child_id in edit_forbidden_parent_ids:
                                continue
                            edit_forbidden_parent_ids.add(child_id)
                            stack_ids.append(child_id)

        import_report = {
            "ok": (request.query_params.get("import_ok") or "").strip(),
            "rows": (request.query_params.get("import_rows") or "").strip(),
            "created": (request.query_params.get("import_created") or "").strip(),
            "updated": (request.query_params.get("import_updated") or "").strip(),
            "errors": (request.query_params.get("import_errors") or "").strip(),
        }
        org_sections = [
            {
                **meta,
                "href": build_org_structure_url(meta["id"]),
                "is_active": meta["id"] == selected_org_section,
            }
            for meta in org_structure_sections().values()
        ]

        return templates.TemplateResponse(
            request,
            "org_structure.html",
            {
                "request": request,
                "user": user,
                "units": ordered_units,
                "parents": ordered_units,
                "unit_type_names": unit_type_names,
                "executors": executors,
                "departments": departments,
                "assignments": assignments,
                "edit_unit": edit_unit,
                "edit_forbidden_parent_ids": edit_forbidden_parent_ids,
                "org_v2_enabled": org_v2,
                "org_sections": org_sections,
                "selected_org_section": selected_org_section,
                "selected_org_section_meta": org_structure_sections().get(selected_org_section),
                "import_report": import_report,
                "can_manage_departments": is_admin(user),
                "assignment_unit_id_filter": assignment_unit_id_int if assignment_unit_id_int is not None else "",
                "assignment_executor_id_filter": (
                    assignment_executor_id_int if assignment_executor_id_int is not None else ""
                ),
                "assignment_department_id_filter": assignment_department_filter,
                "assignment_unit_q_filter": assignment_unit_lookup,
                "assignment_executor_q_filter": assignment_executor_lookup,
                "assignment_primary_filter": assignment_only_primary,
                "assignment_filters_active": assignment_filters_active,
                "assignments_total_all": assignments_total_all,
                "assignments_total": assignments_total,
                "assignments_page": assignment_page,
                "assignments_total_pages": assignments_total_pages,
            },
        )

    @app.post("/web/departments/create")
    async def web_departments_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin)),
    ):
        ensure_company_user(user)
        form = await request.form()
        section = infer_org_structure_section(form.get("section"), error=request.query_params.get("error"))
        name = normalize_department_name(form.get("name"))
        is_active = (form.get("is_active") or "1").strip() in {"1", "on", "true", "yes"}
        if not name:
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_empty_name"),
                status_code=http_303_see_other,
            )
        exists = (
            db.query(department_model.id)
            .filter(department_model.company_id == user.company_id, func.lower(department_model.name) == name.lower())
            .first()
        )
        if exists:
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_exists"),
                status_code=http_303_see_other,
            )
        try:
            db.add(department_model(company_id=user.company_id, name=name, is_active=is_active))
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(url=build_org_structure_url(section), status_code=http_303_see_other)

    @app.post("/web/departments/{department_id}/update")
    async def web_departments_update(
        department_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin)),
    ):
        ensure_company_user(user)
        section = infer_org_structure_section(request.query_params.get("section"))
        item = db.get(department_model, department_id)
        if not item or item.company_id != user.company_id:
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_not_found"),
                status_code=http_303_see_other,
            )
        form = await request.form()
        section = infer_org_structure_section(form.get("section") or section)
        name = normalize_department_name(form.get("name"))
        is_active = (form.get("is_active") or "").strip() in {"1", "on", "true", "yes"}
        if not name:
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_empty_name"),
                status_code=http_303_see_other,
            )
        exists = (
            db.query(department_model.id)
            .filter(
                department_model.company_id == user.company_id,
                func.lower(department_model.name) == name.lower(),
                department_model.id != item.id,
            )
            .first()
        )
        if exists:
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_exists"),
                status_code=http_303_see_other,
            )
        item.name = name
        item.is_active = is_active
        try:
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(url=build_org_structure_url(section), status_code=http_303_see_other)

    @app.post("/web/departments/{department_id}/delete")
    async def web_departments_delete(
        department_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin)),
    ):
        ensure_company_user(user)
        section = infer_org_structure_section(request.query_params.get("section"))
        form = await request.form()
        section = infer_org_structure_section(form.get("section") or section)
        item = db.get(department_model, department_id)
        if not item or item.company_id != user.company_id:
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_not_found"),
                status_code=http_303_see_other,
            )
        in_use = any(
            (
                db.query(ticket_type_model.id).filter(
                    ticket_type_model.company_id == user.company_id,
                    ticket_type_model.department_id == item.id,
                ).first()
                is not None,
                db.query(ticket_template_model.id).filter(
                    ticket_template_model.company_id == user.company_id,
                    ticket_template_model.department_id == item.id,
                ).first()
                is not None,
                db.query(unit_assignment_model.id).filter(
                    unit_assignment_model.company_id == user.company_id,
                    unit_assignment_model.department_id == item.id,
                ).first()
                is not None,
                db.query(ticket_model.id).filter(
                    ticket_model.company_id == user.company_id,
                    ticket_model.department_id == item.id,
                ).first()
                is not None,
            )
        )
        if in_use:
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_in_use"),
                status_code=http_303_see_other,
            )
        try:
            db.delete(item)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_org_structure_url(section, error="department_save_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(url=build_org_structure_url(section), status_code=http_303_see_other)

    @app.post("/web/org-structure/create")
    async def web_org_structure_create(
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        if not org_structure_v2_enabled():
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)
        form = await request.form()
        section = infer_org_structure_section(form.get("section"), error=request.query_params.get("error"))
        name = (form.get("name") or "").strip()
        parent_raw = (form.get("parent_id") or "").strip()
        type_name = (form.get("unit_type_name") or "").strip() or "\u0423\u0437\u0435\u043b"
        if not name:
            return RedirectResponse(
                url=build_org_structure_url(section, error="empty_name"),
                status_code=http_303_see_other,
            )
        try:
            parent_id = int(parent_raw) if parent_raw else None
        except ValueError:
            return RedirectResponse(
                url=build_org_structure_url(section, error="bad_parent"),
                status_code=http_303_see_other,
            )
        if parent_id is not None:
            parent = db.get(org_unit_model, parent_id)
            if not parent or parent.company_id != user.company_id:
                return RedirectResponse(
                    url=build_org_structure_url(section, error="parent_not_found"),
                    status_code=http_303_see_other,
                )
        try:
            unit_type = get_or_create_unit_type(db, user.company_id, type_name)
            db.add(
                org_unit_model(
                    company_id=user.company_id,
                    name=name,
                    unit_type_id=unit_type.id,
                    parent_id=parent_id,
                    is_active=True,
                )
            )
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_org_structure_url(section, error="create_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(url=build_org_structure_url(section), status_code=http_303_see_other)

    @app.post("/web/org-structure/assign")
    async def web_org_structure_assign_executor(
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        if not org_structure_v2_enabled():
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)
        form = await request.form()
        section = infer_org_structure_section(form.get("section"), error=request.query_params.get("error"))
        unit_values_raw = [str(value).strip() for value in form.getlist("unit_ids") if str(value).strip()]
        if not unit_values_raw:
            fallback_unit_raw = (form.get("unit_id") or "").strip()
            if fallback_unit_raw:
                unit_values_raw = [fallback_unit_raw]
        executor_raw = (form.get("executor_id") or "").strip()
        department_raw = (form.get("department_id") or "").strip()
        is_primary = (form.get("is_primary") or "").strip() in {"1", "on", "true", "yes"}
        try:
            executor_id = int(executor_raw)
        except ValueError:
            return RedirectResponse(
                url=build_org_structure_url(section, error="assign_bad_input"),
                status_code=http_303_see_other,
            )
        try:
            department_id = int(department_raw) if department_raw else None
        except ValueError:
            return RedirectResponse(
                url=build_org_structure_url(section, error="assign_bad_input"),
                status_code=http_303_see_other,
            )

        unit_ids: list[int] = []
        seen_unit_ids: set[int] = set()
        try:
            for unit_raw in unit_values_raw:
                unit_id = int(unit_raw)
                if unit_id not in seen_unit_ids:
                    seen_unit_ids.add(unit_id)
                    unit_ids.append(unit_id)
        except ValueError:
            return RedirectResponse(
                url=build_org_structure_url(section, error="assign_bad_input"),
                status_code=http_303_see_other,
            )
        if not unit_ids:
            return RedirectResponse(
                url=build_org_structure_url(section, error="assign_bad_input"),
                status_code=http_303_see_other,
            )

        executor = db.get(user_model, executor_id)
        if not executor or executor.company_id != user.company_id or executor.role != role_enum.executor:
            return RedirectResponse(
                url=build_org_structure_url(section, error="assign_executor_not_found"),
                status_code=http_303_see_other,
            )
        if department_id is not None:
            department = db.get(department_model, department_id)
            if not department or department.company_id != user.company_id or not department.is_active:
                return RedirectResponse(
                    url=build_org_structure_url(section, error="assign_department_not_found"),
                    status_code=http_303_see_other,
                )

        found_unit_ids = {
            row[0]
            for row in (
                db.query(org_unit_model.id)
                .filter(org_unit_model.company_id == user.company_id, org_unit_model.id.in_(unit_ids))
                .all()
            )
        }
        if len(found_unit_ids) != len(unit_ids):
            return RedirectResponse(
                url=build_org_structure_url(section, error="assign_unit_not_found"),
                status_code=http_303_see_other,
            )

        try:
            existing_rows = (
                db.query(unit_assignment_model)
                .filter(
                    unit_assignment_model.company_id == user.company_id,
                    unit_assignment_model.unit_id.in_(unit_ids),
                    unit_assignment_model.user_id == executor_id,
                    unit_assignment_model.role_code == "EXECUTOR",
                    department_match_filter(unit_assignment_model.department_id, department_id),
                )
                .all()
            )
            existing_by_unit_id = {row.unit_id: row for row in existing_rows}
            for unit_id in unit_ids:
                existing = existing_by_unit_id.get(unit_id)
                if existing:
                    existing.is_primary = existing.is_primary or is_primary
                    assignment_id = existing.id
                else:
                    item = unit_assignment_model(
                        company_id=user.company_id,
                        unit_id=unit_id,
                        user_id=executor_id,
                        role_code="EXECUTOR",
                        department_id=department_id,
                        is_primary=is_primary,
                    )
                    db.add(item)
                    db.flush()
                    assignment_id = item.id
                if is_primary:
                    (
                        db.query(unit_assignment_model)
                        .filter(
                            unit_assignment_model.company_id == user.company_id,
                            unit_assignment_model.unit_id == unit_id,
                            unit_assignment_model.role_code == "EXECUTOR",
                            department_match_filter(unit_assignment_model.department_id, department_id),
                            unit_assignment_model.id != assignment_id,
                        )
                        .update({unit_assignment_model.is_primary: False}, synchronize_session=False)
                    )
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_org_structure_url(section, error="assign_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(url=build_org_structure_url(section), status_code=http_303_see_other)

    @app.post("/web/org-structure/assign/{assignment_id}/primary")
    async def web_org_structure_assignment_primary(
        assignment_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        if not org_structure_v2_enabled():
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)
        form = await request.form()
        section = infer_org_structure_section(form.get("section") or request.query_params.get("section"))
        assignment = db.get(unit_assignment_model, assignment_id)
        if not assignment or assignment.company_id != user.company_id or assignment.role_code != "EXECUTOR":
            raise HTTPException(404, "Assignment not found")
        (
            db.query(unit_assignment_model)
            .filter(
                unit_assignment_model.company_id == user.company_id,
                unit_assignment_model.unit_id == assignment.unit_id,
                unit_assignment_model.role_code == "EXECUTOR",
                department_match_filter(unit_assignment_model.department_id, assignment.department_id),
            )
            .update({unit_assignment_model.is_primary: False}, synchronize_session=False)
        )
        assignment.is_primary = True
        db.commit()
        return RedirectResponse(
            url=build_org_structure_url(
                section,
                assignment_department_id=form.get("assignment_department_id"),
                assignment_unit_q=form.get("assignment_unit_q"),
                assignment_executor_q=form.get("assignment_executor_q"),
                assignment_primary=(form.get("assignment_primary") or "").strip() in {"1", "true", "on", "yes"},
                assignment_page=form.get("assignment_page"),
            ),
            status_code=http_303_see_other,
        )

    @app.post("/web/org-structure/assign/{assignment_id}/delete")
    async def web_org_structure_assignment_delete(
        assignment_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        if not org_structure_v2_enabled():
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)
        form = await request.form()
        section = infer_org_structure_section(form.get("section") or request.query_params.get("section"))
        assignment = db.get(unit_assignment_model, assignment_id)
        if not assignment or assignment.company_id != user.company_id or assignment.role_code != "EXECUTOR":
            raise HTTPException(404, "Assignment not found")
        db.delete(assignment)
        db.commit()
        return RedirectResponse(
            url=build_org_structure_url(
                section,
                assignment_department_id=form.get("assignment_department_id"),
                assignment_unit_q=form.get("assignment_unit_q"),
                assignment_executor_q=form.get("assignment_executor_q"),
                assignment_primary=(form.get("assignment_primary") or "").strip() in {"1", "true", "on", "yes"},
                assignment_page=form.get("assignment_page"),
            ),
            status_code=http_303_see_other,
        )

    @app.post("/web/org-structure/{unit_id}/update")
    async def web_org_structure_update(
        unit_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        if not org_structure_v2_enabled():
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)
        section = infer_org_structure_section(request.query_params.get("section"), edit_unit_id=str(unit_id))
        item = db.get(org_unit_model, unit_id)
        if not item or item.company_id != user.company_id:
            return RedirectResponse(
                url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_not_found"),
                status_code=http_303_see_other,
            )
        form = await request.form()
        section = infer_org_structure_section(form.get("section") or section, edit_unit_id=str(unit_id))
        name = (form.get("name") or "").strip()
        parent_raw = (form.get("parent_id") or "").strip()
        type_name = (form.get("unit_type_name") or "").strip() or "\u0423\u0437\u0435\u043b"
        is_active = (form.get("is_active") or "").strip() in {"1", "on", "true", "yes"}
        if not name:
            return RedirectResponse(
                url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_empty_name"),
                status_code=http_303_see_other,
            )
        try:
            parent_id = int(parent_raw) if parent_raw else None
        except ValueError:
            return RedirectResponse(
                url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_bad_parent"),
                status_code=http_303_see_other,
            )
        if parent_id is not None:
            parent = db.get(org_unit_model, parent_id)
            if not parent or parent.company_id != user.company_id:
                return RedirectResponse(
                    url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_parent_not_found"),
                    status_code=http_303_see_other,
                )
        parent_map = build_unit_parent_map(db, user.company_id)
        if would_create_unit_cycle(parent_map, unit_id=unit_id, new_parent_id=parent_id):
            return RedirectResponse(
                url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_cycle"),
                status_code=http_303_see_other,
            )
        try:
            unit_type = get_or_create_unit_type(db, user.company_id, type_name)
            item.name = name
            item.parent_id = parent_id
            item.unit_type_id = unit_type.id
            item.is_active = is_active
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_org_structure_url(section, edit_unit_id=unit_id, error="edit_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(url=build_org_structure_url(section), status_code=http_303_see_other)

    @app.post("/web/org-structure/import-csv")
    async def web_org_structure_import_csv(
        request: Request,
        file: UploadFile = File(...),
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        if not org_structure_v2_enabled():
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)
        section = infer_org_structure_section(request.query_params.get("section") or "import")
        try:
            raw_bytes = await file.read()
        except Exception:
            return RedirectResponse(
                url=build_org_structure_url(section, error="import_read_failed"),
                status_code=http_303_see_other,
            )
        if not raw_bytes:
            return RedirectResponse(
                url=build_org_structure_url(section, error="import_empty"),
                status_code=http_303_see_other,
            )

        text = None
        for encoding in ("utf-8-sig", "utf-8", "cp1251"):
            try:
                text = raw_bytes.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            return RedirectResponse(
                url=build_org_structure_url(section, error="import_encoding"),
                status_code=http_303_see_other,
            )

        csv_stream = io.StringIO(text)
        sample = text[:2048]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(csv_stream, dialect=dialect)
        if not reader.fieldnames:
            return RedirectResponse(
                url=build_org_structure_url(section, error="import_headers"),
                status_code=http_303_see_other,
            )
        headers = {str(header or "").strip().lower() for header in reader.fieldnames}
        if "path" not in headers:
            return RedirectResponse(
                url=build_org_structure_url(section, error="import_need_path"),
                status_code=http_303_see_other,
            )

        existing_units = (
            db.query(org_unit_model.id, org_unit_model.parent_id, org_unit_model.name, org_unit_model.is_active)
            .filter(org_unit_model.company_id == user.company_id)
            .all()
        )
        unit_map: dict[tuple[int | None, str], dict] = {}
        for unit_id, parent_id, name, is_active in existing_units:
            key = (parent_id, (name or "").strip().lower())
            unit_map[key] = {"id": int(unit_id), "is_active": bool(is_active)}

        rows_total = 0
        created_count = 0
        updated_count = 0
        errors_count = 0
        try:
            for raw_row in reader:
                rows_total += 1
                row = {str(key or "").strip().lower(): (value or "").strip() for key, value in raw_row.items()}
                raw_path = row.get("path", "")
                if not raw_path:
                    errors_count += 1
                    continue
                names = [part.strip() for part in raw_path.split("/") if part.strip()]
                if not names:
                    errors_count += 1
                    continue
                types = [part.strip() for part in (row.get("types", "")).split("/") if part.strip()]
                active_final = parse_bool_text(row.get("is_active"), True)

                parent_id: int | None = None
                for idx, node_name in enumerate(names):
                    key = (parent_id, node_name.lower())
                    unit_info = unit_map.get(key)
                    if unit_info:
                        parent_id = int(unit_info["id"])
                        continue
                    type_name = types[idx] if idx < len(types) else "\u0423\u0437\u0435\u043b"
                    unit_type = get_or_create_unit_type(db, user.company_id, type_name)
                    new_item = org_unit_model(
                        company_id=user.company_id,
                        name=node_name,
                        unit_type_id=unit_type.id,
                        parent_id=parent_id,
                        is_active=True,
                    )
                    db.add(new_item)
                    db.flush()
                    unit_map[key] = {"id": int(new_item.id), "is_active": True}
                    parent_id = int(new_item.id)
                    created_count += 1

                if parent_id is not None:
                    final_item = db.get(org_unit_model, parent_id)
                    if final_item and bool(final_item.is_active) != active_final:
                        final_item.is_active = active_final
                        updated_count += 1
            db.commit()
        except Exception:
            db.rollback()
            return RedirectResponse(
                url=build_org_structure_url(section, error="import_failed"),
                status_code=http_303_see_other,
            )

        return RedirectResponse(
            url=build_org_structure_url(
                section,
                import_ok=True,
                import_rows=rows_total,
                import_created=created_count,
                import_updated=updated_count,
                import_errors=errors_count,
            ),
            status_code=http_303_see_other,
        )

    @app.get("/web/org-structure/template.csv")
    def web_org_structure_template_csv(
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        template_path = Path(__file__).resolve().parents[1] / "org_structure_import_example.csv"
        if not template_path.exists():
            raise HTTPException(404, "Template not found")
        return FileResponse(
            template_path,
            media_type="text/csv; charset=utf-8",
            filename="org_structure_import_example.csv",
        )

    @app.post("/web/org-structure/{unit_id}/toggle")
    async def web_org_structure_toggle(
        unit_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        if not org_structure_v2_enabled():
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)
        form = await request.form()
        section = infer_org_structure_section(form.get("section") or request.query_params.get("section"))
        item = db.get(org_unit_model, unit_id)
        if not item or item.company_id != user.company_id:
            raise HTTPException(404, "Org unit not found")
        item.is_active = not bool(item.is_active)
        db.commit()
        return RedirectResponse(url=build_org_structure_url(section), status_code=http_303_see_other)

    @app.post("/web/org-structure/{unit_id}/delete")
    async def web_org_structure_delete(
        unit_id: int,
        request: Request,
        db=Depends(get_db),
        user=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(user)
        if not org_structure_v2_enabled():
            return RedirectResponse(url="/web/settings", status_code=http_303_see_other)
        form = await request.form()
        section = infer_org_structure_section(form.get("section") or request.query_params.get("section"))
        item = db.get(org_unit_model, unit_id)
        if not item or item.company_id != user.company_id:
            return RedirectResponse(
                url=build_org_structure_url(section, error="delete_not_found"),
                status_code=http_303_see_other,
            )
        has_children = (
            db.query(org_unit_model.id)
            .filter(org_unit_model.company_id == user.company_id, org_unit_model.parent_id == unit_id)
            .first()
            is not None
        )
        if has_children:
            return RedirectResponse(
                url=build_org_structure_url(section, error="delete_has_children"),
                status_code=http_303_see_other,
            )
        has_assignments = (
            db.query(unit_assignment_model.id)
            .filter(unit_assignment_model.company_id == user.company_id, unit_assignment_model.unit_id == unit_id)
            .first()
            is not None
        )
        if has_assignments:
            return RedirectResponse(
                url=build_org_structure_url(section, error="delete_has_assignments"),
                status_code=http_303_see_other,
            )
        has_templates = (
            db.query(ticket_template_model.id)
            .filter(ticket_template_model.company_id == user.company_id, ticket_template_model.scope_unit_id == unit_id)
            .first()
            is not None
        )
        if has_templates:
            return RedirectResponse(
                url=build_org_structure_url(section, error="delete_has_templates"),
                status_code=http_303_see_other,
            )
        has_tickets = (
            db.query(ticket_model.id)
            .filter(ticket_model.company_id == user.company_id, ticket_model.target_unit_id == unit_id)
            .first()
            is not None
        )
        if has_tickets:
            return RedirectResponse(
                url=build_org_structure_url(section, error="delete_has_tickets"),
                status_code=http_303_see_other,
            )
        has_generation_keys = (
            db.query(ticket_generation_key_model.id)
            .filter(
                ticket_generation_key_model.company_id == user.company_id,
                ticket_generation_key_model.target_unit_id == unit_id,
            )
            .first()
            is not None
        )
        if has_generation_keys:
            return RedirectResponse(
                url=build_org_structure_url(section, error="delete_has_generation_keys"),
                status_code=http_303_see_other,
            )
        try:
            db.delete(item)
            db.commit()
        except sqlalchemy_error:
            db.rollback()
            return RedirectResponse(
                url=build_org_structure_url(section, error="delete_failed"),
                status_code=http_303_see_other,
            )
        return RedirectResponse(url=build_org_structure_url(section), status_code=http_303_see_other)
