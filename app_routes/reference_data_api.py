from fastapi import Depends, HTTPException


def register_reference_data_api_routes(
    app,
    *,
    get_db,
    get_current_user,
    require_role,
    ensure_company_user,
    is_platform_admin,
    normalize_department_name,
    func,
    project_model,
    department_model,
    unit_type_model,
    ticket_type_model,
    ticket_template_model,
    unit_assignment_model,
    ticket_model,
    org_unit_model,
    role_enum,
    project_create_model,
    project_out_model,
    department_create_model,
    department_update_model,
    department_out_model,
    unit_type_create_model,
    unit_type_update_model,
    unit_type_out_model,
):
    @app.post("/projects", response_model=project_out_model)
    def create_project(
        payload: project_create_model,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        if (
            db.query(project_model)
            .filter(
                project_model.name == payload.name,
                project_model.company_id == _manager.company_id,
            )
            .first()
        ):
            raise HTTPException(400, "Project already exists")
        item = project_model(
            name=payload.name,
            description=payload.description,
            company_id=_manager.company_id,
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item

    @app.get("/projects", response_model=list[project_out_model])
    def list_projects(
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if is_platform_admin(user):
            return db.query(project_model).order_by(project_model.id.desc()).all()
        ensure_company_user(user)
        return (
            db.query(project_model)
            .filter(project_model.company_id == user.company_id)
            .order_by(project_model.id.desc())
            .all()
        )

    @app.post("/departments", response_model=department_out_model)
    def create_department(
        payload: department_create_model,
        db=Depends(get_db),
        _admin=Depends(require_role(role_enum.admin)),
    ):
        ensure_company_user(_admin)
        name = normalize_department_name(payload.name)
        if not name:
            raise HTTPException(422, "Name is required")
        exists = (
            db.query(department_model.id)
            .filter(
                department_model.company_id == _admin.company_id,
                func.lower(department_model.name) == name.lower(),
            )
            .first()
        )
        if exists:
            raise HTTPException(400, "Department already exists")
        item = department_model(
            company_id=_admin.company_id,
            name=name,
            is_active=bool(payload.is_active),
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item

    @app.get("/departments", response_model=list[department_out_model])
    def list_departments(
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if is_platform_admin(user):
            return db.query(department_model).order_by(department_model.id.desc()).all()
        ensure_company_user(user)
        return (
            db.query(department_model)
            .filter(department_model.company_id == user.company_id)
            .order_by(department_model.name.asc(), department_model.id.asc())
            .all()
        )

    @app.patch("/departments/{department_id}", response_model=department_out_model)
    def update_department(
        department_id: int,
        patch: department_update_model,
        db=Depends(get_db),
        _admin=Depends(require_role(role_enum.admin)),
    ):
        ensure_company_user(_admin)
        item = db.get(department_model, department_id)
        if not item or item.company_id != _admin.company_id:
            raise HTTPException(404, "Department not found")
        incoming = patch.model_dump(exclude_unset=True)
        if "name" in incoming:
            next_name = normalize_department_name(incoming.get("name"))
            if not next_name:
                raise HTTPException(422, "Name is required")
            exists = (
                db.query(department_model.id)
                .filter(
                    department_model.company_id == _admin.company_id,
                    func.lower(department_model.name) == next_name.lower(),
                    department_model.id != item.id,
                )
                .first()
            )
            if exists:
                raise HTTPException(400, "Department already exists")
            item.name = next_name
        if "is_active" in incoming:
            item.is_active = bool(incoming.get("is_active"))
        db.commit()
        db.refresh(item)
        return item

    @app.delete("/departments/{department_id}")
    def delete_department(
        department_id: int,
        db=Depends(get_db),
        _admin=Depends(require_role(role_enum.admin)),
    ):
        ensure_company_user(_admin)
        item = db.get(department_model, department_id)
        if not item or item.company_id != _admin.company_id:
            raise HTTPException(404, "Department not found")
        in_use = any(
            (
                db.query(ticket_type_model.id).filter(ticket_type_model.department_id == item.id).first() is not None,
                db.query(ticket_template_model.id).filter(ticket_template_model.department_id == item.id).first()
                is not None,
                db.query(unit_assignment_model.id).filter(unit_assignment_model.department_id == item.id).first()
                is not None,
                db.query(ticket_model.id).filter(ticket_model.department_id == item.id).first() is not None,
            )
        )
        if in_use:
            raise HTTPException(400, "Department is in use")
        db.delete(item)
        db.commit()
        return {"ok": True}

    @app.post("/unit-types", response_model=unit_type_out_model)
    def create_unit_type(
        payload: unit_type_create_model,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        name = (payload.name or "").strip()
        code = (payload.code or "").strip() or None
        if not name:
            raise HTTPException(422, "Name is required")
        if (
            db.query(unit_type_model.id)
            .filter(
                unit_type_model.company_id == _manager.company_id,
                func.lower(unit_type_model.name) == name.lower(),
            )
            .first()
        ):
            raise HTTPException(400, "Unit type already exists")
        if code and (
            db.query(unit_type_model.id)
            .filter(
                unit_type_model.company_id == _manager.company_id,
                func.lower(unit_type_model.code) == code.lower(),
            )
            .first()
        ):
            raise HTTPException(400, "Unit type code already exists")
        item = unit_type_model(
            company_id=_manager.company_id,
            name=name,
            code=code,
            is_active=bool(payload.is_active),
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item

    @app.get("/unit-types", response_model=list[unit_type_out_model])
    def list_unit_types(
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if is_platform_admin(user):
            return db.query(unit_type_model).order_by(unit_type_model.id.desc()).all()
        ensure_company_user(user)
        return (
            db.query(unit_type_model)
            .filter(unit_type_model.company_id == user.company_id)
            .order_by(unit_type_model.id.desc())
            .all()
        )

    @app.patch("/unit-types/{unit_type_id}", response_model=unit_type_out_model)
    def update_unit_type(
        unit_type_id: int,
        patch: unit_type_update_model,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        item = db.get(unit_type_model, unit_type_id)
        if not item or item.company_id != _manager.company_id:
            raise HTTPException(404, "Unit type not found")
        incoming = patch.model_dump(exclude_unset=True)
        if "name" in incoming:
            next_name = (incoming.get("name") or "").strip()
            if not next_name:
                raise HTTPException(422, "Name is required")
            exists = (
                db.query(unit_type_model.id)
                .filter(
                    unit_type_model.company_id == _manager.company_id,
                    func.lower(unit_type_model.name) == next_name.lower(),
                    unit_type_model.id != item.id,
                )
                .first()
            )
            if exists:
                raise HTTPException(400, "Unit type already exists")
            item.name = next_name
        if "code" in incoming:
            next_code = (incoming.get("code") or "").strip() or None
            if next_code:
                exists = (
                    db.query(unit_type_model.id)
                    .filter(
                        unit_type_model.company_id == _manager.company_id,
                        func.lower(unit_type_model.code) == next_code.lower(),
                        unit_type_model.id != item.id,
                    )
                    .first()
                )
                if exists:
                    raise HTTPException(400, "Unit type code already exists")
            item.code = next_code
        if "is_active" in incoming:
            item.is_active = bool(incoming.get("is_active"))
        db.commit()
        db.refresh(item)
        return item

    @app.delete("/unit-types/{unit_type_id}")
    def delete_unit_type(
        unit_type_id: int,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        item = db.get(unit_type_model, unit_type_id)
        if not item or item.company_id != _manager.company_id:
            raise HTTPException(404, "Unit type not found")
        in_use = db.query(org_unit_model.id).filter(org_unit_model.unit_type_id == item.id).first() is not None
        if in_use:
            raise HTTPException(400, "Unit type is in use")
        db.delete(item)
        db.commit()
        return {"ok": True}
