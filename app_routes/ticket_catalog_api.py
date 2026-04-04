from fastapi import Depends, HTTPException


def register_ticket_catalog_api_routes(
    app,
    *,
    get_db,
    get_current_user,
    require_role,
    ensure_company_user,
    is_platform_admin,
    validate_ticket_links,
    normalize_ticket_type_archive_retention_days,
    validate_template_links,
    resolve_ticket_department_id,
    normalize_period_key,
    month_period_key,
    create_tickets_from_template,
    ticket_type_model,
    ticket_template_model,
    ticket_model,
    ticket_generation_key_model,
    role_enum,
    ticket_type_create_model,
    ticket_type_update_model,
    ticket_type_out_model,
    ticket_template_create_model,
    ticket_template_update_model,
    ticket_template_out_model,
    ticket_template_run_in_model,
    sqlalchemy_error,
):
    @app.post("/ticket-types", response_model=ticket_type_out_model)
    def create_ticket_type(
        payload: ticket_type_create_model,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        name = (payload.name or "").strip()
        if not name:
            raise HTTPException(422, "Name is required")
        exists = (
            db.query(ticket_type_model)
            .filter(
                ticket_type_model.company_id == _manager.company_id,
                ticket_type_model.name == name,
            )
            .first()
        )
        if exists:
            raise HTTPException(400, "Ticket type already exists")
        validate_ticket_links(
            db,
            _manager.company_id,
            None,
            None,
            None,
            None,
            None,
            payload.department_id,
        )
        item = ticket_type_model(
            company_id=_manager.company_id,
            name=name,
            description=(payload.description or "").strip() or None,
            department_id=payload.department_id,
            archive_retention_days=normalize_ticket_type_archive_retention_days(payload.archive_retention_days),
            is_active=bool(payload.is_active),
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item

    @app.get("/ticket-types", response_model=list[ticket_type_out_model])
    def list_ticket_types(
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if is_platform_admin(user):
            return db.query(ticket_type_model).order_by(ticket_type_model.id.desc()).all()
        ensure_company_user(user)
        return (
            db.query(ticket_type_model)
            .filter(ticket_type_model.company_id == user.company_id)
            .order_by(ticket_type_model.id.desc())
            .all()
        )

    @app.patch("/ticket-types/{ticket_type_id}", response_model=ticket_type_out_model)
    def update_ticket_type(
        ticket_type_id: int,
        patch: ticket_type_update_model,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        item = db.get(ticket_type_model, ticket_type_id)
        if not item or item.company_id != _manager.company_id:
            raise HTTPException(404, "Ticket type not found")

        incoming = patch.model_dump(exclude_unset=True)
        if "name" in incoming:
            next_name = (incoming.get("name") or "").strip()
            if not next_name:
                raise HTTPException(422, "Name is required")
            exists = (
                db.query(ticket_type_model)
                .filter(
                    ticket_type_model.company_id == _manager.company_id,
                    ticket_type_model.name == next_name,
                    ticket_type_model.id != item.id,
                )
                .first()
            )
            if exists:
                raise HTTPException(400, "Ticket type already exists")
            item.name = next_name
        if "description" in incoming:
            item.description = (incoming.get("description") or "").strip() or None
        if "department_id" in incoming:
            validate_ticket_links(
                db,
                _manager.company_id,
                None,
                None,
                None,
                None,
                None,
                incoming.get("department_id"),
            )
            item.department_id = incoming.get("department_id")
        if "is_active" in incoming:
            item.is_active = bool(incoming.get("is_active"))
        if "archive_retention_days" in incoming:
            item.archive_retention_days = normalize_ticket_type_archive_retention_days(
                incoming.get("archive_retention_days")
            )
        db.commit()
        db.refresh(item)
        return item

    @app.delete("/ticket-types/{ticket_type_id}")
    def delete_ticket_type(
        ticket_type_id: int,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        item = db.get(ticket_type_model, ticket_type_id)
        if not item or item.company_id != _manager.company_id:
            raise HTTPException(404, "Ticket type not found")

        has_tickets = db.query(ticket_model.id).filter(ticket_model.ticket_type_id == item.id).first() is not None
        has_templates = (
            db.query(ticket_template_model.id).filter(ticket_template_model.ticket_type_id == item.id).first()
            is not None
        )
        if has_tickets or has_templates:
            raise HTTPException(400, "Ticket type is in use")

        db.delete(item)
        db.commit()
        return {"ok": True}

    @app.post("/ticket-templates", response_model=ticket_template_out_model)
    def create_ticket_template(
        payload: ticket_template_create_model,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        name = (payload.name or "").strip()
        if not name:
            raise HTTPException(422, "Name is required")
        validate_template_links(
            db,
            _manager.company_id,
            payload.ticket_type_id,
            payload.department_id,
            payload.default_executor_id,
            payload.scope_unit_id,
        )
        resolved_department_id = resolve_ticket_department_id(
            db,
            company_id=_manager.company_id,
            ticket_type_id=payload.ticket_type_id,
            department_id=payload.department_id,
        )
        exists = (
            db.query(ticket_template_model.id)
            .filter(
                ticket_template_model.company_id == _manager.company_id,
                ticket_template_model.name == name,
            )
            .first()
        )
        if exists:
            raise HTTPException(400, "Ticket template already exists")
        item = ticket_template_model(
            company_id=_manager.company_id,
            ticket_type_id=payload.ticket_type_id,
            department_id=resolved_department_id,
            name=name,
            title_template=(payload.title_template or "").strip() or None,
            description_template=(payload.description_template or "").strip() or None,
            default_deadline_rule=(payload.default_deadline_rule or "").strip() or None,
            default_executor_id=payload.default_executor_id,
            scope_unit_id=payload.scope_unit_id,
            is_active=bool(payload.is_active),
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item

    @app.get("/ticket-templates", response_model=list[ticket_template_out_model])
    def list_ticket_templates(
        db=Depends(get_db),
        user=Depends(get_current_user),
    ):
        if is_platform_admin(user):
            return db.query(ticket_template_model).order_by(ticket_template_model.id.desc()).all()
        ensure_company_user(user)
        return (
            db.query(ticket_template_model)
            .filter(ticket_template_model.company_id == user.company_id)
            .order_by(ticket_template_model.id.desc())
            .all()
        )

    @app.patch("/ticket-templates/{template_id}", response_model=ticket_template_out_model)
    def update_ticket_template(
        template_id: int,
        patch: ticket_template_update_model,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        item = db.get(ticket_template_model, template_id)
        if not item or item.company_id != _manager.company_id:
            raise HTTPException(404, "Ticket template not found")
        incoming = patch.model_dump(exclude_unset=True)
        if "name" in incoming:
            next_name = (incoming.get("name") or "").strip()
            if not next_name:
                raise HTTPException(422, "Name is required")
            exists = (
                db.query(ticket_template_model.id)
                .filter(
                    ticket_template_model.company_id == _manager.company_id,
                    ticket_template_model.name == next_name,
                    ticket_template_model.id != item.id,
                )
                .first()
            )
            if exists:
                raise HTTPException(400, "Ticket template already exists")
            item.name = next_name

        next_ticket_type_id = incoming.get("ticket_type_id", item.ticket_type_id)
        next_department_id = incoming.get("department_id", item.department_id)
        next_default_executor_id = incoming.get("default_executor_id", item.default_executor_id)
        next_scope_unit_id = incoming.get("scope_unit_id", item.scope_unit_id)
        validate_template_links(
            db,
            _manager.company_id,
            next_ticket_type_id,
            next_department_id,
            next_default_executor_id,
            next_scope_unit_id,
        )
        resolved_department_id = resolve_ticket_department_id(
            db,
            company_id=_manager.company_id,
            ticket_type_id=next_ticket_type_id,
            department_id=next_department_id,
        )

        if "ticket_type_id" in incoming:
            item.ticket_type_id = incoming.get("ticket_type_id")
        if "department_id" in incoming or "ticket_type_id" in incoming:
            item.department_id = resolved_department_id
        if "title_template" in incoming:
            item.title_template = (incoming.get("title_template") or "").strip() or None
        if "description_template" in incoming:
            item.description_template = (incoming.get("description_template") or "").strip() or None
        if "default_deadline_rule" in incoming:
            item.default_deadline_rule = (incoming.get("default_deadline_rule") or "").strip() or None
        if "default_executor_id" in incoming:
            item.default_executor_id = incoming.get("default_executor_id")
        if "scope_unit_id" in incoming:
            item.scope_unit_id = incoming.get("scope_unit_id")
        if "is_active" in incoming:
            item.is_active = bool(incoming.get("is_active"))
        db.commit()
        db.refresh(item)
        return item

    @app.delete("/ticket-templates/{template_id}")
    def delete_ticket_template(
        template_id: int,
        db=Depends(get_db),
        _manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(_manager)
        item = db.get(ticket_template_model, template_id)
        if not item or item.company_id != _manager.company_id:
            raise HTTPException(404, "Ticket template not found")
        try:
            db.query(ticket_model).filter(
                ticket_model.company_id == _manager.company_id,
                ticket_model.ticket_template_id == item.id,
            ).update({"ticket_template_id": None}, synchronize_session=False)
            db.query(ticket_generation_key_model).filter(
                ticket_generation_key_model.company_id == _manager.company_id,
                ticket_generation_key_model.ticket_template_id == item.id,
            ).delete(synchronize_session=False)
            db.delete(item)
            db.commit()
            return {"ok": True}
        except sqlalchemy_error:
            db.rollback()
            raise HTTPException(400, "Cannot delete ticket template")

    @app.post("/ticket-templates/{template_id}/run")
    def run_ticket_template(
        template_id: int,
        payload: ticket_template_run_in_model,
        db=Depends(get_db),
        manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(manager)
        item = db.get(ticket_template_model, template_id)
        if not item or item.company_id != manager.company_id:
            raise HTTPException(404, "Ticket template not found")
        normalized_period = normalize_period_key(payload.period_key)
        if payload.period_key and normalized_period is None:
            raise HTTPException(422, "Invalid period_key format, expected YYYY-MM")

        created_count, skipped_count, effective_period = create_tickets_from_template(
            db=db,
            template=item,
            actor_id=manager.id,
            period_key=normalized_period,
        )
        db.commit()
        return {
            "ok": True,
            "created_count": created_count,
            "skipped_count": skipped_count,
            "period_key": effective_period,
        }

    @app.post("/ticket-templates/{template_id}/clear-keys")
    def clear_ticket_template_keys(
        template_id: int,
        payload: ticket_template_run_in_model,
        db=Depends(get_db),
        manager=Depends(require_role(role_enum.admin, role_enum.curator)),
    ):
        ensure_company_user(manager)
        item = db.get(ticket_template_model, template_id)
        if not item or item.company_id != manager.company_id:
            raise HTTPException(404, "Ticket template not found")

        normalized_period = normalize_period_key(payload.period_key) or month_period_key()
        deleted_count = (
            db.query(ticket_generation_key_model)
            .filter(
                ticket_generation_key_model.company_id == manager.company_id,
                ticket_generation_key_model.ticket_template_id == item.id,
                ticket_generation_key_model.period_key == normalized_period,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        return {"ok": True, "period_key": normalized_period, "deleted_count": int(deleted_count or 0)}
