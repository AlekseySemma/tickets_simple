class RoleTemplateSupport:
    def __init__(
        self,
        *,
        manageable_roles_for_web_user_management_func,
        role_enum,
        normalize_capability_flags_func,
        default_role_template_presets,
        role_template_model,
    ):
        self.manageable_roles_for_web_user_management_func = manageable_roles_for_web_user_management_func
        self.role_enum = role_enum
        self.normalize_capability_flags_func = normalize_capability_flags_func
        self.default_role_template_presets = tuple(default_role_template_presets)
        self.role_template_model = role_template_model

    def manageable_template_access_levels_for_actor(self, actor) -> tuple:
        return self.manageable_roles_for_web_user_management_func(actor, role_enum=self.role_enum)

    def role_template_payload(self, template) -> dict[str, bool]:
        return self.normalize_capability_flags_func(
            template.access_level,
            show_receipts_accounting_mode=template.show_receipts_accounting_mode,
            is_assignable_executor=template.is_assignable_executor,
            can_view_all_tickets=template.can_view_all_tickets,
            can_create_tickets=template.can_create_tickets,
            can_close_tickets=template.can_close_tickets,
        )

    def ensure_default_role_templates(self, db, company_id: int, allowed_access_levels: tuple) -> None:
        if not allowed_access_levels:
            return
        existing_names = {
            str(row[0]).strip().casefold()
            for row in db.query(self.role_template_model.name).filter(self.role_template_model.company_id == company_id).all()
        }
        created = False
        for preset in self.default_role_template_presets:
            access_level = preset["access_level"]
            if access_level not in allowed_access_levels:
                continue
            preset_name = str(preset["name"]).strip()
            if preset_name.casefold() in existing_names:
                continue
            flags = self.normalize_capability_flags_func(
                access_level,
                show_receipts_accounting_mode=bool(preset["show_receipts_accounting_mode"]),
                is_assignable_executor=bool(preset["is_assignable_executor"]),
                can_view_all_tickets=bool(preset["can_view_all_tickets"]),
                can_create_tickets=bool(preset["can_create_tickets"]),
                can_close_tickets=bool(preset["can_close_tickets"]),
            )
            db.add(
                self.role_template_model(
                    company_id=company_id,
                    name=preset_name,
                    access_level=access_level,
                    **flags,
                )
            )
            existing_names.add(preset_name.casefold())
            created = True
        if created:
            db.commit()

    def get_manageable_role_template(self, db, actor, template_id: int | None, *, allowed_access_levels: tuple | None = None):
        if template_id is None:
            return None
        template = db.get(self.role_template_model, template_id)
        if not template or template.company_id != actor.company_id:
            return None
        access_levels = allowed_access_levels or self.manageable_template_access_levels_for_actor(actor)
        if template.access_level not in access_levels:
            return None
        return template
