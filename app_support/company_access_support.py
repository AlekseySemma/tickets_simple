class CompanyAccessSupport:
    def __init__(
        self,
        *,
        depends_func,
        get_current_user_func,
        ensure_company_user_func,
        http_exception_cls,
        ticket_model,
        receipt_model,
        list_tickets_for_user_func,
        is_platform_admin_func,
        role_enum,
    ):
        self.depends_func = depends_func
        self.get_current_user_func = get_current_user_func
        self.ensure_company_user_func = ensure_company_user_func
        self.http_exception_cls = http_exception_cls
        self.ticket_model = ticket_model
        self.receipt_model = receipt_model
        self.list_tickets_for_user_func = list_tickets_for_user_func
        self.is_platform_admin_func = is_platform_admin_func
        self.role_enum = role_enum

    def require_role(self, *roles):
        def checker(user=self.depends_func(self.get_current_user_func)):
            if user.role not in roles:
                raise self.http_exception_cls(status_code=403, detail="Forbidden")
            return user

        return checker

    def get_company_ticket_or_404(self, db, user, ticket_id: int):
        self.ensure_company_user_func(user)
        ticket = db.get(self.ticket_model, ticket_id)
        if not ticket:
            raise self.http_exception_cls(404, "Ticket not found")
        if ticket.company_id != user.company_id:
            raise self.http_exception_cls(403, "Forbidden")
        return ticket

    def get_company_receipt_or_404(self, db, user, receipt_id: int):
        self.ensure_company_user_func(user)
        receipt = db.get(self.receipt_model, receipt_id)
        if not receipt:
            raise self.http_exception_cls(404, "Receipt not found")
        if receipt.company_id != user.company_id:
            raise self.http_exception_cls(403, "Forbidden")
        return receipt

    def list_tickets(self, db, user):
        return self.list_tickets_for_user_func(
            db,
            user,
            ticket_model=self.ticket_model,
            is_platform_admin=self.is_platform_admin_func,
            ensure_company_user=self.ensure_company_user_func,
            role_enum=self.role_enum,
        )
