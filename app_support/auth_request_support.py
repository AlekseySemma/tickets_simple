class AuthRequestSupport:
    def __init__(
        self,
        *,
        resolve_current_user_func,
        core_get_active_invite_func,
        user_model,
        registration_invite_model,
        jwt_module,
        jwt_secret: str,
        algorithm: str,
        get_user_auth_token_version_func,
        ensure_user_can_authenticate_func,
        http_exception_cls,
    ):
        self.resolve_current_user_func = resolve_current_user_func
        self.core_get_active_invite_func = core_get_active_invite_func
        self.user_model = user_model
        self.registration_invite_model = registration_invite_model
        self.jwt_module = jwt_module
        self.jwt_secret = jwt_secret
        self.algorithm = algorithm
        self.get_user_auth_token_version_func = get_user_auth_token_version_func
        self.ensure_user_can_authenticate_func = ensure_user_can_authenticate_func
        self.http_exception_cls = http_exception_cls

    def get_current_user(self, request, token, db):
        return self.resolve_current_user_func(
            request,
            token,
            db,
            user_model=self.user_model,
            jwt_module=self.jwt_module,
            jwt_secret=self.jwt_secret,
            algorithm=self.algorithm,
            get_user_auth_token_version_func=self.get_user_auth_token_version_func,
            ensure_user_can_authenticate_func=self.ensure_user_can_authenticate_func,
            http_exception_cls=self.http_exception_cls,
        )

    def get_active_invite(self, db, token: str | None):
        return self.core_get_active_invite_func(
            db,
            token,
            registration_invite_model=self.registration_invite_model,
        )
