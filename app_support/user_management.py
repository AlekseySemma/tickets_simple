def manageable_roles_for_web_user_management(actor, *, role_enum):
    if actor.role == role_enum.admin:
        return (role_enum.curator, role_enum.executor)
    if actor.role == role_enum.curator:
        return (role_enum.executor,)
    return tuple()


def can_manage_company_user(actor, target, *, manager_roles, role_enum) -> bool:
    if actor.company_id != target.company_id:
        return False
    if actor.id == target.id and actor.role in manager_roles:
        return True
    return target.role in manageable_roles_for_web_user_management(actor, role_enum=role_enum)
