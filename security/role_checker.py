from fastapi import Depends, HTTPException, status
from common.models import User
from common.payments_helper import get_current_user

class RoleChecker:
    def __init__(self, required_roles: list[str]):
        self.required_roles = required_roles

    def __call__(self, current_user: User = Depends(get_current_user)):
        if current_user.role not in self.required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for your role"
            )
        return current_user

admin_role = RoleChecker(["admin"])
manager_role = RoleChecker(["manager"])
admin_or_manager = RoleChecker(["admin", "manager"])
any_authenticated = RoleChecker(["admin", "manager", "user"])
