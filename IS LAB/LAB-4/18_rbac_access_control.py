"""Question 18: Rbac access control

Implement role-based access control with role permissions, permission changes and revocation.
"""


class RBAC:
    def __init__(self):
        self.user_roles = {}
        self.role_permissions = {}

    def add_role(self, role):
        self.role_permissions.setdefault(role, set())

    def assign_role(self, user, role):
        self.add_role(role)
        self.user_roles.setdefault(user, set()).add(role)

    def grant(self, role, permission):
        self.add_role(role)
        self.role_permissions[role].add(permission)

    def revoke_permission(self, role, permission):
        self.role_permissions.get(role, set()).discard(permission)

    def revoke_role(self, user, role=None):
        if user not in self.user_roles:
            return
        if role is None:
            self.user_roles[user].clear()
        else:
            self.user_roles[user].discard(role)

    def can_access(self, user, permission):
        return any(permission in self.role_permissions.get(role, set()) for role in self.user_roles.get(user, set()))


def main():
    print("==============================")
    print("RBAC ACCESS CONTROL")
    print("==============================")
    print()
    ac = RBAC()
    ac.grant("admin", "read")
    ac.grant("admin", "write")
    ac.grant("doctor", "read")
    ac.assign_role("Alice", "admin")
    ac.assign_role("Bob", "doctor")
    print("Alice read access:", ac.can_access("Alice", "read"))
    print("Bob write access:", ac.can_access("Bob", "write"))
    print("Revoking doctor read permission")
    ac.revoke_permission("doctor", "read")
    print("Bob read access after revoke:", ac.can_access("Bob", "read"))


if __name__ == "__main__":
    main()
