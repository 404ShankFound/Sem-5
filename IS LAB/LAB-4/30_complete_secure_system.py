"""Question 30: Complete secure system

Build an interactive program combining cryptography, key management, access control, renewal/revocation, auditing and performance measurement.
"""

import math
import time


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % m


def is_prime(n):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in [2, 3, 5, 7, 11]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


class Audit:
    def __init__(self):
        self.logs = []

    def log(self, action):
        self.logs.append(action)


class RBAC:
    def __init__(self):
        self.user_roles = {}
        self.role_permissions = {}

    def grant_role(self, user, role):
        self.user_roles.setdefault(user, set()).add(role)

    def grant_permission(self, role, permission):
        self.role_permissions.setdefault(role, set()).add(permission)

    def can_access(self, user, permission):
        return any(permission in self.role_permissions.get(role, set()) for role in self.user_roles.get(user, set()))


class SecureSystem:
    def __init__(self):
        p, q, e = 383, 503, 17
        n = p * q
        d = modinv(e, (p - 1) * (q - 1))
        self.keys = {"public": {"n": n, "e": e}, "private": {"n": n, "d": d}}
        self.active = {"admin": True, "user": True}
        self.rbac = RBAC()
        self.audit = Audit()
        self.version = 1

    def encrypt_message(self, text):
        pub = self.keys["public"]
        return [pow(b, pub["e"], pub["n"]) for b in text.encode()]

    def decrypt_message(self, blocks):
        priv = self.keys["private"]
        return bytes(pow(b, priv["d"], priv["n"]) for b in blocks).decode()

    def renew_keys(self):
        p, q, e = 389, 509, 17
        n = p * q
        d = modinv(e, (p - 1) * (q - 1))
        self.keys = {"public": {"n": n, "e": e}, "private": {"n": n, "d": d}}
        self.version += 1
        self.audit.log(f"renew -> version {self.version}")

    def revoke_user(self, user):
        self.active[user] = False
        self.audit.log(f"revoke -> {user}")


def measure(func, *args):
    start = time.perf_counter()
    result = func(*args)
    return result, time.perf_counter() - start


def main():
    print("==============================")
    print("COMPLETE SECURE SYSTEM")
    print("==============================")
    print()
    system = SecureSystem()
    system.rbac.grant_role("Alice", "admin")
    system.rbac.grant_role("Bob", "user")
    system.rbac.grant_permission("admin", "encrypt")
    system.rbac.grant_permission("user", "read")

    cipher, enc_time = measure(system.encrypt_message, "SECRET")
    plain, dec_time = measure(system.decrypt_message, cipher)
    print("Encrypted Message:", cipher)
    print("Recovered Message:", plain)
    print("Encryption Time:", f"{enc_time:.6f} s")
    print("Decryption Time:", f"{dec_time:.6f} s")
    print("Alice can encrypt:", system.rbac.can_access("Alice", "encrypt"))
    print("Bob can encrypt:", system.rbac.can_access("Bob", "encrypt"))

    system.renew_keys()
    system.revoke_user("Bob")
    print("Bob active after revoke:", system.active["Bob"])
    print("Current Key Version:", system.version)
    print()
    print("Audit Log:")
    for log in system.audit.logs:
        print(log)


if __name__ == "__main__":
    main()
