"""L3 additional q1 drm key access control

DigiRights needs an ElGamal-based DRM key-management and access-control service. Implement content encryption, authorized and time-limited access, creator-managed permissions, revocation, renewal, secure storage and audit logging.
"""

import secrets
import math
from datetime import datetime, timedelta


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


def prime_factors(n):
    factors = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def primitive_root(p):
    phi = p - 1
    factors = prime_factors(phi)
    for g in range(2, p):
        if all(pow(g, phi // f, p) != 1 for f in factors):
            return g
    raise ValueError("No primitive root found")


def elgamal_keygen(p=467, g=None, d=127):
    if not is_prime(p):
        raise ValueError("ElGamal requires a prime p")
    if g is None:
        g = primitive_root(p)
    y = pow(g, d, p)
    return {"public": {"p": p, "g": g, "y": y}, "private": {"p": p, "g": g, "d": d}}


def elgamal_encrypt(data, public_key):
    pairs = []
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]
    for b in data:
        k = secrets.randbelow(p - 3) + 2
        c1 = pow(g, k, p)
        c2 = (b * pow(y, k, p)) % p
        pairs.append((c1, c2))
    return pairs


def elgamal_decrypt(pairs, private_key):
    p = private_key["p"]
    d = private_key["d"]
    out = []
    for c1, c2 in pairs:
        s = pow(c1, d, p)
        out.append((c2 * modinv(s, p)) % p)
    return bytes(out)


class DRMService:
    def __init__(self):
        self.catalog = {}
        self.logs = []

    def add_content(self, content_id, creator, content, allowed_users, valid_minutes=30):
        keys = elgamal_keygen()
        cipher = elgamal_encrypt(content.encode(), keys["public"])
        self.catalog[content_id] = {
            "creator": creator,
            "cipher": cipher,
            "keys": keys,
            "allowed_users": set(allowed_users),
            "expires": datetime.now() + timedelta(minutes=valid_minutes),
            "revoked": set(),
        }
        self.logs.append(f"add -> {content_id} by {creator}")

    def get_content(self, content_id, user):
        record = self.catalog[content_id]
        if datetime.now() > record["expires"]:
            raise PermissionError("license expired")
        if user in record["revoked"]:
            raise PermissionError("user revoked")
        if user not in record["allowed_users"]:
            raise PermissionError("user not authorized")
        recovered = elgamal_decrypt(record["cipher"], record["keys"]["private"]).decode()
        self.logs.append(f"access -> {content_id} by {user}")
        return recovered

    def revoke_user(self, content_id, user):
        self.catalog[content_id]["revoked"].add(user)
        self.logs.append(f"revoke -> {content_id} for {user}")

    def renew(self, content_id, extra_minutes=30):
        self.catalog[content_id]["expires"] = datetime.now() + timedelta(minutes=extra_minutes)
        self.logs.append(f"renew -> {content_id}")


def main():
    print("==============================")
    print("DIGIRIGHTS DRM KEY ACCESS CONTROL")
    print("==============================")
    print()
    drm = DRMService()
    drm.add_content("video1", "CreatorA", "COPY-PROTECTED", ["Alice", "Bob"], valid_minutes=0)
    drm.renew("video1", 30)
    print("Alice access:", drm.get_content("video1", "Alice"))
    try:
        print("Eve access:", drm.get_content("video1", "Eve"))
    except Exception as exc:
        print("Denied:", exc)
    drm.revoke_user("video1", "Bob")
    try:
        print("Bob access after revoke:", drm.get_content("video1", "Bob"))
    except Exception as exc:
        print("Denied after revoke:", exc)
    print()
    print("Audit Log:")
    for log in drm.logs:
        print(log)


if __name__ == "__main__":
    main()
