"""Question 13: Key renewal expiry

Implement key lifetime, expiry and automatic renewal while retaining key-management records.
"""

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


class KMS:
    def __init__(self):
        self.records = {}
        self.logs = []
        self.key_pairs = [
            (383, 503, 17),
            (389, 509, 17),
            (397, 521, 17),
            (401, 523, 17),
        ]

    def _generate_rsa(self, index):
        p, q, e = self.key_pairs[index % len(self.key_pairs)]
        if not (is_prime(p) and is_prime(q)):
            raise ValueError("Invalid internal prime pair")
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            e = 65537
        d = modinv(e, phi)
        return {"public": {"n": n, "e": e}, "private": {"n": n, "d": d, "p": p, "q": q}}

    def register(self, entity, lifetime_seconds=2):
        keypair = self._generate_rsa(len(self.records))
        record = {
            "keys": keypair,
            "revoked": False,
            "version": 1,
            "created": datetime.now(),
            "expires": datetime.now() + timedelta(seconds=lifetime_seconds),
        }
        self.records[entity] = record
        self.logs.append(f"register -> {entity}")
        return keypair

    def is_expired(self, entity):
        return datetime.now() > self.records[entity]["expires"]

    def renew(self, entity, lifetime_seconds=2):
        record = self.records[entity]
        record["keys"] = self._generate_rsa(record["version"] + 1)
        record["version"] += 1
        record["created"] = datetime.now()
        record["expires"] = datetime.now() + timedelta(seconds=lifetime_seconds)
        self.logs.append(f"renew -> {entity} version={record['version']}")
        return record["keys"]

    def ensure_active(self, entity):
        if self.is_expired(entity):
            self.logs.append(f"auto_renew -> {entity}")
            return self.renew(entity)
        return self.records[entity]["keys"]


def main():
    print("==============================")
    print("KEY RENEWAL EXPIRY")
    print("==============================")
    print()
    kms = KMS()
    kms.register("Alice", lifetime_seconds=0)
    print("Initial Record:", kms.records["Alice"])
    if kms.is_expired("Alice"):
        print("Alice key expired, auto renewing...")
    active = kms.ensure_active("Alice")
    print("Active Key:", active)
    print("Renewed Record:", kms.records["Alice"])
    print()
    print("Audit Log:")
    for log in kms.logs:
        print(log)


if __name__ == "__main__":
    main()
