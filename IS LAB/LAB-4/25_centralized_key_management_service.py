"""Question 25: Centralized key management service

Build a configurable healthcare key-management service with key generation, secure storage, distribution, renewal, revocation and auditing.
"""

import math


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


class CentralKMS:
    def __init__(self, algorithm="RSA"):
        self.algorithm = algorithm.upper()
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

    def register(self, entity):
        keypair = self._generate_rsa(len(self.records))
        self.records[entity] = {"keys": keypair, "revoked": False, "version": 1, "authorized": {entity}}
        self.logs.append(f"register -> {entity}")
        return keypair

    def authorize(self, entity, user):
        self.records[entity]["authorized"].add(user)
        self.logs.append(f"authorize -> {entity} for {user}")

    def distribute_public(self, entity, user):
        self.logs.append(f"distribute_public -> {entity} to {user}")
        return self.records[entity]["keys"]["public"]

    def get_private(self, entity, requester):
        record = self.records[entity]
        if record["revoked"]:
            raise PermissionError(f"{entity} is revoked")
        if requester not in record["authorized"]:
            raise PermissionError(f"{requester} is not authorized")
        self.logs.append(f"access_private -> {entity} by {requester}")
        return record["keys"]["private"]

    def renew(self, entity):
        record = self.records[entity]
        record["keys"] = self._generate_rsa(record["version"] + 1)
        record["version"] += 1
        self.logs.append(f"renew -> {entity} version={record['version']}")
        return record["keys"]

    def revoke(self, entity):
        self.records[entity]["revoked"] = True
        self.logs.append(f"revoke -> {entity}")


def main():
    print("==============================")
    print("CENTRALIZED HEALTHCARE KMS")
    print("==============================")
    print()
    kms = CentralKMS("RSA")
    for entity in ["HospitalA", "ClinicB", "LabC"]:
        kms.register(entity)
    kms.authorize("HospitalA", "Admin")
    kms.authorize("ClinicB", "Admin")
    print("HospitalA public:", kms.distribute_public("HospitalA", "ClinicB"))
    print("ClinicB public:", kms.distribute_public("ClinicB", "HospitalA"))
    print("Admin reads HospitalA private:", kms.get_private("HospitalA", "Admin"))
    print("Renew ClinicB:", kms.renew("ClinicB"))
    kms.revoke("LabC")
    try:
        print(kms.get_private("LabC", "LabC"))
    except Exception as exc:
        print("Denied:", exc)
    print()
    print("Audit Log:")
    for log in kms.logs:
        print(log)


if __name__ == "__main__":
    main()
