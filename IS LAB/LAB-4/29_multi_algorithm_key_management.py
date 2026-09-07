"""Question 29: Multi algorithm key management

Build one modular system supporting RSA, ElGamal and Rabin key generation, storage, distribution, renewal, revocation and performance comparison.
"""

import math
import secrets
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


class MultiAlgoKMS:
    def __init__(self):
        self.records = {}
        self.logs = []
        self.algorithms = ["RSA", "ELGAMAL", "RABIN"]

    def generate(self, algorithm):
        if algorithm == "RSA":
            p, q, e = 383, 503, 17
            n = p * q
            d = modinv(e, (p - 1) * (q - 1))
            return {"public": {"n": n, "e": e}, "private": {"n": n, "d": d}}
        if algorithm == "ELGAMAL":
            p = 467
            g = primitive_root(p)
            d = 127
            y = pow(g, d, p)
            return {"public": {"p": p, "g": g, "y": y}, "private": {"p": p, "g": g, "d": d}}
        if algorithm == "RABIN":
            p, q = 499, 547
            return {"public": {"n": p * q}, "private": {"p": p, "q": q}}
        raise ValueError("Unsupported algorithm")

    def register(self, entity, algorithm):
        self.records[entity] = {"algorithm": algorithm, "keys": self.generate(algorithm), "revoked": False, "version": 1}
        self.logs.append(f"register -> {entity} using {algorithm}")

    def renew(self, entity):
        algo = self.records[entity]["algorithm"]
        self.records[entity]["keys"] = self.generate(algo)
        self.records[entity]["version"] += 1
        self.logs.append(f"renew -> {entity} v{self.records[entity]['version']}")

    def revoke(self, entity):
        self.records[entity]["revoked"] = True
        self.logs.append(f"revoke -> {entity}")

    def distribute_public(self, entity, user):
        self.logs.append(f"distribute_public -> {entity} to {user}")
        return self.records[entity]["keys"]["public"]


def measure(func, *args):
    start = time.perf_counter()
    result = func(*args)
    return result, time.perf_counter() - start


def main():
    print("==============================")
    print("MULTI-ALGORITHM KEY MANAGEMENT")
    print("==============================")
    print()
    kms = MultiAlgoKMS()
    kms.register("Alice", "RSA")
    kms.register("Bob", "ELGAMAL")
    kms.register("Carol", "RABIN")
    print("Alice public:", kms.distribute_public("Alice", "Admin"))
    print("Bob public:", kms.distribute_public("Bob", "Admin"))
    print("Carol public:", kms.distribute_public("Carol", "Admin"))
    print()
    _, t1 = measure(kms.generate, "RSA")
    _, t2 = measure(kms.generate, "ELGAMAL")
    _, t3 = measure(kms.generate, "RABIN")
    print("Performance Comparison:")
    print("RSA key generation:", f"{t1:.6f} s")
    print("ElGamal key generation:", f"{t2:.6f} s")
    print("Rabin key generation:", f"{t3:.6f} s")
    print()
    print("Renew Bob and revoke Carol")
    kms.renew("Bob")
    kms.revoke("Carol")
    for entity, record in kms.records.items():
        print(entity, "->", record["algorithm"], "revoked:", record["revoked"], "version:", record["version"])
    print()
    print("Audit Log:")
    for log in kms.logs:
        print(log)


if __name__ == "__main__":
    main()
