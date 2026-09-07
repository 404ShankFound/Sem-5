"""Question 28: Asymmetric system combination

Combine RSA, ElGamal and Rabin with key management and access control; encrypt data, control access, revoke keys and log operations.
"""

import math
import secrets


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


def rsa_keygen():
    p, q, e = 383, 503, 17
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return {"public": {"n": n, "e": e}, "private": {"n": n, "d": d}}


def rsa_encrypt(data, public_key):
    return [pow(b, public_key["e"], public_key["n"]) for b in data]


def rsa_decrypt(blocks, private_key):
    return bytes(pow(b, private_key["d"], private_key["n"]) for b in blocks)


def elgamal_keygen():
    p = 467
    g = primitive_root(p)
    d = 127
    y = pow(g, d, p)
    return {"public": {"p": p, "g": g, "y": y}, "private": {"p": p, "g": g, "d": d}}


def elgamal_encrypt(data, public_key):
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]
    out = []
    for b in data:
        k = secrets.randbelow(p - 3) + 2
        c1 = pow(g, k, p)
        c2 = (b * pow(y, k, p)) % p
        out.append((c1, c2))
    return out


def elgamal_decrypt(pairs, private_key):
    p = private_key["p"]
    d = private_key["d"]
    out = []
    for c1, c2 in pairs:
        s = pow(c1, d, p)
        out.append((c2 * modinv(s, p)) % p)
    return bytes(out)


def rabin_keygen():
    p, q = 499, 547
    return {"public": {"n": p * q}, "private": {"p": p, "q": q}}


def rabin_encode(value):
    return value * 100 + 99


def rabin_decode(value):
    return value // 100 if value % 100 == 99 else None


def rabin_roots(ciphertext, p, q):
    n = p * q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    roots = []
    for sp in [mp, (-mp) % p]:
        for sq in [mq, (-mq) % q]:
            root = (sp * q * modinv(q, p) + sq * p * modinv(p, q)) % n
            roots.append(root)
    return sorted(set(roots))


class ComboSystem:
    def __init__(self):
        self.rsa = rsa_keygen()
        self.elg = elgamal_keygen()
        self.rabin = rabin_keygen()
        self.allowed = {"admin"}
        self.logs = []

    def grant(self, user):
        self.allowed.add(user)
        self.logs.append(f"grant -> {user}")

    def revoke(self, user):
        self.allowed.discard(user)
        self.logs.append(f"revoke -> {user}")

    def encrypt_all(self, message):
        data = message.encode()
        return {
            "rsa": rsa_encrypt(data, self.rsa["public"]),
            "elgamal": elgamal_encrypt(data, self.elg["public"]),
            "rabin": pow(rabin_encode(123), 2, self.rabin["public"]["n"]),
        }

    def decrypt_all(self, payload):
        rsa_pt = rsa_decrypt(payload["rsa"], self.rsa["private"]).decode()
        elg_pt = elgamal_decrypt(payload["elgamal"], self.elg["private"]).decode()
        roots = rabin_roots(payload["rabin"], self.rabin["private"]["p"], self.rabin["private"]["q"])
        rabin_pt = rabin_decode(next(r for r in roots if r % 100 == 99))
        return rsa_pt, elg_pt, rabin_pt


def main():
    print("==============================")
    print("ASYMMETRIC SYSTEM COMBINATION")
    print("==============================")
    print()
    system = ComboSystem()
    system.grant("Alice")
    payload = system.encrypt_all("DATA")
    rsa_pt, elg_pt, rabin_pt = system.decrypt_all(payload)
    print("RSA Ciphertext:", payload["rsa"])
    print("ElGamal Ciphertext:", payload["elgamal"])
    print("Rabin Ciphertext:", payload["rabin"])
    print("Recovered RSA:", rsa_pt)
    print("Recovered ElGamal:", elg_pt)
    print("Recovered Rabin:", rabin_pt)
    print("Alice access granted:", "Alice" in system.allowed)
    system.revoke("Alice")
    print("Alice access after revoke:", "Alice" in system.allowed)
    print()
    print("Audit Log:")
    for log in system.logs:
        print(log)


if __name__ == "__main__":
    main()
