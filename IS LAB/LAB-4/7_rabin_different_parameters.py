"""Question 7: Rabin different parameters

Modify Rabin for different p,q and plaintext values; generate keys, encrypt/decrypt and identify the original root.
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


def rabin_keygen(p, q):
    if not (is_prime(p) and is_prime(q) and p % 4 == 3 and q % 4 == 3):
        raise ValueError("Rabin requires primes congruent to 3 mod 4")
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
    return mp, mq, sorted(set(roots))


def main():
    print("==============================")
    print("RABIN DIFFERENT PARAMETERS")
    print("==============================")
    print()
    p = 563
    q = 587
    plaintext = 77
    keys = rabin_keygen(p, q)
    encoded = rabin_encode(plaintext)
    ciphertext = pow(encoded, 2, keys["public"]["n"])
    mp, mq, roots = rabin_roots(ciphertext, p, q)
    original = next((r for r in roots if r % 100 == 99), roots[0])
    recovered = rabin_decode(original)
    print("p:", p)
    print("q:", q)
    print("n:", keys["public"]["n"])
    print("Plaintext:", plaintext)
    print("Encoded Plaintext:", encoded)
    print("Ciphertext:", ciphertext)
    print("mp:", mp)
    print("mq:", mq)
    print("Four Roots:", roots)
    print("Original Root:", original)
    print("Recovered Plaintext:", recovered)
    print("Verified:", recovered == plaintext)


if __name__ == "__main__":
    main()
