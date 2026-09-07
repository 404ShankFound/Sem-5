"""Question 2: Rsa elgamal rabin key generation

Generate public/private keys for RSA, ElGamal and Rabin; display all required parameters.
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
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small:
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


def rsa_keygen(p=383, q=503, e=17):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("RSA requires prime p and q")
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        e = 65537
        if math.gcd(e, phi) != 1:
            e = 17
    d = modinv(e, phi)
    return {"public": {"n": n, "e": e}, "private": {"n": n, "d": d, "p": p, "q": q}}


def elgamal_keygen(p=467, g=None, d=127):
    if not is_prime(p):
        raise ValueError("ElGamal requires a prime p")
    if g is None:
        g = primitive_root(p)
    y = pow(g, d, p)
    return {"public": {"p": p, "g": g, "y": y}, "private": {"p": p, "g": g, "d": d}}


def rabin_keygen(p=499, q=547):
    if not (is_prime(p) and is_prime(q) and p % 4 == 3 and q % 4 == 3):
        raise ValueError("Rabin requires primes congruent to 3 mod 4")
    return {"public": {"n": p * q}, "private": {"p": p, "q": q}}


def main():
    print("==============================")
    print("RSA, ELGAMAL, RABIN KEY GENERATION")
    print("==============================")
    print()

    rsa = rsa_keygen()
    print("RSA")
    print("Public Key:", rsa["public"])
    print("Private Key:", rsa["private"])
    print()

    elg = elgamal_keygen()
    print("ELGAMAL")
    print("Public Key:", elg["public"])
    print("Private Key:", elg["private"])
    print()

    rabin = rabin_keygen()
    print("RABIN")
    print("Public Key:", rabin["public"])
    print("Private Key:", rabin["private"])


if __name__ == "__main__":
    main()
