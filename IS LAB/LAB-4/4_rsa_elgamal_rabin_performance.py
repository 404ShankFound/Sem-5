"""Question 4: Rsa elgamal rabin performance

Measure key-generation, encryption and decryption times for RSA, ElGamal and Rabin; compare results.
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
    return {"public": {"n": n, "e": e}, "private": {"n": n, "d": d}}


def rsa_encrypt(data, public_key):
    return [pow(b, public_key["e"], public_key["n"]) for b in data]


def rsa_decrypt(blocks, private_key):
    return bytes(pow(b, private_key["d"], private_key["n"]) for b in blocks)


def elgamal_keygen(p=467, g=None, d=127):
    if not is_prime(p):
        raise ValueError("ElGamal requires prime p")
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


def rabin_keygen(p=499, q=547):
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


def measure(func, *args):
    start = time.perf_counter()
    result = func(*args)
    return result, time.perf_counter() - start


def main():
    print("==============================")
    print("RSA, ELGAMAL, RABIN PERFORMANCE")
    print("==============================")
    print()

    message = b"PERF"

    rsa_keys, t1 = measure(rsa_keygen)
    rsa_ct, t2 = measure(rsa_encrypt, message, rsa_keys["public"])
    rsa_pt, t3 = measure(rsa_decrypt, rsa_ct, rsa_keys["private"])
    print("RSA")
    print("Key Generation Time:", f"{t1:.6f} s")
    print("Encryption Time:", f"{t2:.6f} s")
    print("Decryption Time:", f"{t3:.6f} s")
    print("Verified:", rsa_pt == message)
    print()

    elg_keys, t4 = measure(elgamal_keygen)
    elg_ct, t5 = measure(elgamal_encrypt, message, elg_keys["public"])
    elg_pt, t6 = measure(elgamal_decrypt, elg_ct, elg_keys["private"])
    print("ELGAMAL")
    print("Key Generation Time:", f"{t4:.6f} s")
    print("Encryption Time:", f"{t5:.6f} s")
    print("Decryption Time:", f"{t6:.6f} s")
    print("Verified:", elg_pt == message)
    print()

    rabin_keys, t7 = measure(rabin_keygen)
    encoded = rabin_encode(123)
    ciphertext, t8 = measure(pow, encoded, 2, rabin_keys["public"]["n"])
    roots_info, t9 = measure(rabin_roots, ciphertext, rabin_keys["private"]["p"], rabin_keys["private"]["q"])
    original = next((r for r in roots_info[2] if r % 100 == 99), roots_info[2][0])
    recovered = rabin_decode(original)
    print("RABIN")
    print("Key Generation Time:", f"{t7:.6f} s")
    print("Encryption Time:", f"{t8:.6f} s")
    print("Decryption Time:", f"{t9:.6f} s")
    print("Verified:", recovered == 123)


if __name__ == "__main__":
    main()
