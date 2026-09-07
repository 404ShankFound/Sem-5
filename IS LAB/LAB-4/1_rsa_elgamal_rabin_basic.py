"""Question 1: Rsa elgamal rabin basic

Implement RSA, ElGamal and Rabin encryption/decryption; generate/use keys and verify recovered plaintext.
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


def rsa_encrypt(data, public_key):
    n = public_key["n"]
    e = public_key["e"]
    return [pow(b, e, n) for b in data]


def rsa_decrypt(blocks, private_key):
    n = private_key["n"]
    d = private_key["d"]
    return bytes(pow(b, d, n) for b in blocks)


def elgamal_keygen(p=467, g=None, d=127):
    if not is_prime(p):
        raise ValueError("ElGamal requires a prime p")
    if g is None:
        g = primitive_root(p)
    y = pow(g, d, p)
    return {"public": {"p": p, "g": g, "y": y}, "private": {"p": p, "g": g, "d": d}}


def elgamal_encrypt(data, public_key):
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]
    pairs = []
    for b in data:
        k = secrets.randbelow(p - 3) + 2
        c1 = pow(g, k, p)
        c2 = (b * pow(y, k, p)) % p
        pairs.append((c1, c2))
    return pairs


def elgamal_decrypt(pairs, private_key):
    p = private_key["p"]
    d = private_key["d"]
    recovered = []
    for c1, c2 in pairs:
        s = pow(c1, d, p)
        recovered.append((c2 * modinv(s, p)) % p)
    return bytes(recovered)


def rabin_keygen(p=499, q=547):
    if not (is_prime(p) and is_prime(q) and p % 4 == 3 and q % 4 == 3):
        raise ValueError("Rabin requires primes congruent to 3 mod 4")
    return {"public": {"n": p * q}, "private": {"p": p, "q": q}}


def rabin_encode(value):
    return value * 100 + 99


def rabin_decode(value):
    if value % 100 == 99:
        return value // 100
    return None


def rabin_roots(ciphertext, p, q):
    n = p * q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    roots = []
    for sp in [mp, (-mp) % p]:
        for sq in [mq, (-mq) % q]:
            q_inv = modinv(q, p)
            p_inv = modinv(p, q)
            root = (sp * q * q_inv + sq * p * p_inv) % n
            roots.append(root)
    roots = sorted(set(roots))
    return mp, mq, roots


def main():
    print("==============================")
    print("RSA, ELGAMAL, RABIN BASIC")
    print("==============================")
    print()

    message = b"LAB"

    rsa = rsa_keygen()
    rsa_ct = rsa_encrypt(message, rsa["public"])
    rsa_pt = rsa_decrypt(rsa_ct, rsa["private"])
    print("RSA")
    print("Public Key:", rsa["public"])
    print("Private Key:", {"d": rsa["private"]["d"]})
    print("Plaintext:", message.decode())
    print("Ciphertext:", rsa_ct)
    print("Recovered Plaintext:", rsa_pt.decode())
    print("Verified:", rsa_pt == message)
    print()

    elg = elgamal_keygen()
    elg_ct = elgamal_encrypt(message, elg["public"])
    elg_pt = elgamal_decrypt(elg_ct, elg["private"])
    print("ELGAMAL")
    print("Public Key:", elg["public"])
    print("Private Key:", {"d": elg["private"]["d"]})
    print("Plaintext:", message.decode())
    print("Ciphertext:", elg_ct)
    print("Recovered Plaintext:", elg_pt.decode())
    print("Verified:", elg_pt == message)
    print()

    rabin = rabin_keygen()
    plain_value = rabin_encode(123)
    ct = pow(plain_value, 2, rabin["public"]["n"])
    mp, mq, roots = rabin_roots(ct, rabin["private"]["p"], rabin["private"]["q"])
    original_root = next((r for r in roots if r % 100 == 99), roots[0])
    recovered_value = rabin_decode(original_root)
    print("RABIN")
    print("Public Key:", rabin["public"])
    print("Private Key:", {"p": rabin["private"]["p"], "q": rabin["private"]["q"]})
    print("Encoded Plaintext:", plain_value)
    print("Ciphertext:", ct)
    print("mp:", mp)
    print("mq:", mq)
    print("Four Roots:", roots)
    print("Original Root:", original_root)
    print("Recovered Plaintext:", recovered_value)
    print("Verified:", recovered_value == 123)


if __name__ == "__main__":
    main()
