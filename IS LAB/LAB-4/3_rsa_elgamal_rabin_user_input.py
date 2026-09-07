"""Question 3: Rsa elgamal rabin user input

Accept algorithm, keys/parameters and plaintext from the user; validate inputs and perform encryption/decryption.
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


def rsa_keygen(p, q, e):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("RSA requires prime p and q")
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError("Invalid RSA exponent")
    d = modinv(e, phi)
    return {"public": {"n": n, "e": e}, "private": {"n": n, "d": d}}


def rsa_encrypt(data, public_key):
    return [pow(b, public_key["e"], public_key["n"]) for b in data]


def rsa_decrypt(blocks, private_key):
    return bytes(pow(b, private_key["d"], private_key["n"]) for b in blocks)


def elgamal_keygen(p, g, d):
    if not is_prime(p):
        raise ValueError("ElGamal requires prime p")
    if g is None:
        g = primitive_root(p)
    if g <= 1 or g >= p:
        raise ValueError("Invalid generator")
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


def ask_int(prompt, default):
    try:
        raw = input(f"{prompt} [{default}]: ").strip()
    except EOFError:
        raw = ""
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print("Invalid integer. Using default.")
        return default


def ask_text(prompt, default):
    try:
        raw = input(f"{prompt} [{default}]: ").strip()
    except EOFError:
        raw = ""
    return raw if raw else default


def main():
    print("==============================")
    print("RSA, ELGAMAL, RABIN USER INPUT")
    print("==============================")
    print()
    algo = ask_text("Choose algorithm (rsa/elgamal/rabin)", "rsa").lower()
    text = ask_text("Enter plaintext", "LAB")

    try:
        if algo == "rsa":
            p = ask_int("Enter prime p", 383)
            q = ask_int("Enter prime q", 503)
            e = ask_int("Enter public exponent e", 17)
            keys = rsa_keygen(p, q, e)
            blocks = rsa_encrypt(text.encode(), keys["public"])
            recovered = rsa_decrypt(blocks, keys["private"]).decode()
            print("RSA")
            print("Public Key:", keys["public"])
            print("Private Key:", keys["private"])
            print("Plaintext:", text)
            print("Ciphertext:", blocks)
            print("Recovered Plaintext:", recovered)
            print("Verified:", recovered == text)
        elif algo == "elgamal":
            p = ask_int("Enter prime p", 467)
            g = ask_int("Enter generator g (0 for auto)", 0)
            d = ask_int("Enter private key d", 127)
            if g == 0:
                g = primitive_root(p)
            if not (is_prime(p) and g > 1 and g < p):
                raise ValueError("Invalid ElGamal parameters")
            keys = elgamal_keygen(p, g, d)
            pairs = elgamal_encrypt(text.encode(), keys["public"])
            recovered = elgamal_decrypt(pairs, keys["private"]).decode()
            print("ELGAMAL")
            print("Public Key:", keys["public"])
            print("Private Key:", keys["private"])
            print("Plaintext:", text)
            print("Ciphertext:", pairs)
            print("Recovered Plaintext:", recovered)
            print("Verified:", recovered == text)
        elif algo == "rabin":
            p = ask_int("Enter prime p", 499)
            q = ask_int("Enter prime q", 547)
            value = ask_int("Enter plaintext integer", 123)
            keys = rabin_keygen(p, q)
            encoded = rabin_encode(value)
            ciphertext = pow(encoded, 2, keys["public"]["n"])
            mp, mq, roots = rabin_roots(ciphertext, keys["private"]["p"], keys["private"]["q"])
            original = next((r for r in roots if r % 100 == 99), roots[0])
            recovered = rabin_decode(original)
            print("RABIN")
            print("Public Key:", keys["public"])
            print("Private Key:", keys["private"])
            print("Encoded Plaintext:", encoded)
            print("Ciphertext:", ciphertext)
            print("mp:", mp)
            print("mq:", mq)
            print("Four Roots:", roots)
            print("Original Root:", original)
            print("Recovered Plaintext:", recovered)
            print("Verified:", recovered == value)
        else:
            print("Invalid algorithm choice.")
    except Exception as exc:
        print("Error:", exc)


if __name__ == "__main__":
    main()
