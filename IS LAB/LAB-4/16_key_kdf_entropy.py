"""Question 16: Key kdf entropy

Implement key-related operations using entropy calculation and/or a KDF with key, salt and iterations; display the result.
"""

import hashlib
import math


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    total = len(text)
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def derive_key(password, salt, iterations, length=32):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        iterations,
        dklen=length,
    )


def ask_text(prompt, default):
    try:
        raw = input(f"{prompt} [{default}]: ").strip()
    except EOFError:
        raw = ""
    return raw if raw else default


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


def main():
    print("==============================")
    print("KEY KDF ENTROPY")
    print("==============================")
    print()
    key = ask_text("Enter password/key", "secret-key")
    salt = ask_text("Enter salt", "lab-salt")
    iterations = ask_int("Enter iterations", 100000)
    entropy = shannon_entropy(key)
    derived = derive_key(key, salt, iterations)
    print("Key:", key)
    print("Salt:", salt)
    print("Iterations:", iterations)
    print("Shannon Entropy:", f"{entropy:.4f} bits/char")
    print("Derived Key (hex):", derived.hex())


if __name__ == "__main__":
    main()
