"""
21. asymmetric_multiple_messages

Encrypt/decrypt multiple messages of different sizes using RSA, ElGamal
and/or ECC; verify every recovered plaintext and compare execution times.
"""

import time
import random

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, bytes_to_long


# RSA key generation
def rsa_keygen():

    t = time.perf_counter()

    key = RSA.generate(2048)

    et = time.perf_counter() - t

    return key, et


# ElGamal key generation
def elgamal_keygen():

    t = time.perf_counter()

    p = getPrime(2048)
    g = 2
    d = random.randint(2, p - 2)

    e1 = g
    e2 = pow(e1, d, p)

    et = time.perf_counter() - t

    return p, e1, e2, d, et


# ECC key generation
def ecc_keygen():

    t = time.perf_counter()

    key = ECC.generate(curve="P-256")

    et = time.perf_counter() - t

    return key, et


# RSA encryption and decryption
def rsa_test(key, pt):

    if len(pt) > 190:
        return None, None, False

    cipher = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256)

    t = time.perf_counter()

    ct = cipher.encrypt(pt)

    enc = time.perf_counter() - t

    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)

    t = time.perf_counter()

    dt = cipher.decrypt(ct)

    dec = time.perf_counter() - t

    return enc, dec, dt == pt


# ElGamal encryption and decryption
def elgamal_test(p, e1, e2, d, pt):

    m = bytes_to_long(pt)

    if m >= p:
        return None, None, False

    # Random temporary key
    k = random.randint(2, p - 2)

    # Encryption
    t = time.perf_counter()

    c1 = pow(e1, k, p)
    c2 = (m * pow(e2, k, p)) % p

    enc = time.perf_counter() - t

    # Decryption
    t = time.perf_counter()

    s = pow(c1, d, p)
    s_inv = inverse(s, p)

    m2 = (c2 * s_inv) % p

    dec = time.perf_counter() - t

    return enc, dec, m2 == m


# ECC + AES encryption and decryption
def ecc_test(key, pt):

    # Generate temporary ECC key
    eph = ECC.generate(curve=key.curve)

    # Calculate shared secret
    t = time.perf_counter()

    s = eph.d * key.public_key().pointQ

    # Derive AES key
    k = SHA256.new(
        int(s.x).to_bytes(32, "big")
    ).digest()

    # Encrypt
    cipher = AES.new(k, AES.MODE_EAX)

    ct, tag = cipher.encrypt_and_digest(pt)

    enc = time.perf_counter() - t

    # Decrypt
    t = time.perf_counter()

    s2 = key.d * eph.public_key().pointQ

    k2 = SHA256.new(
        int(s2.x).to_bytes(32, "big")
    ).digest()

    cipher2 = AES.new(
        k2,
        AES.MODE_EAX,
        nonce=cipher.nonce
    )

    dt = cipher2.decrypt_and_verify(ct, tag)

    dec = time.perf_counter() - t

    return enc, dec, dt == pt


def rsa_messages():

    print("\n========== RSA MULTIPLE MESSAGES ==========")

    sizes = [16, 32, 64, 128, 190]

    key, kt = rsa_keygen()

    print("RSA Key Generation:", kt, "seconds")

    for size in sizes:

        pt = b"A" * size

        enc, dec, ok = rsa_test(key, pt)

        print("\nMessage Size:", size, "bytes")

        if enc is None:
            print("Message too large for RSA-OAEP-SHA256")
            continue

        print("Encryption:", enc, "seconds")
        print("Decryption:", dec, "seconds")
        print("Verified:", ok)


def elgamal_messages():

    print("\n========== ELGAMAL MULTIPLE MESSAGES ==========")

    sizes = [16, 32, 64, 128, 256]

    p, e1, e2, d, kt = elgamal_keygen()

    print("ElGamal Key Generation:", kt, "seconds")

    for size in sizes:

        pt = b"A" * size

        enc, dec, ok = elgamal_test(
            p, e1, e2, d, pt
        )

        print("\nMessage Size:", size, "bytes")

        if enc is None:
            print("Message too large for ElGamal modulus")
            continue

        print("Encryption:", enc, "seconds")
        print("Decryption:", dec, "seconds")
        print("Verified:", ok)


def ecc_messages():

    print("\n========== ECC MULTIPLE MESSAGES ==========")

    sizes = [16, 64, 128, 256, 512]

    key, kt = ecc_keygen()

    print("ECC Key Generation:", kt, "seconds")

    for size in sizes:

        pt = b"A" * size

        enc, dec, ok = ecc_test(key, pt)

        print("\nMessage Size:", size, "bytes")
        print("Encryption:", enc, "seconds")
        print("Decryption:", dec, "seconds")
        print("Verified:", ok)


def main():

    while True:

        print("\n========== MULTIPLE MESSAGE TEST ==========")
        print("1. RSA")
        print("2. ElGamal")
        print("3. ECC")
        print("4. All algorithms")
        print("5. Exit")

        ch = int(input("Enter your choice: "))

        if ch == 1:
            rsa_messages()

        elif ch == 2:
            elgamal_messages()

        elif ch == 3:
            ecc_messages()

        elif ch == 4:
            rsa_messages()
            elgamal_messages()
            ecc_messages()

        elif ch == 5:
            print("Exiting...")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()