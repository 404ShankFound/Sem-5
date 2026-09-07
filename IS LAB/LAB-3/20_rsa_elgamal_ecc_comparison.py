"""
20. rsa_elgamal_ecc_comparison

Implement RSA, ElGamal and ECC for the same messages/data sizes; measure
key-generation and encryption/decryption times and compare computational
overhead.
"""

import time
import random

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
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

    # Use a simple generator for the performance experiment
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


# RSA encryption/decryption
def rsa_test(key, pt):

    cipher = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256)

    t = time.perf_counter()

    ct = cipher.encrypt(pt)

    enc = time.perf_counter() - t

    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)

    t = time.perf_counter()

    dt = cipher.decrypt(ct)

    dec = time.perf_counter() - t

    return enc, dec


# ElGamal encryption/decryption
def elgamal_test(p, e1, e2, d, pt):

    m = bytes_to_long(pt)

    if m >= p:
        return None, None

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

    return enc, dec


# ECC + AES hybrid encryption/decryption
def ecc_test(key, pt):

    # Generate temporary ECC key
    eph = ECC.generate(curve=key.curve)

    # Calculate shared secret
    t = time.perf_counter()

    s = eph.d * key.public_key().pointQ

    # Derive AES key using SHA-256
    k = SHA256.new(int(s.x).to_bytes(32, "big")).digest()

    # Encrypt plaintext using AES
    cipher = AES.new(k, AES.MODE_EAX)

    ct, tag = cipher.encrypt_and_digest(pt)

    enc = time.perf_counter() - t

    # Decryption
    t = time.perf_counter()

    s2 = key.d * eph.public_key().pointQ

    k2 = SHA256.new(int(s2.x).to_bytes(32, "big")).digest()

    cipher2 = AES.new(k2, AES.MODE_EAX, nonce=cipher.nonce)

    dt = cipher2.decrypt_and_verify(ct, tag)

    dec = time.perf_counter() - t

    return enc, dec


# Compare key-generation times
def key_comparison():

    print("\n========== KEY GENERATION ==========")

    rkey, rt = rsa_keygen()
    p, e1, e2, d, et = elgamal_keygen()
    ekey, ect = ecc_keygen()

    print("RSA-2048:", rt, "seconds")
    print("ElGamal-2048:", et, "seconds")
    print("ECC-P256:", ect, "seconds")


# Compare encryption/decryption
def encryption_comparison():

    print("\n========== ENCRYPTION / DECRYPTION ==========")

    sizes = [16, 64, 128, 190]

    rkey, rt = rsa_keygen()
    p, e1, e2, d, et = elgamal_keygen()
    ekey, ect = ecc_keygen()

    for size in sizes:

        pt = b"A" * size

        print("\nMessage Size:", size, "bytes")

        # RSA
        re, rd = rsa_test(rkey, pt)

        print("RSA Encryption:", re)
        print("RSA Decryption:", rd)

        # ElGamal
        ee, ed = elgamal_test(p, e1, e2, d, pt)

        print("ElGamal Encryption:", ee)
        print("ElGamal Decryption:", ed)

        # ECC
        ce, cd = ecc_test(ekey, pt)

        print("ECC Encryption:", ce)
        print("ECC Decryption:", cd)


# Compare key/storage sizes
def size_comparison():

    print("\n========== KEY SIZE / STORAGE ==========")

    rkey, rt = rsa_keygen()
    p, e1, e2, d, et = elgamal_keygen()
    ekey, ect = ecc_keygen()

    rsa_pub = len(rkey.publickey().export_key())
    rsa_pri = len(rkey.export_key())

    elg_pub = len(str((e1, e2, p)).encode())
    elg_pri = len(str(d).encode())

    ecc_pub = len(ekey.public_key().export_key())
    ecc_pri = len(ekey.export_key())

    print("RSA Public Key Storage:", rsa_pub, "bytes")
    print("RSA Private Key Storage:", rsa_pri, "bytes")

    print("\nElGamal Public Key Storage:", elg_pub, "bytes")
    print("ElGamal Private Key Storage:", elg_pri, "bytes")

    print("\nECC Public Key Storage:", ecc_pub, "bytes")
    print("ECC Private Key Storage:", ecc_pri, "bytes")


# Complete comparison
def complete_comparison():

    key_comparison()
    encryption_comparison()
    size_comparison()


def main():

    while True:

        print("\n========== RSA vs ElGamal vs ECC ==========")
        print("1. Compare key-generation time")
        print("2. Compare encryption/decryption time")
        print("3. Compare key size and storage")
        print("4. Run complete comparison")
        print("5. Exit")

        ch = int(input("Enter your choice: "))

        if ch == 1:
            key_comparison()

        elif ch == 2:
            encryption_comparison()

        elif ch == 3:
            size_comparison()

        elif ch == 4:
            complete_comparison()

        elif ch == 5:
            print("Exiting...")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()