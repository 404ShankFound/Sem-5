"""
24. asymmetric_complete_system

Build an interactive system supporting RSA, ElGamal, ECC and Diffie-Hellman
with user input, key generation, encryption/decryption or key exchange,
validation, verification and performance measurement.
"""

import time
import random

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, bytes_to_long, isPrime


# ============================================================
# RSA
# ============================================================

def rsa_system():

    while True:

        print("\n========== RSA ==========")
        print("1. Generate Keys")
        print("2. Encrypt and Decrypt")
        print("3. Display Keys")
        print("4. Performance")
        print("5. Back")

        ch = int(input("Enter choice: "))

        if ch == 1:

            t = time.perf_counter()

            key = RSA.generate(2048)

            et = time.perf_counter() - t

            print("RSA Keys Generated")
            print("Key Generation Time:", et, "seconds")

        elif ch == 2:

            key = RSA.generate(2048)

            pt = input("Enter plaintext: ").encode()

            # RSA-OAEP-SHA256 supports at most 190 bytes for RSA-2048
            if len(pt) > 190:
                print("Plaintext too large for RSA-2048 OAEP.")
                continue

            cipher = PKCS1_OAEP.new(
                key.publickey(),
                hashAlgo=SHA256
            )

            ct = cipher.encrypt(pt)

            print("Ciphertext:", ct.hex())

            cipher = PKCS1_OAEP.new(
                key,
                hashAlgo=SHA256
            )

            dt = cipher.decrypt(ct)

            print("Recovered Plaintext:", dt.decode())
            print("Verified:", dt == pt)

        elif ch == 3:

            key = RSA.generate(2048)

            print("\nRSA Parameters:")
            print("p =", key.p)
            print("q =", key.q)
            print("n =", key.n)
            print("e =", key.e)
            print("d =", key.d)

        elif ch == 4:

            t = time.perf_counter()
            key = RSA.generate(2048)
            kg = time.perf_counter() - t

            pt = b"A" * 100

            cipher = PKCS1_OAEP.new(
                key.publickey(),
                hashAlgo=SHA256
            )

            t = time.perf_counter()
            ct = cipher.encrypt(pt)
            enc = time.perf_counter() - t

            cipher = PKCS1_OAEP.new(
                key,
                hashAlgo=SHA256
            )

            t = time.perf_counter()
            dt = cipher.decrypt(ct)
            dec = time.perf_counter() - t

            print("Key Generation:", kg)
            print("Encryption:", enc)
            print("Decryption:", dec)
            print("Verified:", dt == pt)

        elif ch == 5:
            break

        else:
            print("Invalid choice.")


# ============================================================
# ElGamal
# ============================================================

def elgamal_system():

    while True:

        print("\n========== ELGAMAL ==========")
        print("1. Generate Keys")
        print("2. Encrypt and Decrypt")
        print("3. User Input Parameters")
        print("4. Performance")
        print("5. Back")

        ch = int(input("Enter choice: "))

        if ch == 1:

            t = time.perf_counter()

            p = getPrime(1024)
            g = 2
            d = random.randint(2, p - 2)

            e1 = g
            e2 = pow(e1, d, p)

            et = time.perf_counter() - t

            print("Public Key:", (e1, e2, p))
            print("Private Key:", d)
            print("Key Generation Time:", et)

        elif ch == 2:

            p = getPrime(1024)
            g = 2
            d = random.randint(2, p - 2)

            e1 = g
            e2 = pow(e1, d, p)

            pt = input("Enter plaintext: ").encode()

            m = bytes_to_long(pt)

            if m >= p:
                print("Plaintext too large for ElGamal modulus.")
                continue

            k = random.randint(2, p - 2)

            c1 = pow(e1, k, p)
            c2 = (m * pow(e2, k, p)) % p

            print("Ciphertext:", (c1, c2))

            s = pow(c1, d, p)
            s_inv = inverse(s, p)

            m2 = (c2 * s_inv) % p

            # Convert recovered integer back to bytes
            n = (m2.bit_length() + 7) // 8 or 1
            dt = m2.to_bytes(n, "big")

            print("Recovered Plaintext:", dt.decode())
            print("Verified:", dt == pt)

        elif ch == 3:

            p = int(input("Enter prime p: "))

            if p <= 2 or not isPrime(p):
                print("Invalid prime.")
                continue

            g = int(input("Enter generator g: "))

            if g < 2 or g >= p:
                print("Invalid generator.")
                continue

            d = int(input("Enter private key d: "))

            if d < 1 or d > p - 2:
                print("Invalid private key.")
                continue

            e1 = g
            e2 = pow(e1, d, p)

            print("Public Key:", (e1, e2, p))
            print("Private Key:", d)

        elif ch == 4:

            t = time.perf_counter()

            p = getPrime(1024)
            g = 2
            d = random.randint(2, p - 2)
            e1 = g
            e2 = pow(e1, d, p)

            kg = time.perf_counter() - t

            pt = b"A" * 64
            m = bytes_to_long(pt)
            k = random.randint(2, p - 2)

            t = time.perf_counter()

            c1 = pow(e1, k, p)
            c2 = (m * pow(e2, k, p)) % p

            enc = time.perf_counter() - t

            t = time.perf_counter()

            s = pow(c1, d, p)
            m2 = (c2 * inverse(s, p)) % p

            dec = time.perf_counter() - t

            print("Key Generation:", kg)
            print("Encryption:", enc)
            print("Decryption:", dec)
            print("Verified:", m2 == m)

        elif ch == 5:
            break

        else:
            print("Invalid choice.")


# ============================================================
# ECC
# ============================================================

def ecc_system():

    while True:

        print("\n========== ECC ==========")
        print("1. Generate Keys")
        print("2. ECDH Key Exchange")
        print("3. ECC + AES Encryption")
        print("4. Performance")
        print("5. Back")

        ch = int(input("Enter choice: "))

        if ch == 1:

            t = time.perf_counter()

            key = ECC.generate(curve="P-256")

            et = time.perf_counter() - t

            print("Private Key:", key.d)
            print("Public Key:", key.public_key().pointQ)
            print("Key Generation Time:", et)

        elif ch == 2:

            alice = ECC.generate(curve="P-256")
            bob = ECC.generate(curve="P-256")

            s1 = alice.d * bob.public_key().pointQ
            s2 = bob.d * alice.public_key().pointQ

            print("Alice Public Key:", alice.public_key().pointQ)
            print("Bob Public Key:", bob.public_key().pointQ)

            print("Alice Shared Secret:", s1)
            print("Bob Shared Secret:", s2)

            print("Shared Secret Same:", s1 == s2)

        elif ch == 3:

            alice = ECC.generate(curve="P-256")
            bob = ECC.generate(curve="P-256")

            # ECDH
            s = alice.d * bob.public_key().pointQ

            # SHA-256 derives AES key
            key = SHA256.new(
                int(s.x).to_bytes(32, "big")
            ).digest()

            pt = input("Enter plaintext: ").encode()

            # AES encryption
            cipher = AES.new(key, AES.MODE_EAX)

            ct, tag = cipher.encrypt_and_digest(pt)

            print("Ciphertext:", ct.hex())

            # Bob calculates same shared secret
            s2 = bob.d * alice.public_key().pointQ

            key2 = SHA256.new(
                int(s2.x).to_bytes(32, "big")
            ).digest()

            # AES decryption
            cipher2 = AES.new(
                key2,
                AES.MODE_EAX,
                nonce=cipher.nonce
            )

            dt = cipher2.decrypt_and_verify(ct, tag)

            print("Recovered Plaintext:", dt.decode())
            print("Verified:", dt == pt)

        elif ch == 4:

            t = time.perf_counter()

            alice = ECC.generate(curve="P-256")
            bob = ECC.generate(curve="P-256")

            kg = time.perf_counter() - t

            t = time.perf_counter()

            s1 = alice.d * bob.public_key().pointQ
            s2 = bob.d * alice.public_key().pointQ

            ex = time.perf_counter() - t

            print("Key Generation:", kg)
            print("Key Exchange:", ex)
            print("Verified:", s1 == s2)

        elif ch == 5:
            break

        else:
            print("Invalid choice.")


# ============================================================
# Diffie-Hellman
# ============================================================

def dh_system():

    while True:

        print("\n========== DIFFIE-HELLMAN ==========")
        print("1. Key Exchange")
        print("2. User Input Parameters")
        print("3. Performance")
        print("4. Back")

        ch = int(input("Enter choice: "))

        if ch == 1:

            p = 23
            g = 5

            a = random.randint(2, p - 2)
            b = random.randint(2, p - 2)

            A = pow(g, a, p)
            B = pow(g, b, p)

            s1 = pow(B, a, p)
            s2 = pow(A, b, p)

            print("p =", p)
            print("g =", g)

            print("\nAlice Public Key:", A)
            print("Bob Public Key:", B)

            print("Alice Shared Secret:", s1)
            print("Bob Shared Secret:", s2)

            print("Shared Secret Same:", s1 == s2)

        elif ch == 2:

            p = int(input("Enter prime p: "))
            g = int(input("Enter generator g: "))

            if p <= 2 or not isPrime(p):
                print("Invalid prime.")
                continue

            a = int(input("Enter Alice private key: "))
            b = int(input("Enter Bob private key: "))

            if a <= 0 or b <= 0:
                print("Private keys must be positive.")
                continue

            A = pow(g, a, p)
            B = pow(g, b, p)

            s1 = pow(B, a, p)
            s2 = pow(A, b, p)

            print("\nAlice Public Key:", A)
            print("Bob Public Key:", B)

            print("Alice Shared Secret:", s1)
            print("Bob Shared Secret:", s2)

            print("Shared Secret Same:", s1 == s2)

        elif ch == 3:

            p = getPrime(2048)
            g = 2

            a = random.randint(2, p - 2)
            b = random.randint(2, p - 2)

            t = time.perf_counter()

            A = pow(g, a, p)
            B = pow(g, b, p)

            kg = time.perf_counter() - t

            t = time.perf_counter()

            s1 = pow(B, a, p)
            s2 = pow(A, b, p)

            ex = time.perf_counter() - t

            print("Key Generation:", kg)
            print("Key Exchange:", ex)
            print("Verified:", s1 == s2)

        elif ch == 4:
            break

        else:
            print("Invalid choice.")


# ============================================================
# Main System
# ============================================================

def main():

    while True:

        print("\n========================================")
        print("       ASYMMETRIC CRYPTO SYSTEM")
        print("========================================")
        print("1. RSA")
        print("2. ElGamal")
        print("3. ECC")
        print("4. Diffie-Hellman")
        print("5. Exit")

        ch = int(input("Enter choice: "))

        if ch == 1:
            rsa_system()

        elif ch == 2:
            elgamal_system()

        elif ch == 3:
            ecc_system()

        elif ch == 4:
            dh_system()

        elif ch == 5:
            print("Exiting...")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()