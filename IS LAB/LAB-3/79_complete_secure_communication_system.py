"""
Question 79: Complete Secure Communication System

Build a complete system supporting RSA encryption, ElGamal encryption,
ECC-based hybrid encryption and Diffie-Hellman key exchange.

Menu:
1. RSA Communication
2. ElGamal Communication
3. ECC Hybrid Communication
4. DH Secure Communication
5. Exit

Requirements:
- RSA communication
- ElGamal communication
- ECC hybrid communication
- DH key exchange
- User input
- Verification
- Error handling
- Secure symmetric encryption for actual data

Absorbs: original Q122.
"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import (
    getPrime, getRandomRange, inverse
)
import os


# ---------------------------------------------------------
# AES
# ---------------------------------------------------------

def aes_enc(data, key):
    # AES-EAX encrypts data and produces authentication tag
    c = AES.new(key, AES.MODE_EAX)

    ct, tag = c.encrypt_and_digest(data)

    return ct, c.nonce, tag


def aes_dec(ct, nonce, tag, key):
    # Decrypt and verify authentication tag
    c = AES.new(key, AES.MODE_EAX, nonce=nonce)

    pt = c.decrypt(ct)

    try:
        c.verify(tag)
        return pt, True

    except ValueError:
        return None, False


# ---------------------------------------------------------
# RSA
# ---------------------------------------------------------

def rsa_communication(data):
    print("\n--- RSA Secure Communication ---")

    try:
        # User B generates RSA key pair
        print("User B generating RSA keys...")

        pri = RSA.generate(2048)
        pub = pri.publickey()

        # Generate AES session key
        key = os.urandom(32)

        # User A uses User B's public key
        ek = PKCS1_OAEP.new(pub).encrypt(key)

        # Encrypt actual data using AES
        ct, nonce, tag = aes_enc(data, key)

        print("User A: Data encrypted.")
        print("User A: Ciphertext sent to User B.")

        # User B uses private key
        key2 = PKCS1_OAEP.new(pri).decrypt(ek)

        # Decrypt actual data
        pt, ok = aes_dec(
            ct, nonce, tag, key2
        )

        if ok and pt == data:
            print("User B: Data decrypted successfully.")
            print("Recovered:", pt.decode())
            print("Verification: SUCCESS")
        else:
            print("Verification: FAILURE")

    except Exception as e:
        print("RSA communication failed:", e)


# ---------------------------------------------------------
# ElGamal
# ---------------------------------------------------------

def elgamal_keys():
    # Generate ElGamal parameters and keys
    p = getPrime(512)
    g = 2

    x = getRandomRange(2, p - 2)
    y = pow(g, x, p)

    return p, g, x, y


def elgamal_communication(data):
    print("\n--- ElGamal Secure Communication ---")

    try:
        # User B generates ElGamal key pair
        print("User B generating ElGamal keys...")

        p, g, x, y = elgamal_keys()

        # Convert plaintext to integer
        m = int.from_bytes(data, "big")

        if m >= p:
            print(
                "FAILURE: Message is too large for "
                "the ElGamal modulus."
            )
            return

        # User A encrypts using public key
        k = getRandomRange(2, p - 2)

        c1 = pow(g, k, p)
        s = pow(y, k, p)
        c2 = (m * s) % p

        print("User A: Data encrypted.")
        print("User A: Ciphertext sent to User B.")

        # User B decrypts using private key
        s2 = pow(c1, x, p)

        m2 = (
            c2 * inverse(s2, p)
        ) % p

        # Convert integer back to bytes
        if m2 == 0:
            pt = b"\0"
        else:
            pt = m2.to_bytes(
                (m2.bit_length() + 7) // 8,
                "big"
            )

        if pt == data:
            print("User B: Data decrypted successfully.")
            print("Recovered:", pt.decode())
            print("Verification: SUCCESS")
        else:
            print("Verification: FAILURE")

    except Exception as e:
        print("ElGamal communication failed:", e)


# ---------------------------------------------------------
# ECC / ECDH
# ---------------------------------------------------------

def ecc_key(alice, bob):
    # User A calculates shared point
    s1 = alice.d * bob.public_key().pointQ

    # User B calculates shared point
    s2 = bob.d * alice.public_key().pointQ

    if s1 != s2:
        raise ValueError(
            "ECDH shared secret mismatch."
        )

    # Use shared X coordinate as KDF input
    x = int(s1.x).to_bytes(32, "big")

    # SHA-256 derives the AES key
    return SHA256.new(x).digest()


def ecc_communication(data):
    print("\n--- ECC Hybrid Secure Communication ---")

    try:
        # Generate User A and User B ECC keys
        print("Generating ECC keys...")

        alice = ECC.generate(
            curve="secp256r1"
        )

        bob = ECC.generate(
            curve="secp256r1"
        )

        # ECDH derives common AES key
        key = ecc_key(alice, bob)

        # User A encrypts data using AES
        ct, nonce, tag = aes_enc(
            data, key
        )

        print("User A: Shared AES key established.")
        print("User A: Data encrypted.")
        print("User A: Ciphertext sent to User B.")

        # User B derives same AES key
        key2 = ecc_key(alice, bob)

        # User B decrypts
        pt, ok = aes_dec(
            ct, nonce, tag, key2
        )

        if ok and pt == data:
            print("User B: Data decrypted successfully.")
            print("Recovered:", pt.decode())
            print("Verification: SUCCESS")
        else:
            print("Verification: FAILURE")

    except Exception as e:
        print("ECC communication failed:", e)


# ---------------------------------------------------------
# Diffie-Hellman
# ---------------------------------------------------------

def dh_communication(data):
    print("\n--- Diffie-Hellman Secure Communication ---")

    try:
        p = int(input("Enter prime p: "))
        g = int(input("Enter generator g: "))

        a = int(
            input("Enter Alice private key: ")
        )

        b = int(
            input("Enter Bob private key: ")
        )

    except ValueError:
        print("FAILURE: Invalid numeric input.")
        return

    # Validate parameters
    if p <= 2:
        print("FAILURE: p must be greater than 2.")
        return

    if g <= 1 or g >= p:
        print("FAILURE: Invalid generator.")
        return

    if a <= 0 or b <= 0:
        print("FAILURE: Private keys must be positive.")
        return

    try:
        # Public key exchange
        A = pow(g, a, p)
        B = pow(g, b, p)

        print("\nAlice Public Key:", A)
        print("Bob Public Key:", B)

        # Shared secret
        s1 = pow(B, a, p)
        s2 = pow(A, b, p)

        if s1 != s2:
            print(
                "FAILURE: Shared secret mismatch."
            )
            return

        print("Shared Secret:", s1)

        # KDF using SHA-256
        sb = s1.to_bytes(
            (s1.bit_length() + 7) // 8,
            "big"
        )

        if not sb:
            sb = b"\0"

        key = SHA256.new(sb).digest()

        # AES encryption
        ct, nonce, tag = aes_enc(
            data, key
        )

        print("Alice: Data encrypted.")
        print("Ciphertext sent to Bob.")

        # Bob derives same key
        key2 = SHA256.new(sb).digest()

        # AES decryption
        pt, ok = aes_dec(
            ct, nonce, tag, key2
        )

        if ok and pt == data:
            print("Bob: Data decrypted successfully.")
            print("Recovered:", pt.decode())
            print("Verification: SUCCESS")
        else:
            print("Verification: FAILURE")

    except Exception as e:
        print("DH communication failed:", e)


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    print("=" * 55)
    print("       COMPLETE SECURE COMMUNICATION SYSTEM")
    print("=" * 55)

    while True:
        print("\n--- Main Menu ---")
        print("1. RSA Secure Communication")
        print("2. ElGamal Secure Communication")
        print("3. ECC Hybrid Communication")
        print("4. DH Secure Communication")
        print("5. Exit")

        ch = input("Enter choice: ")

        if ch in ["1", "2", "3"]:
            msg = input("Enter message: ")

            if not msg:
                print("FAILURE: Message cannot be empty.")
                continue

            data = msg.encode()

            if ch == "1":
                rsa_communication(data)

            elif ch == "2":
                elgamal_communication(data)

            else:
                ecc_communication(data)

        elif ch == "4":
            msg = input("Enter message: ")

            if not msg:
                print("FAILURE: Message cannot be empty.")
                continue

            dh_communication(
                msg.encode()
            )

        elif ch == "5":
            print("Exiting...")
            break

        else:
            print("FAILURE: Invalid menu choice.")


if __name__ == "__main__":
    main()