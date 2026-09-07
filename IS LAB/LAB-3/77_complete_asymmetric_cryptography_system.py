"""
Question 77: Complete Asymmetric Cryptography System

Create a single interactive cryptographic system supporting RSA, ElGamal,
ECC and Diffie-Hellman. The system should provide key generation,
parameter display, encryption/decryption, key exchange, validation,
verification, performance analysis and secure communication.

Modules:
1. RSA
2. ElGamal
3. ECC
4. Diffie-Hellman
5. Performance
6. Exit

Absorbs: original Q116–120 and serves as the integrated base for Q121–123.
"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import (
    getPrime, getRandomRange, inverse
)
import os
import time


# ---------------------------------------------------------
# AES FUNCTIONS
# ---------------------------------------------------------

def aes_enc(data, key):
    # AES-EAX provides encryption and authentication
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

def rsa_keys():
    print("\nGenerating RSA-2048 keys...")

    st = time.perf_counter()

    pri = RSA.generate(2048)
    pub = pri.publickey()

    t = time.perf_counter() - st

    print("RSA key generation completed.")
    print("Key Generation Time:", f"{t:.6f}", "seconds")

    return pub, pri


def rsa_module():
    # Generate and store RSA keys
    pub, pri = rsa_keys()

    print("\n--- RSA Parameters ---")
    print("Algorithm: RSA")
    print("Key Size: 2048 bits")
    print("Public n:", pub.n)
    print("Public e:", pub.e)

    while True:
        print("\n--- RSA Menu ---")
        print("1. Encrypt / Decrypt Message")
        print("2. Multiple Messages")
        print("3. Display Parameters")
        print("4. Back")

        ch = input("Enter choice: ")

        if ch == "1":
            msg = input("Enter message: ")

            if not msg:
                print("FAILURE: Empty message.")
                continue

            data = msg.encode()

            try:
                # Generate AES session key
                key = os.urandom(32)

                # RSA protects AES key
                st = time.perf_counter()

                ek = PKCS1_OAEP.new(pub).encrypt(key)

                # AES encrypts actual message
                ct, nonce, tag = aes_enc(data, key)

                et = time.perf_counter() - st

                # Decrypt AES key using private key
                st = time.perf_counter()

                key2 = PKCS1_OAEP.new(pri).decrypt(ek)

                pt, ok = aes_dec(
                    ct, nonce, tag, key2
                )

                dt = time.perf_counter() - st

                print("\nCiphertext:", ct.hex())
                print("Encryption Time:", f"{et:.6f}")
                print("Decryption Time:", f"{dt:.6f}")

                if ok and pt == data:
                    print("Recovered:", pt.decode())
                    print("Verification: SUCCESS")
                else:
                    print("Verification: FAILURE")

            except Exception as e:
                print("FAILURE:", e)

        elif ch == "2":
            msgs = input(
                "Enter messages separated by |: "
            ).split("|")

            for i, msg in enumerate(msgs, 1):

                if not msg:
                    print("Message", i, ": FAILURE")
                    continue

                try:
                    data = msg.encode()
                    key = os.urandom(32)

                    ek = PKCS1_OAEP.new(pub).encrypt(key)

                    ct, nonce, tag = aes_enc(
                        data, key
                    )

                    key2 = PKCS1_OAEP.new(pri).decrypt(ek)

                    pt, ok = aes_dec(
                        ct, nonce, tag, key2
                    )

                    print(
                        "Message", i, ":",
                        "SUCCESS" if ok and pt == data
                        else "FAILURE"
                    )

                except Exception:
                    print("Message", i, ": FAILURE")

        elif ch == "3":
            print("\n--- RSA Parameters ---")
            print("n:", pub.n)
            print("e:", pub.e)
            print("Private d:", pri.d)

        elif ch == "4":
            break

        else:
            print("Error: Invalid choice.")


# ---------------------------------------------------------
# ELGAMAL
# ---------------------------------------------------------

def elgamal_keys():
    print("\nGenerating ElGamal keys...")

    st = time.perf_counter()

    p = getPrime(512)
    g = 2
    x = getRandomRange(2, p - 2)
    y = pow(g, x, p)

    t = time.perf_counter() - st

    print("ElGamal key generation completed.")
    print("Key Generation Time:", f"{t:.6f}", "seconds")

    return p, g, x, y


def elgamal_encrypt(m, p, g, y):
    # Random k makes ElGamal encryption probabilistic
    k = getRandomRange(2, p - 2)

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    return c1, c2


def elgamal_decrypt(c1, c2, p, x):
    # Calculate shared value
    s = pow(c1, x, p)

    # Find modular inverse
    s_inv = inverse(s, p)

    # Recover plaintext integer
    m = (c2 * s_inv) % p

    return m


def elgamal_module():
    p, g, x, y = elgamal_keys()

    print("\n--- ElGamal Parameters ---")
    print("p:", p)
    print("g:", g)
    print("Public y:", y)
    print("Private x:", x)

    while True:
        print("\n--- ElGamal Menu ---")
        print("1. Encrypt / Decrypt Message")
        print("2. Multiple Messages")
        print("3. Display Parameters")
        print("4. Back")

        ch = input("Enter choice: ")

        if ch == "1":
            msg = input("Enter message: ")

            if not msg:
                print("FAILURE: Empty message.")
                continue

            data = msg.encode()
            m = int.from_bytes(data, "big")

            # Textbook ElGamal requires m < p
            if m >= p:
                print(
                    "FAILURE: Message is too large for "
                    "the ElGamal modulus."
                )
                continue

            try:
                st = time.perf_counter()

                c1, c2 = elgamal_encrypt(
                    m, p, g, y
                )

                et = time.perf_counter() - st

                st = time.perf_counter()

                m2 = elgamal_decrypt(
                    c1, c2, p, x
                )

                dt = time.perf_counter() - st

                pt = m2.to_bytes(
                    (m2.bit_length() + 7) // 8,
                    "big"
                )

                print("\nc1:", c1)
                print("c2:", c2)
                print("Encryption Time:", f"{et:.6f}")
                print("Decryption Time:", f"{dt:.6f}")

                if pt == data:
                    print("Recovered:", pt.decode())
                    print("Verification: SUCCESS")
                else:
                    print("Verification: FAILURE")

            except Exception as e:
                print("FAILURE:", e)

        elif ch == "2":
            msgs = input(
                "Enter messages separated by |: "
            ).split("|")

            for i, msg in enumerate(msgs, 1):

                if not msg:
                    print("Message", i, ": FAILURE")
                    continue

                data = msg.encode()
                m = int.from_bytes(data, "big")

                if m >= p:
                    print(
                        "Message", i,
                        ": FAILURE - Message too large"
                    )
                    continue

                try:
                    c1, c2 = elgamal_encrypt(
                        m, p, g, y
                    )

                    m2 = elgamal_decrypt(
                        c1, c2, p, x
                    )

                    pt = m2.to_bytes(
                        (m2.bit_length() + 7) // 8,
                        "big"
                    )

                    print(
                        "Message", i, ":",
                        "SUCCESS" if pt == data
                        else "FAILURE"
                    )

                except Exception:
                    print("Message", i, ": FAILURE")

        elif ch == "3":
            print("\n--- ElGamal Parameters ---")
            print("p:", p)
            print("g:", g)
            print("Public y:", y)
            print("Private x:", x)

        elif ch == "4":
            break

        else:
            print("Error: Invalid choice.")


# ---------------------------------------------------------
# ECC
# ---------------------------------------------------------

def ecc_keys():
    print("\nGenerating ECC P-256 keys...")

    st = time.perf_counter()

    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    t = time.perf_counter() - st

    print("ECC key generation completed.")
    print("Key Generation Time:", f"{t:.6f}", "seconds")

    return alice, bob


def ecc_key(alice, bob):
    # ECDH shared point
    s1 = alice.d * bob.public_key().pointQ
    s2 = bob.d * alice.public_key().pointQ

    if s1 != s2:
        raise ValueError("ECDH shared secret mismatch.")

    # Use X coordinate as input to SHA-256 KDF
    x = int(s1.x).to_bytes(32, "big")

    key = SHA256.new(x).digest()

    return key


def ecc_module():
    alice, bob = ecc_keys()

    print("\n--- ECC Parameters ---")
    print("Curve: secp256r1")
    print("Alice Public X:", alice.public_key().pointQ.x)
    print("Alice Public Y:", alice.public_key().pointQ.y)
    print("Bob Public X:", bob.public_key().pointQ.x)
    print("Bob Public Y:", bob.public_key().pointQ.y)

    while True:
        print("\n--- ECC Menu ---")
        print("1. ECDH")
        print("2. AES Hybrid Encryption")
        print("3. Multiple Messages")
        print("4. Display Parameters")
        print("5. Back")

        ch = input("Enter choice: ")

        if ch == "1":
            try:
                s1 = alice.d * bob.public_key().pointQ
                s2 = bob.d * alice.public_key().pointQ

                print("\nAlice Shared Point:")
                print("X:", s1.x)
                print("Y:", s1.y)

                print("\nBob Shared Point:")
                print("X:", s2.x)
                print("Y:", s2.y)

                print(
                    "\nECDH Verification:",
                    "SUCCESS" if s1 == s2 else "FAILURE"
                )

            except Exception as e:
                print("FAILURE:", e)

        elif ch == "2":
            msg = input("Enter message: ")

            if not msg:
                print("FAILURE: Empty message.")
                continue

            data = msg.encode()

            try:
                st = time.perf_counter()

                key = ecc_key(alice, bob)

                ct, nonce, tag = aes_enc(
                    data, key
                )

                et = time.perf_counter() - st

                st = time.perf_counter()

                key2 = ecc_key(alice, bob)

                pt, ok = aes_dec(
                    ct, nonce, tag, key2
                )

                dt = time.perf_counter() - st

                print("\nAES Key:", key.hex())
                print("Ciphertext:", ct.hex())
                print("Encryption Time:", f"{et:.6f}")
                print("Decryption Time:", f"{dt:.6f}")

                if ok and pt == data:
                    print("Recovered:", pt.decode())
                    print("Verification: SUCCESS")
                else:
                    print("Verification: FAILURE")

            except Exception as e:
                print("FAILURE:", e)

        elif ch == "3":
            msgs = input(
                "Enter messages separated by |: "
            ).split("|")

            try:
                key = ecc_key(alice, bob)

                for i, msg in enumerate(msgs, 1):

                    if not msg:
                        print(
                            "Message", i,
                            ": FAILURE"
                        )
                        continue

                    data = msg.encode()

                    ct, nonce, tag = aes_enc(
                        data, key
                    )

                    pt, ok = aes_dec(
                        ct, nonce, tag, key
                    )

                    print(
                        "Message", i, ":",
                        "SUCCESS" if ok and pt == data
                        else "FAILURE"
                    )

            except Exception as e:
                print("FAILURE:", e)

        elif ch == "4":
            print("\n--- ECC Parameters ---")
            print("Curve: secp256r1")
            print("Alice Private:", alice.d)
            print(
                "Alice Public X:",
                alice.public_key().pointQ.x
            )
            print(
                "Alice Public Y:",
                alice.public_key().pointQ.y
            )
            print("Bob Private:", bob.d)
            print(
                "Bob Public X:",
                bob.public_key().pointQ.x
            )
            print(
                "Bob Public Y:",
                bob.public_key().pointQ.y
            )

        elif ch == "5":
            break

        else:
            print("Error: Invalid choice.")


# ---------------------------------------------------------
# DIFFIE-HELLMAN
# ---------------------------------------------------------

def dh_module():
    print("\n--- Diffie-Hellman Parameters ---")

    try:
        p = int(input("Enter prime p: "))
        g = int(input("Enter generator g: "))

    except ValueError:
        print("FAILURE: Invalid numeric input.")
        return

    if p <= 2:
        print("FAILURE: p must be greater than 2.")
        return

    if g <= 1 or g >= p:
        print("FAILURE: Invalid generator.")
        return

    try:
        a = int(input("Enter Alice private key: "))
        b = int(input("Enter Bob private key: "))

    except ValueError:
        print("FAILURE: Invalid private key.")
        return

    if a <= 0 or b <= 0:
        print("FAILURE: Private keys must be positive.")
        return

    while True:
        print("\n--- DH Menu ---")
        print("1. Generate Public Keys")
        print("2. Calculate Shared Secret")
        print("3. Secure Communication")
        print("4. Display Parameters")
        print("5. Back")

        ch = input("Enter choice: ")

        if ch == "1":
            A = pow(g, a, p)
            B = pow(g, b, p)

            print("\nAlice Public Key:", A)
            print("Bob Public Key:", B)

        elif ch == "2":
            A = pow(g, a, p)
            B = pow(g, b, p)

            s1 = pow(B, a, p)
            s2 = pow(A, b, p)

            print("\nAlice Shared Secret:", s1)
            print("Bob Shared Secret:", s2)

            if s1 == s2:
                print("DH Verification: SUCCESS")
            else:
                print("DH Verification: FAILURE")

        elif ch == "3":
            msg = input("Enter message: ")

            if not msg:
                print("FAILURE: Empty message.")
                continue

            try:
                # DH public keys
                A = pow(g, a, p)
                B = pow(g, b, p)

                # Shared secret
                s1 = pow(B, a, p)
                s2 = pow(A, b, p)

                if s1 != s2:
                    print(
                        "FAILURE: Shared secret mismatch."
                    )
                    continue

                # KDF
                sb = s1.to_bytes(
                    (s1.bit_length() + 7) // 8,
                    "big"
                )

                if not sb:
                    sb = b"\0"

                key = SHA256.new(sb).digest()

                # Encrypt
                ct, nonce, tag = aes_enc(
                    msg.encode(), key
                )

                # Decrypt
                pt, ok = aes_dec(
                    ct, nonce, tag, key
                )

                print("\nCiphertext:", ct.hex())

                if ok and pt == msg.encode():
                    print("Recovered:", pt.decode())
                    print("Verification: SUCCESS")
                else:
                    print("Verification: FAILURE")

            except Exception as e:
                print("FAILURE:", e)

        elif ch == "4":
            print("\n--- DH Parameters ---")
            print("p:", p)
            print("g:", g)
            print("Alice Private:", a)
            print("Bob Private:", b)
            print("Alice Public:", pow(g, a, p))
            print("Bob Public:", pow(g, b, p))

        elif ch == "5":
            break

        else:
            print("Error: Invalid choice.")


# ---------------------------------------------------------
# PERFORMANCE
# ---------------------------------------------------------

def performance():
    print("\n--- Performance Comparison ---")

    msg = input("Enter message: ")

    if not msg:
        print("Error: Empty message.")
        return

    data = msg.encode()

    # RSA
    st = time.perf_counter()
    rp = RSA.generate(2048)
    rpub = rp.publickey()
    rkg = time.perf_counter() - st

    key = os.urandom(32)

    st = time.perf_counter()
    ek = PKCS1_OAEP.new(rpub).encrypt(key)
    ct, nonce, tag = aes_enc(data, key)
    re = time.perf_counter() - st

    st = time.perf_counter()
    key2 = PKCS1_OAEP.new(rp).decrypt(ek)
    rpt, rok = aes_dec(ct, nonce, tag, key2)
    rd = time.perf_counter() - st

    # ElGamal
    st = time.perf_counter()

    p = getPrime(512)
    g = 2
    x = getRandomRange(2, p - 2)
    y = pow(g, x, p)

    elgkg = time.perf_counter() - st

    # Protect a small AES key with ElGamal
    key = os.urandom(32)
    m = int.from_bytes(key, "big")

    st = time.perf_counter()

    if m >= p:
        print("ElGamal modulus too small.")
        return

    c1, c2 = elgamal_encrypt(
        m, p, g, y
    )

    ct, nonce, tag = aes_enc(data, key)

    ele = time.perf_counter() - st

    st = time.perf_counter()

    m2 = elgamal_decrypt(
        c1, c2, p, x
    )

    key2 = m2.to_bytes(32, "big")

    elgpt, elgok = aes_dec(
        ct, nonce, tag, key2
    )

    elgd = time.perf_counter() - st

    # ECC
    st = time.perf_counter()

    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    ecckg = time.perf_counter() - st

    st = time.perf_counter()

    key = ecc_key(alice, bob)

    ct, nonce, tag = aes_enc(data, key)

    ecce = time.perf_counter() - st

    st = time.perf_counter()

    key2 = ecc_key(alice, bob)

    eccpt, eccok = aes_dec(
        ct, nonce, tag, key2
    )

    eccd = time.perf_counter() - st

    print("\nAlgorithm\tKeyGen\t\tEncrypt\t\tDecrypt")

    print(
        "RSA\t\t",
        f"{rkg:.6f}",
        "\t",
        f"{re:.6f}",
        "\t",
        f"{rd:.6f}"
    )

    print(
        "ElGamal\t\t",
        f"{elgkg:.6f}",
        "\t",
        f"{ele:.6f}",
        "\t",
        f"{elgd:.6f}"
    )

    print(
        "ECC\t\t",
        f"{ecckg:.6f}",
        "\t",
        f"{ecce:.6f}",
        "\t",
        f"{eccd:.6f}"
    )

    print("\nVerification:")
    print(
        "RSA:",
        "SUCCESS" if rok and rpt == data
        else "FAILURE"
    )

    print(
        "ElGamal:",
        "SUCCESS" if elgok and elgpt == data
        else "FAILURE"
    )

    print(
        "ECC:",
        "SUCCESS" if eccok and eccpt == data
        else "FAILURE"
    )


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    print("=" * 55)
    print("       COMPLETE ASYMMETRIC CRYPTOGRAPHY SYSTEM")
    print("=" * 55)

    while True:
        print("\n--- Main Menu ---")
        print("1. RSA")
        print("2. ElGamal")
        print("3. ECC")
        print("4. Diffie-Hellman")
        print("5. Performance Analysis")
        print("6. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            rsa_module()

        elif ch == "2":
            elgamal_module()

        elif ch == "3":
            ecc_module()

        elif ch == "4":
            dh_module()

        elif ch == "5":
            performance()

        elif ch == "6":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()