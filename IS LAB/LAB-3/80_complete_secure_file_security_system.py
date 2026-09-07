"""
Question 80: Complete Secure File Security System

Build a complete secure file-transfer system where asymmetric cryptography
is used for key exchange/key protection and AES is used for actual file
encryption. Support RSA and ECC approaches and verify the recovered file.

Menu:
1. RSA Secure File Transfer
2. ECC Secure File Transfer
3. Compare RSA and ECC
4. Tamper Test
5. Exit

Requirements:
- File input
- RSA + AES
- ECC/ECDH + AES
- Large-file support
- Session key handling
- Encryption/decryption
- File recovery
- Verification
- Error/tamper handling

Absorbs: original Q123.
"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import os
import time


def aes_enc(data, key):
    # Encrypt file using AES-EAX
    c = AES.new(key, AES.MODE_EAX)

    ct, tag = c.encrypt_and_digest(data)

    return ct, c.nonce, tag


def aes_dec(ct, nonce, tag, key):
    # Decrypt and authenticate file
    c = AES.new(key, AES.MODE_EAX, nonce=nonce)

    pt = c.decrypt(ct)

    try:
        c.verify(tag)
        return pt, True

    except ValueError:
        return None, False


# ---------------------------------------------------------
# RSA FILE TRANSFER
# ---------------------------------------------------------

def rsa_keys():
    # Generate recipient RSA key pair
    pri = RSA.generate(2048)
    pub = pri.publickey()

    return pub, pri


def rsa_transfer(data):
    # Generate recipient keys
    st = time.perf_counter()

    pub, pri = rsa_keys()

    kg = time.perf_counter() - st

    # Generate AES session key
    key = os.urandom(32)

    # Protect AES session key using RSA public key
    st = time.perf_counter()

    ek = PKCS1_OAEP.new(pub).encrypt(key)

    # Encrypt actual file using AES
    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # Recipient decrypts AES session key
    st = time.perf_counter()

    key2 = PKCS1_OAEP.new(pri).decrypt(ek)

    # Decrypt actual file
    pt, ok = aes_dec(
        ct, nonce, tag, key2
    )

    dt = time.perf_counter() - st

    return pt, ok, kg, et, dt, (
        ek, ct, nonce, tag, pri
    )


# ---------------------------------------------------------
# ECC FILE TRANSFER
# ---------------------------------------------------------

def ecc_keys():
    # Generate sender and receiver ECC keys
    alice = ECC.generate(
        curve="secp256r1"
    )

    bob = ECC.generate(
        curve="secp256r1"
    )

    return alice, bob


def ecc_key(alice, bob):
    # Sender calculates shared point
    s1 = alice.d * bob.public_key().pointQ

    # Receiver calculates same shared point
    s2 = bob.d * alice.public_key().pointQ

    if s1 != s2:
        raise ValueError(
            "ECDH shared secret mismatch."
        )

    # SHA-256 derives the AES session key
    x = int(s1.x).to_bytes(32, "big")

    return SHA256.new(x).digest()


def ecc_transfer(data):
    # Generate ECC keys
    st = time.perf_counter()

    alice, bob = ecc_keys()

    kg = time.perf_counter() - st

    # ECDH + AES encryption
    st = time.perf_counter()

    key = ecc_key(alice, bob)

    ct, nonce, tag = aes_enc(
        data, key
    )

    et = time.perf_counter() - st

    # ECDH + AES decryption
    st = time.perf_counter()

    key2 = ecc_key(alice, bob)

    pt, ok = aes_dec(
        ct, nonce, tag, key2
    )

    dt = time.perf_counter() - st

    return pt, ok, kg, et, dt, (
        ct, nonce, tag, alice, bob
    )


# ---------------------------------------------------------
# FILE INPUT / OUTPUT
# ---------------------------------------------------------

def read_file():
    path = input("Enter input file path: ")

    try:
        with open(path, "rb") as f:
            data = f.read()

        print("File read successfully.")
        print("File Size:", len(data), "bytes")

        return data, path

    except FileNotFoundError:
        print("FAILURE: File not found.")

    except PermissionError:
        print("FAILURE: Permission denied.")

    except OSError as e:
        print("FAILURE:", e)

    return None, None


def save_file(data, path):
    # Create recovered filename
    out = path + ".recovered"

    try:
        with open(out, "wb") as f:
            f.write(data)

        print("Recovered file:", out)

    except OSError as e:
        print("FAILURE: Could not write recovered file.")
        print(e)


# ---------------------------------------------------------
# RSA FILE MENU
# ---------------------------------------------------------

def rsa_file():
    print("\n--- RSA Secure File Transfer ---")

    data, path = read_file()

    if data is None:
        return

    try:
        pt, ok, kg, et, dt, enc = rsa_transfer(data)

        print("\n--- RSA Results ---")
        print("Key Generation:", f"{kg:.6f}", "seconds")
        print("Encryption:", f"{et:.6f}", "seconds")
        print("Decryption:", f"{dt:.6f}", "seconds")

        if ok and pt == data:
            print("Verification: SUCCESS")
            save_file(pt, path)
        else:
            print("Verification: FAILURE")

    except Exception as e:
        print("RSA transfer failed:", e)


# ---------------------------------------------------------
# ECC FILE MENU
# ---------------------------------------------------------

def ecc_file():
    print("\n--- ECC Secure File Transfer ---")

    data, path = read_file()

    if data is None:
        return

    try:
        pt, ok, kg, et, dt, enc = ecc_transfer(data)

        print("\n--- ECC Results ---")
        print("Key Generation:", f"{kg:.6f}", "seconds")
        print("Encryption:", f"{et:.6f}", "seconds")
        print("Decryption:", f"{dt:.6f}", "seconds")

        if ok and pt == data:
            print("Verification: SUCCESS")
            save_file(pt, path)
        else:
            print("Verification: FAILURE")

    except Exception as e:
        print("ECC transfer failed:", e)


# ---------------------------------------------------------
# COMPARISON
# ---------------------------------------------------------

def comparison():
    print("\n--- RSA vs ECC File Transfer ---")

    data, path = read_file()

    if data is None:
        return

    try:
        rpt, rok, rkg, re, rd, _ = rsa_transfer(data)

        ept, eok, ekg, ee, ed, _ = ecc_transfer(data)

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
            "ECC\t\t",
            f"{ekg:.6f}",
            "\t",
            f"{ee:.6f}",
            "\t",
            f"{ed:.6f}"
        )

        print("\nVerification:")
        print(
            "RSA:",
            "SUCCESS" if rok and rpt == data
            else "FAILURE"
        )

        print(
            "ECC:",
            "SUCCESS" if eok and ept == data
            else "FAILURE"
        )

        rt = rkg + re + rd
        et = ekg + ee + ed

        print("\nTotal RSA Time:", f"{rt:.6f}")
        print("Total ECC Time:", f"{et:.6f}")

        if rt < et:
            print("Faster Overall: RSA")
        elif et < rt:
            print("Faster Overall: ECC")
        else:
            print("Faster Overall: Equal")

    except Exception as e:
        print("Comparison failed:", e)


# ---------------------------------------------------------
# TAMPER TEST
# ---------------------------------------------------------

def tamper_test():
    print("\n--- Tamper Detection Test ---")

    data = input("Enter message for tamper test: ")

    if not data:
        print("FAILURE: Empty message.")
        return

    data = data.encode()

    try:
        # Generate RSA keys
        pub, pri = rsa_keys()

        # Generate AES session key
        key = os.urandom(32)

        # Encrypt AES key
        ek = PKCS1_OAEP.new(pub).encrypt(key)

        # Encrypt message
        ct, nonce, tag = aes_enc(
            data, key
        )

        # Modify ciphertext
        ct = bytearray(ct)

        if len(ct) > 0:
            ct[0] ^= 1

        ct = bytes(ct)

        # Attempt decryption
        key2 = PKCS1_OAEP.new(pri).decrypt(ek)

        pt, ok = aes_dec(
            ct, nonce, tag, key2
        )

        if ok:
            print(
                "FAILURE: Tampered data was accepted."
            )
        else:
            print(
                "SUCCESS: Tampering detected."
            )

    except Exception:
        print(
            "SUCCESS: Tampered data detected."
        )


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    print("=" * 60)
    print("          COMPLETE SECURE FILE SECURITY SYSTEM")
    print("=" * 60)

    while True:
        print("\n--- Menu ---")
        print("1. RSA Secure File Transfer")
        print("2. ECC Secure File Transfer")
        print("3. RSA vs ECC Comparison")
        print("4. Tamper Test")
        print("5. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            rsa_file()

        elif ch == "2":
            ecc_file()

        elif ch == "3":
            comparison()

        elif ch == "4":
            tamper_test()

        elif ch == "5":
            print("Exiting...")
            break

        else:
            print("FAILURE: Invalid menu choice.")


if __name__ == "__main__":
    main()