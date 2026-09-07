"""
Question 76: Secure Communication and File Transfer

Build a secure communication/file-transfer system supporting RSA-based,
ECC-based and DH-based secure communication. Use asymmetric cryptography
for key exchange/key protection and AES for actual message/file encryption.

Menu:
1. RSA Secure Message
2. RSA Secure File
3. ECC Secure File
4. DH Secure Communication
5. Multiple Users
6. Different File Sizes
7. RSA vs ECC Transfer
8. Exit

Requirements:
- Recipient public key encryption
- Private-key decryption
- RSA + AES file transfer
- ECC/ECDH + AES file transfer
- DH + AES secure communication
- Multiple users
- Different file sizes
- Verification
- Performance comparison
- Hybrid encryption for large data

Absorbs: original Q109–115.
"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime
import os
import time


def aes_enc(data, key):
    # AES-EAX encrypts data and generates an authentication tag
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


def rsa_keys():
    # Generate recipient RSA key pair
    pri = RSA.generate(2048)
    pub = pri.publickey()

    return pub, pri


def rsa_transfer(data, pub, pri):
    # Generate AES session key
    key = os.urandom(32)

    # Encrypt AES key using recipient's public key
    st = time.perf_counter()

    ek = PKCS1_OAEP.new(pub).encrypt(key)

    # Encrypt actual data using AES
    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # Recipient uses private key to recover AES key
    st = time.perf_counter()

    key2 = PKCS1_OAEP.new(pri).decrypt(ek)

    pt, ok = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return pt, ok, et, dt


def ecc_keys():
    # Generate sender and receiver ECC keys
    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    return alice, bob


def ecc_key(alice, bob):
    # ECDH shared secret
    s1 = alice.d * bob.public_key().pointQ
    s2 = bob.d * alice.public_key().pointQ

    if s1 != s2:
        raise ValueError("ECDH shared secret mismatch.")

    # SHA-256 converts shared value into AES key
    x = int(s1.x).to_bytes(32, "big")

    return SHA256.new(x).digest()


def ecc_transfer(data, alice, bob):
    # Sender and receiver derive the same AES key
    st = time.perf_counter()

    key = ecc_key(alice, bob)

    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # Receiver derives the same key and decrypts
    st = time.perf_counter()

    key2 = ecc_key(alice, bob)

    pt, ok = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return pt, ok, et, dt


def dh_key(p, g, a, b):
    # Generate public values
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Calculate shared secret
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)

    if s1 != s2:
        raise ValueError("DH shared secret mismatch.")

    # Derive AES key using SHA-256
    s = s1.to_bytes((s1.bit_length() + 7) // 8, "big")

    if not s:
        s = b"\0"

    return SHA256.new(s).digest()


def dh_transfer(data, p, g, a, b):
    # Derive shared AES key
    st = time.perf_counter()

    key = dh_key(p, g, a, b)

    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # Derive same key for decryption
    st = time.perf_counter()

    key2 = dh_key(p, g, a, b)

    pt, ok = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return pt, ok, et, dt


def rsa_message():
    print("\n--- RSA Secure Message ---")

    msg = input("Enter message: ")

    if not msg:
        print("Error: Empty message.")
        return

    data = msg.encode()

    pub, pri = rsa_keys()

    try:
        pt, ok, et, dt = rsa_transfer(data, pub, pri)

        print("Encryption Time:", f"{et:.6f}", "seconds")
        print("Decryption Time:", f"{dt:.6f}", "seconds")

        if ok and pt == data:
            print("Recovered:", pt.decode())
            print("Verification: SUCCESS")
        else:
            print("Verification: FAILURE")

    except Exception as e:
        print("Transfer failed:", e)


def rsa_file():
    print("\n--- RSA Secure File Transfer ---")

    path = input("Enter file path: ")

    try:
        with open(path, "rb") as f:
            data = f.read()

    except FileNotFoundError:
        print("Error: File not found.")
        return

    except OSError as e:
        print("Error:", e)
        return

    pub, pri = rsa_keys()

    try:
        pt, ok, et, dt = rsa_transfer(data, pub, pri)

        print("File Size:", len(data), "bytes")
        print("Encryption Time:", f"{et:.6f}", "seconds")
        print("Decryption Time:", f"{dt:.6f}", "seconds")

        if ok and pt == data:
            print("File Verification: SUCCESS")
        else:
            print("File Verification: FAILURE")

    except Exception as e:
        print("Transfer failed:", e)


def ecc_file():
    print("\n--- ECC Secure File Transfer ---")

    path = input("Enter file path: ")

    try:
        with open(path, "rb") as f:
            data = f.read()

    except FileNotFoundError:
        print("Error: File not found.")
        return

    except OSError as e:
        print("Error:", e)
        return

    alice, bob = ecc_keys()

    try:
        pt, ok, et, dt = ecc_transfer(data, alice, bob)

        print("File Size:", len(data), "bytes")
        print("Encryption Time:", f"{et:.6f}", "seconds")
        print("Decryption Time:", f"{dt:.6f}", "seconds")

        if ok and pt == data:
            print("File Verification: SUCCESS")
        else:
            print("File Verification: FAILURE")

    except Exception as e:
        print("Transfer failed:", e)


def dh_communication():
    print("\n--- DH Secure Communication ---")

    try:
        p = int(input("Enter prime p: "))
        g = int(input("Enter generator g: "))
        a = int(input("Enter Alice private key: "))
        b = int(input("Enter Bob private key: "))

    except ValueError:
        print("Error: Invalid numeric input.")
        return

    if p <= 2 or g <= 1 or g >= p:
        print("Error: Invalid p/g.")
        return

    msg = input("Enter message: ")

    if not msg:
        print("Error: Empty message.")
        return

    data = msg.encode()

    try:
        pt, ok, et, dt = dh_transfer(
            data, p, g, a, b
        )

        print("Encryption Time:", f"{et:.6f}", "seconds")
        print("Decryption Time:", f"{dt:.6f}", "seconds")

        if ok and pt == data:
            print("Recovered:", pt.decode())
            print("Verification: SUCCESS")
        else:
            print("Verification: FAILURE")

    except Exception as e:
        print("Communication failed:", e)


def multiple_users():
    print("\n--- Multiple Users ---")

    msg = input("Enter message: ")

    if not msg:
        print("Error: Empty message.")
        return

    data = msg.encode()

    n = int(input("Enter number of users: "))

    if n <= 0:
        print("Error: Invalid number of users.")
        return

    print("\nGenerating user keys...")

    users = []

    for i in range(n):
        pub, pri = rsa_keys()
        users.append((pub, pri))

    print("\n--- User Transfer Results ---")

    for i, (pub, pri) in enumerate(users, 1):

        try:
            pt, ok, et, dt = rsa_transfer(
                data, pub, pri
            )

            print(
                "User", i,
                ":",
                "SUCCESS" if ok and pt == data else "FAILURE",
                "Enc:", f"{et:.6f}",
                "Dec:", f"{dt:.6f}"
            )

        except Exception:
            print("User", i, ": FAILURE")


def different_sizes():
    print("\n--- Different File Sizes ---")

    sizes = [
        1024,
        10240,
        102400,
        1048576
    ]

    pub, pri = rsa_keys()
    alice, bob = ecc_keys()

    print("\nSize\tRSA Enc\tRSA Dec\tECC Enc\tECC Dec")

    for size in sizes:
        data = os.urandom(size)

        try:
            _, rok, re, rd = rsa_transfer(
                data, pub, pri
            )

            _, eok, ee, ed = ecc_transfer(
                data, alice, bob
            )

            print(
                size,
                "\t",
                f"{re:.6f}",
                "\t",
                f"{rd:.6f}",
                "\t",
                f"{ee:.6f}",
                "\t",
                f"{ed:.6f}"
            )

        except Exception as e:
            print("Error:", e)


def rsa_vs_ecc():
    print("\n--- RSA vs ECC File Transfer ---")

    size = int(
        input("Enter file size in MB: ")
    )

    if size <= 0:
        print("Error: Invalid size.")
        return

    data = os.urandom(size * 1024 * 1024)

    print("\nGenerating keys...")

    pub, pri = rsa_keys()
    alice, bob = ecc_keys()

    print("\nTransferring using RSA...")

    st = time.perf_counter()

    rpt, rok, re, rd = rsa_transfer(
        data, pub, pri
    )

    rt = time.perf_counter() - st

    print("Transferring using ECC...")

    st = time.perf_counter()

    ept, eok, ee, ed = ecc_transfer(
        data, alice, bob
    )

    et = time.perf_counter() - st

    print("\n--- Comparison ---")
    print("File Size:", size, "MB")

    print("\nRSA")
    print("Encryption:", f"{re:.6f}", "seconds")
    print("Decryption:", f"{rd:.6f}", "seconds")
    print("Total:", f"{rt:.6f}", "seconds")
    print("Verification:", "SUCCESS" if rok and rpt == data else "FAILURE")

    print("\nECC")
    print("Encryption:", f"{ee:.6f}", "seconds")
    print("Decryption:", f"{ed:.6f}", "seconds")
    print("Total:", f"{et:.6f}", "seconds")
    print("Verification:", "SUCCESS" if eok and ept == data else "FAILURE")

    if rt < et:
        print("\nFaster Transfer: RSA")
    elif et < rt:
        print("\nFaster Transfer: ECC")
    else:
        print("\nFaster Transfer: Equal")


def main():
    print("--- Secure Communication and File Transfer ---")

    while True:
        print("\n--- Menu ---")
        print("1. RSA Secure Message")
        print("2. RSA Secure File")
        print("3. ECC Secure File")
        print("4. DH Secure Communication")
        print("5. Multiple Users")
        print("6. Different File Sizes")
        print("7. RSA vs ECC Transfer")
        print("8. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            rsa_message()

        elif ch == "2":
            rsa_file()

        elif ch == "3":
            ecc_file()

        elif ch == "4":
            dh_communication()

        elif ch == "5":
            multiple_users()

        elif ch == "6":
            different_sizes()

        elif ch == "7":
            rsa_vs_ecc()

        elif ch == "8":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()