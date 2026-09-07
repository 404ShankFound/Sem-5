"""
Question 73: Multiple Message, File, Binary and Large-Data Hybrid Encryption

Create a hybrid asymmetric encryption system capable of handling multiple messages, different message sizes, repeated encryption of the same message, text-file input, binary data and large data.

Asymmetric cryptography should be used for key exchange/key protection, while AES should encrypt the actual data.

Menu:
1. Multiple Messages
2. Different Message Sizes
3. Same Message Multiple Times
4. Text File
5. Binary Data
6. Large Data
7. Exit

Requirements:
- Same key for multiple messages
- Different message sizes
- Same message encrypted multiple times
- Text file support
- Binary data support
- Large data support
- RSA/ECC + AES hybrid approach
- Decryption
- Verification
- Authentication/tampering detection where supported

Absorbs: original Q91–96.
"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import os


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


def rsa_key():
    # RSA is used only for protecting the AES key
    pri = RSA.generate(2048)
    pub = pri.publickey()

    return pub, pri


def rsa_encrypt(data, pub):
    # Generate a fresh AES session key
    key = os.urandom(32)

    # Protect AES key using RSA-OAEP
    ek = PKCS1_OAEP.new(pub).encrypt(key)

    # Encrypt actual data using AES
    ct, nonce, tag = aes_enc(data, key)

    return ek, ct, nonce, tag


def rsa_decrypt(ek, ct, nonce, tag, pri):
    # Recover AES key using RSA
    key = PKCS1_OAEP.new(pri).decrypt(ek)

    # Decrypt actual data using AES
    return aes_dec(ct, nonce, tag, key)


def ecc_key():
    # ECC keys for ECDH
    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    return alice, bob


def ecc_key_from_shared(alice, bob):
    # ECDH shared secret
    s1 = alice.d * bob.public_key().pointQ
    s2 = bob.d * alice.public_key().pointQ

    if s1 != s2:
        raise ValueError("ECDH shared secret mismatch.")

    # Convert shared point to AES key
    x = int(s1.x).to_bytes(32, "big")
    key = SHA256.new(x).digest()

    return key


def ecc_encrypt(data, alice, bob):
    # Derive AES key using ECDH
    key = ecc_key_from_shared(alice, bob)

    # Encrypt data using AES
    ct, nonce, tag = aes_enc(data, key)

    return ct, nonce, tag


def ecc_decrypt(ct, nonce, tag, alice, bob):
    # Derive the same AES key
    key = ecc_key_from_shared(alice, bob)

    # Decrypt and authenticate
    return aes_dec(ct, nonce, tag, key)


def choose_algorithm():
    print("\n--- Select Algorithm ---")
    print("1. RSA + AES")
    print("2. ECC + AES")

    while True:
        ch = input("Enter choice: ")

        if ch == "1":
            return "RSA"

        elif ch == "2":
            return "ECC"

        else:
            print("Error: Invalid choice.")


def encrypt_data(data, alg, keys):
    # Use selected hybrid encryption method
    if alg == "RSA":
        pub, pri = keys

        ek, ct, nonce, tag = rsa_encrypt(data, pub)

        return (ek, ct, nonce, tag), keys

    else:
        alice, bob = keys

        ct, nonce, tag = ecc_encrypt(data, alice, bob)

        return (ct, nonce, tag), keys


def decrypt_data(enc, alg, keys):
    # Decrypt using the selected method
    if alg == "RSA":
        ek, ct, nonce, tag = enc

        pub, pri = keys

        return rsa_decrypt(
            ek, ct, nonce, tag, pri
        )

    else:
        ct, nonce, tag = enc

        alice, bob = keys

        return ecc_decrypt(
            ct, nonce, tag, alice, bob
        )


def verify(data, dec):
    # Compare decrypted data with original data
    if dec is not None and data == dec:
        print("Verification: SUCCESS")
        return True

    print("Verification: FAILURE")
    return False


def multiple_messages():
    alg = choose_algorithm()

    # Generate one key pair/session setup
    if alg == "RSA":
        keys = rsa_key()
    else:
        keys = ecc_key()

    print("\nEnter messages separated by |")
    inp = input("Messages: ")

    msgs = inp.split("|")

    print("\n--- Multiple Message Test ---")

    for i, msg in enumerate(msgs, 1):
        data = msg.encode()

        enc, keys = encrypt_data(data, alg, keys)

        dec, ok = decrypt_data(enc, alg, keys)

        print("\nMessage", i)
        print("Original:", msg)

        if ok:
            print("Recovered:", dec.decode())
            verify(data, dec)
        else:
            print("Authentication FAILED")


def message_sizes():
    alg = choose_algorithm()

    # One key setup is reused for different data sizes
    if alg == "RSA":
        keys = rsa_key()
    else:
        keys = ecc_key()

    sizes = [16, 64, 256, 1024, 4096]

    print("\n--- Different Message Sizes ---")

    for size in sizes:
        data = b"A" * size

        enc, keys = encrypt_data(data, alg, keys)

        dec, ok = decrypt_data(enc, alg, keys)

        print(
            "Size:", size,
            "bytes",
            "Verification:",
            "SUCCESS" if ok and data == dec else "FAILURE"
        )


def same_message():
    alg = choose_algorithm()

    if alg == "RSA":
        keys = rsa_key()
    else:
        keys = ecc_key()

    msg = input("\nEnter message: ").encode()

    n = int(input("Enter number of repetitions: "))

    print("\n--- Same Message Multiple Times ---")

    cts = []

    for i in range(n):
        enc, keys = encrypt_data(msg, alg, keys)

        dec, ok = decrypt_data(enc, alg, keys)

        if ok and msg == dec:
            print("Encryption", i + 1, ": SUCCESS")
        else:
            print("Encryption", i + 1, ": FAILURE")

        # Store ciphertext to show that fresh encryption differs
        if alg == "RSA":
            cts.append(enc[1])
        else:
            cts.append(enc[0])

    if len(cts) > 1:
        different = len(set(cts)) > 1

        print(
            "Different ciphertexts:",
            "YES" if different else "NO"
        )


def text_file():
    alg = choose_algorithm()

    path = input("\nEnter text file path: ")

    try:
        with open(path, "rb") as f:
            data = f.read()

    except FileNotFoundError:
        print("Error: File not found.")
        return

    except OSError as e:
        print("Error reading file:", e)
        return

    if alg == "RSA":
        keys = rsa_key()
    else:
        keys = ecc_key()

    enc, keys = encrypt_data(data, alg, keys)

    dec, ok = decrypt_data(enc, alg, keys)

    print("\n--- Text File Test ---")
    print("File Size:", len(data), "bytes")

    if ok and data == dec:
        print("Decryption: SUCCESS")
        print("Verification: SUCCESS")
    else:
        print("Decryption: FAILURE")


def binary_data():
    alg = choose_algorithm()

    size = int(input("\nEnter binary data size in bytes: "))

    if size < 0:
        print("Error: Invalid size.")
        return

    # Generate arbitrary binary data
    data = os.urandom(size)

    if alg == "RSA":
        keys = rsa_key()
    else:
        keys = ecc_key()

    enc, keys = encrypt_data(data, alg, keys)

    dec, ok = decrypt_data(enc, alg, keys)

    print("\n--- Binary Data Test ---")
    print("Data Size:", size, "bytes")

    if ok and data == dec:
        print("Binary Decryption: SUCCESS")
        print("Verification: SUCCESS")
    else:
        print("Binary Decryption: FAILURE")


def large_data():
    alg = choose_algorithm()

    size = int(input("\nEnter large data size in MB: "))

    if size <= 0:
        print("Error: Invalid size.")
        return

    # Generate large binary data
    data = os.urandom(size * 1024 * 1024)

    print("\nEncrypting", size, "MB data...")

    if alg == "RSA":
        keys = rsa_key()
    else:
        keys = ecc_key()

    enc, keys = encrypt_data(data, alg, keys)

    print("Encryption completed.")

    dec, ok = decrypt_data(enc, alg, keys)

    print("Decryption completed.")

    if ok and data == dec:
        print("Large Data Verification: SUCCESS")
    else:
        print("Large Data Verification: FAILURE")


def main():
    print("--- Multiple Message, File and Large-Data Hybrid Encryption ---")

    while True:
        print("\n--- Menu ---")
        print("1. Multiple Messages")
        print("2. Different Message Sizes")
        print("3. Same Message Multiple Times")
        print("4. Text File")
        print("5. Binary Data")
        print("6. Large Data")
        print("7. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            multiple_messages()

        elif ch == "2":
            message_sizes()

        elif ch == "3":
            same_message()

        elif ch == "4":
            text_file()

        elif ch == "5":
            binary_data()

        elif ch == "6":
            large_data()

        elif ch == "7":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()