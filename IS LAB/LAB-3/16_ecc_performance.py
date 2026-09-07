"""
16. ecc_performance

Measure ECC key-generation, encryption/decryption or point-operation times
and compare performance for different inputs.
"""

import time
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# Generate ECC key and measure key-generation time
def key_gen():

    t = time.perf_counter()

    key = ECC.generate(curve="P-256")

    et = time.perf_counter() - t

    return key, et


# Measure ECC key-generation performance
def key_performance():

    print("\nECC Key Generation Performance")

    n = [1, 10, 50, 100]

    for x in n:

        t = time.perf_counter()

        for i in range(x):
            ECC.generate(curve="P-256")

        et = time.perf_counter() - t

        print("Keys:", x, "Time:", et, "seconds")


# Measure ECC encryption/decryption using ECDH + AES
def encryption_performance():

    print("\nECC Encryption/Decryption Performance")

    sizes = [16, 64, 128, 256]

    # Generate Alice and Bob keys once
    alice = ECC.generate(curve="P-256")
    bob = ECC.generate(curve="P-256")

    # Calculate shared secret
    s = alice.d * bob.public_key().pointQ

    # Use X-coordinate of shared point
    x = int(s.x)

    # Derive AES key using SHA-256
    key = SHA256.new(x.to_bytes(32, "big")).digest()

    for size in sizes:

        pt = b"A" * size

        # Encryption time
        t = time.perf_counter()

        cipher = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(pt)

        enc_time = time.perf_counter() - t

        # Decryption time
        t = time.perf_counter()

        cipher2 = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
        cipher2.decrypt_and_verify(ct, tag)

        dec_time = time.perf_counter() - t

        print("Plaintext:", size, "bytes")
        print("Encryption:", enc_time, "seconds")
        print("Decryption:", dec_time, "seconds")
        print()


# Measure ECC point multiplication performance
def point_performance():

    print("\nECC Point Operation Performance")

    key = ECC.generate(curve="P-256")

    G = key._curve.G

    ks = [10, 100, 1000, 10000]

    for k in ks:

        t = time.perf_counter()

        R = k * G

        et = time.perf_counter() - t

        print("Scalar:", k, "Time:", et, "seconds")


# Compare different ECC curves
def curve_performance():

    print("\nECC Curve Performance")

    curves = ["P-192", "P-224", "P-256", "P-384", "P-521"]

    for curve in curves:

        t = time.perf_counter()

        key = ECC.generate(curve=curve)

        et = time.perf_counter() - t

        print("Curve:", curve, "Time:", et, "seconds")


def main():

    while True:

        print("\n========== ECC PERFORMANCE ==========")
        print("1. Vary number of key generations")
        print("2. Vary plaintext size")
        print("3. Vary scalar for point multiplication")
        print("4. Vary ECC curve")
        print("5. Exit")

        ch = int(input("Enter your choice: "))

        if ch == 1:
            key_performance()

        elif ch == 2:
            encryption_performance()

        elif ch == 3:
            point_performance()

        elif ch == 4:
            curve_performance()

        elif ch == 5:
            print("Exiting...")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()