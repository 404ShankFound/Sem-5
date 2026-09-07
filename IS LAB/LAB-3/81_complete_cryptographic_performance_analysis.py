"""
Question 81: Complete Cryptographic Performance Analysis

Implement a complete performance-analysis system for multiple asymmetric
algorithms. Test different message/data sizes, repeat cryptographic
operations, calculate average execution times and produce a final
comparison report.

Requirements:
- Multiple asymmetric algorithms
- Multiple message sizes
- Repeated measurements
- Average execution time
- Key generation
- Encryption
- Decryption
- Comparison report
- Fastest algorithm identification
- Use time.perf_counter()
- Avoid including printing inside timed sections

Absorbs: original Q124.
"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, getRandomRange, inverse
import os
import time


def aes_enc(data, key):
    # AES encrypts the actual data
    c = AES.new(key, AES.MODE_EAX)

    ct, tag = c.encrypt_and_digest(data)

    return ct, c.nonce, tag


def aes_dec(ct, nonce, tag, key):
    # AES decrypts and verifies the data
    c = AES.new(key, AES.MODE_EAX, nonce=nonce)

    pt = c.decrypt(ct)
    c.verify(tag)

    return pt


# ---------------------------------------------------------
# RSA TEST
# ---------------------------------------------------------

def rsa_test(data):
    # Key generation
    st = time.perf_counter()

    pri = RSA.generate(2048)
    pub = pri.publickey()

    kg = time.perf_counter() - st

    # Generate AES session key
    key = os.urandom(32)

    # Encryption
    st = time.perf_counter()

    ek = PKCS1_OAEP.new(pub).encrypt(key)
    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # Decryption
    st = time.perf_counter()

    key2 = PKCS1_OAEP.new(pri).decrypt(ek)
    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return kg, et, dt, pt


# ---------------------------------------------------------
# ELGAMAL TEST
# ---------------------------------------------------------

def elgamal_test(data):
    # Key generation
    st = time.perf_counter()

    p = getPrime(512)
    g = 2
    x = getRandomRange(2, p - 2)
    y = pow(g, x, p)

    kg = time.perf_counter() - st

    # Generate AES session key
    key = os.urandom(32)
    m = int.from_bytes(key, "big")

    if m >= p:
        raise ValueError(
            "ElGamal modulus is too small."
        )

    # Encryption
    st = time.perf_counter()

    k = getRandomRange(2, p - 2)

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # Decryption
    st = time.perf_counter()

    s = pow(c1, x, p)

    m2 = (c2 * inverse(s, p)) % p

    key2 = m2.to_bytes(32, "big")

    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return kg, et, dt, pt


# ---------------------------------------------------------
# ECC TEST
# ---------------------------------------------------------

def ecc_test(data):
    # Key generation
    st = time.perf_counter()

    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    kg = time.perf_counter() - st

    # ECDH + AES encryption
    st = time.perf_counter()

    s1 = alice.d * bob.public_key().pointQ

    x1 = int(s1.x).to_bytes(32, "big")
    key = SHA256.new(x1).digest()

    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # ECDH + AES decryption
    st = time.perf_counter()

    s2 = bob.d * alice.public_key().pointQ

    x2 = int(s2.x).to_bytes(32, "big")
    key2 = SHA256.new(x2).digest()

    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return kg, et, dt, pt


# ---------------------------------------------------------
# AVERAGE TEST
# ---------------------------------------------------------

def average_test(fn, data, n):
    # Store total time of all repetitions
    kg = 0
    et = 0
    dt = 0

    pt = None

    for _ in range(n):
        a, b, c, pt = fn(data)

        kg += a
        et += b
        dt += c

    # Calculate average
    kg /= n
    et /= n
    dt /= n

    return kg, et, dt, pt


# ---------------------------------------------------------
# PERFORMANCE ANALYSIS
# ---------------------------------------------------------

def performance():
    # Different message sizes in bytes
    sizes = [
        1024,
        10240,
        102400
    ]

    # Number of repeated measurements
    n = 5

    results = {
        "RSA": [],
        "ElGamal": [],
        "ECC": []
    }

    print("\n--- Performance Analysis ---")
    print("Repeating each test", n, "times.")

    for size in sizes:
        data = b"A" * size

        # Run RSA
        r = average_test(
            rsa_test,
            data,
            n
        )

        # Run ElGamal
        e = average_test(
            elgamal_test,
            data,
            n
        )

        # Run ECC
        c = average_test(
            ecc_test,
            data,
            n
        )

        # Verify all results
        if r[3] != data:
            print("RSA verification failed.")

        if e[3] != data:
            print("ElGamal verification failed.")

        if c[3] != data:
            print("ECC verification failed.")

        results["RSA"].append(r)
        results["ElGamal"].append(e)
        results["ECC"].append(c)

    # Print final table after all timing is completed
    print("\n--- Final Comparison ---")

    print(
        "Size\tAlgorithm\tKeyGen\t\tEncrypt\t\tDecrypt"
    )

    for i, size in enumerate(sizes):

        for alg in ["RSA", "ElGamal", "ECC"]:

            kg, et, dt, pt = results[alg][i]

            print(
                size,
                "\t",
                alg,
                "\t\t",
                f"{kg:.6f}",
                "\t",
                f"{et:.6f}",
                "\t",
                f"{dt:.6f}"
            )

    # Final average across all message sizes
    print("\n--- Overall Average ---")

    total = {}

    for alg in results:

        kg = sum(x[0] for x in results[alg]) / len(sizes)
        et = sum(x[1] for x in results[alg]) / len(sizes)
        dt = sum(x[2] for x in results[alg]) / len(sizes)

        total[alg] = kg + et + dt

        print(
            alg,
            "KeyGen:",
            f"{kg:.6f}",
            "Encrypt:",
            f"{et:.6f}",
            "Decrypt:",
            f"{dt:.6f}",
            "Total:",
            f"{total[alg]:.6f}"
        )

    # Find fastest algorithm
    fast = min(total, key=total.get)

    print("\nFastest Algorithm:", fast)

    # Difference from fastest
    print("\n--- Time Difference ---")

    for alg in total:
        diff = total[alg] - total[fast]

        print(
            alg,
            "difference:",
            f"{diff:.6f}",
            "seconds"
        )


def main():
    print("=" * 60)
    print("       COMPLETE CRYPTOGRAPHIC PERFORMANCE ANALYSIS")
    print("=" * 60)

    while True:
        print("\n--- Menu ---")
        print("1. Run Performance Analysis")
        print("2. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            performance()

        elif ch == "2":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()