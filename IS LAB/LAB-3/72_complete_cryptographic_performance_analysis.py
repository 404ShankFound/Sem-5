"""
Question 72: Complete Cryptographic Performance Analysis

Create an interactive performance-analysis system that compares RSA, ElGamal and ECC based on key generation, encryption and decryption time. Support key-size comparisons, repeated measurements, average execution time, time overhead and identification of the fastest algorithm.

Flow:
                 Performance System
                        ↓
          ┌─────────────┴─────────────┐
          ↓                           ↓
     Algorithm Test              Key Size Test
          ↓                           ↓
 Message Size Test              Key Generation
          ↓
   Repeat Measurements
          ↓
   Average Execution Time
          ↓
 ┌────────┬────────┬────────┐
 │ RSA    │ ElGamal│ ECC    │
 └────────┴────────┴────────┘
          ↓
 Comparison / Difference
          ↓
 Fastest Algorithm

Requirements:
- RSA/ElGamal/ECC
- Key-generation timing
- Encryption timing
- Decryption timing
- Different message sizes
- Different key sizes
- Repeated tests
- Average timing
- Time overhead/difference
- Fastest algorithm
- Final comparison table

Absorbs: original Q86–90.

"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.number import getPrime, getRandomRange, inverse
from Crypto.Hash import SHA256
import time


def aes_enc(data, key):
    # AES-EAX encryption
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(data)

    return ct, c.nonce, tag


def aes_dec(ct, nonce, tag, key):
    # AES-EAX decryption and verification
    c = AES.new(key, AES.MODE_EAX, nonce=nonce)
    pt = c.decrypt(ct)
    c.verify(tag)

    return pt


def rsa_test(data, pub, pri):
    # Generate AES session key
    key = AES.get_random_bytes(32)

    # Encryption
    st = time.perf_counter()

    ek = PKCS1_OAEP.new(pub).encrypt(key)
    ct, nonce, tag = aes_enc(data, key)

    enc_t = time.perf_counter() - st

    # Decryption
    st = time.perf_counter()

    key2 = PKCS1_OAEP.new(pri).decrypt(ek)
    pt = aes_dec(ct, nonce, tag, key2)

    dec_t = time.perf_counter() - st

    return enc_t, dec_t, pt


def elgamal_test(data, p, g, x):
    # Generate ElGamal public key
    y = pow(g, x, p)

    # Generate AES session key
    key = AES.get_random_bytes(32)
    m = int.from_bytes(key, "big")

    # Encryption
    st = time.perf_counter()

    k = getRandomRange(2, p - 2)
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    ct, nonce, tag = aes_enc(data, key)

    enc_t = time.perf_counter() - st

    # Decryption
    st = time.perf_counter()

    s = pow(c1, x, p)
    key2 = (c2 * inverse(s, p)) % p
    key2 = key2.to_bytes(32, "big")

    pt = aes_dec(ct, nonce, tag, key2)

    dec_t = time.perf_counter() - st

    return enc_t, dec_t, pt


def ecc_test(data, alice, bob):
    # Encryption
    st = time.perf_counter()

    s = alice.d * bob.public_key().pointQ
    key = SHA256.new(
        int(s.x).to_bytes(32, "big")
    ).digest()

    ct, nonce, tag = aes_enc(data, key)

    enc_t = time.perf_counter() - st

    # Decryption
    st = time.perf_counter()

    s2 = bob.d * alice.public_key().pointQ
    key2 = SHA256.new(
        int(s2.x).to_bytes(32, "big")
    ).digest()

    pt = aes_dec(ct, nonce, tag, key2)

    dec_t = time.perf_counter() - st

    return enc_t, dec_t, pt


def average_test(fn, n):
    # Run the test multiple times and calculate averages
    et = 0
    dt = 0

    for _ in range(n):
        e, d, pt = fn()
        et += e
        dt += d

    return et / n, dt / n, pt


def algorithm_test():
    # Message sizes
    sizes = [1024, 10240, 102400]

    # Number of repeated tests
    n = 5

    print("\nGenerating keys...")

    # RSA
    rsa_pri = RSA.generate(2048)
    rsa_pub = rsa_pri.publickey()

    # ElGamal
    p = getPrime(512)
    g = 2
    x = getRandomRange(2, p - 2)

    # ECC
    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    print("\n--- Algorithm Performance ---")
    print("Size\tRSA Enc\tRSA Dec\tElGamal Enc\tElGamal Dec\tECC Enc\tECC Dec")

    for size in sizes:
        data = b"A" * size

        re, rd, rpt = average_test(
            lambda: rsa_test(data, rsa_pub, rsa_pri), n
        )

        ee, ed, ept = average_test(
            lambda: elgamal_test(data, p, g, x), n
        )

        ce, cd, cpt = average_test(
            lambda: ecc_test(data, alice, bob), n
        )

        if data != rpt or data != ept or data != cpt:
            print("Verification: FAILURE")
            continue

        print(
            size,
            "\t",
            f"{re:.6f}",
            "\t",
            f"{rd:.6f}",
            "\t",
            f"{ee:.6f}",
            "\t\t",
            f"{ed:.6f}",
            "\t\t",
            f"{ce:.6f}",
            "\t",
            f"{cd:.6f}"
        )


def key_size_test():
    # RSA and ECC key sizes
    rsa_sizes = [1024, 2048, 3072]
    ecc_curves = ["P-192", "P-224", "P-256", "P-384", "P-521"]

    print("\n--- RSA Key Generation ---")
    print("Size\tTime")

    for size in rsa_sizes:
        st = time.perf_counter()

        RSA.generate(size)

        t = time.perf_counter() - st

        print(size, "\t", f"{t:.6f}", "seconds")

    print("\n--- ECC Key Generation ---")
    print("Curve\tTime")

    for curve in ecc_curves:
        st = time.perf_counter()

        ECC.generate(curve=curve)

        t = time.perf_counter() - st

        print(curve, "\t", f"{t:.6f}", "seconds")


def comparison_test():
    # Run a common message-size test
    data = b"A" * 1024
    n = 5

    # Generate keys once
    rsa_pri = RSA.generate(2048)
    rsa_pub = rsa_pri.publickey()

    p = getPrime(512)
    g = 2
    x = getRandomRange(2, p - 2)

    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    # Calculate average times
    rt = average_test(
        lambda: rsa_test(data, rsa_pub, rsa_pri), n
    )

    et = average_test(
        lambda: elgamal_test(data, p, g, x), n
    )

    ct = average_test(
        lambda: ecc_test(data, alice, bob), n
    )

    vals = {
        "RSA": rt[0] + rt[1],
        "ElGamal": et[0] + et[1],
        "ECC": ct[0] + ct[1]
    }

    print("\n--- Complete Comparison ---")
    print("Algorithm\tEnc\t\tDec\t\tTotal")

    print(
        "RSA\t\t",
        f"{rt[0]:.6f}",
        "\t",
        f"{rt[1]:.6f}",
        "\t",
        f"{vals['RSA']:.6f}"
    )

    print(
        "ElGamal\t\t",
        f"{et[0]:.6f}",
        "\t",
        f"{et[1]:.6f}",
        "\t",
        f"{vals['ElGamal']:.6f}"
    )

    print(
        "ECC\t\t",
        f"{ct[0]:.6f}",
        "\t",
        f"{ct[1]:.6f}",
        "\t",
        f"{vals['ECC']:.6f}"
    )

    # Find fastest algorithm
    fast = min(vals, key=vals.get)

    print("\nFastest Algorithm:", fast)

    # Display overhead relative to fastest
    print("\n--- Time Overhead ---")

    for alg in vals:
        diff = vals[alg] - vals[fast]
        print(alg, "overhead:", f"{diff:.6f}", "seconds")


def main():
    print("--- Complete Cryptographic Performance Analysis ---")

    while True:
        print("\n--- Menu ---")
        print("1. Algorithm Performance")
        print("2. Key Size Performance")
        print("3. Algorithm Comparison and Overhead")
        print("4. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            algorithm_test()

        elif ch == "2":
            key_size_test()

        elif ch == "3":
            comparison_test()

        elif ch == "4":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()