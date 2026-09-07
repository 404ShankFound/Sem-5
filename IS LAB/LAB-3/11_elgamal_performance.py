"""
11. elgamal_performance

Measure ElGamal key-generation, encryption and decryption time for different
prime sizes or different plaintext sizes and compare the results.
"""

import time
import random
from Crypto.Util.number import getPrime, bytes_to_long, inverse


def main():
    # Choose what to vary.
    print("1. Vary prime size")
    print("2. Vary plaintext size")

    ch = int(input("Enter choice: "))

    # Prime size variation.
    if ch == 1:
        # Test different prime sizes in bits.
        sizes = [1024, 2048, 3072]

        print("-" * 65)
        print(f"{'Prime Size':<15}{'Key Gen':<15}{'Encryption':<15}{'Decryption':<15}")

        # Repeat the experiment for each prime size.
        for size in sizes:

            # Measure key-generation time.
            t1 = time.perf_counter()

            # Generate a random prime p of the selected size.
            p = getPrime(size)

            # Use g = 2 as the primitive root.
            g = 2

            # Generate private/secret key d.
            d = random.randint(1, p - 2)

            # Generate public key parameters.
            # e1 = g
            # e2 = e1^d mod p
            e1 = g
            e2 = pow(e1, d, p)

            t2 = time.perf_counter()

            # Calculate key-generation time.
            kg = t2 - t1

            # Use a fixed plaintext for prime-size comparison.
            pt = b"A" * 16

            # Convert plaintext into an integer.
            m = bytes_to_long(pt)

            # Generate random k.
            k = random.randint(1, p - 2)

            # Measure encryption time.
            t1 = time.perf_counter()

            # c1 = e1^k mod p
            c1 = pow(e1, k, p)

            # c2 = m * e2^k mod p
            c2 = (m * pow(e2, k, p)) % p

            t2 = time.perf_counter()

            et = t2 - t1

            # Measure decryption time.
            t1 = time.perf_counter()

            # Calculate shared value.
            s = pow(c1, d, p)

            # Find modular inverse of shared value.
            s_inv = inverse(s, p)

            # Recover plaintext integer.
            md = (c2 * s_inv) % p

            t2 = time.perf_counter()

            dt = t2 - t1

            print(f"{size:<15}{kg:<15.6f}{et:<15.6f}{dt:<15.6f}")

    # Plaintext size variation.
    elif ch == 2:
        # Use a fixed 2048-bit prime for plaintext-size comparison.
        p = getPrime(2048)

        # Use g = 2 as the primitive root.
        g = 2

        # Generate private/secret key d.
        d = random.randint(1, p - 2)

        # Generate public key parameters.
        # e1 = g
        # e2 = e1^d mod p
        e1 = g
        e2 = pow(e1, d, p)

        # Test different plaintext sizes in bytes.
        sizes = [16, 64, 128, 256]

        print("-" * 65)
        print(f"{'Plaintext Size':<15}{'Key Gen':<15}{'Encryption':<15}{'Decryption':<15}")

        # Repeat the experiment for each plaintext size.
        for size in sizes:

            # Generate plaintext of the selected size.
            pt = b"A" * size

            # Convert plaintext into an integer.
            m = bytes_to_long(pt)

            # ElGamal requires m < p.
            if m >= p:
                print("Plaintext is too large for p.")
                return

            # Generate random k.
            k = random.randint(1, p - 2)

            # Measure encryption time.
            t1 = time.perf_counter()

            # c1 = e1^k mod p
            c1 = pow(e1, k, p)

            # c2 = m * e2^k mod p
            c2 = (m * pow(e2, k, p)) % p

            t2 = time.perf_counter()

            et = t2 - t1

            # Measure decryption time.
            t1 = time.perf_counter()

            # Calculate shared value.
            s = pow(c1, d, p)

            # Find modular inverse of shared value.
            s_inv = inverse(s, p)

            # Recover plaintext integer.
            md = (c2 * s_inv) % p

            t2 = time.perf_counter()

            dt = t2 - t1

            print(f"{size:<15}{0:<15.6f}{et:<15.6f}{dt:<15.6f}")

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()