"""
Question 43: Elgamal random k

Generate a new random k for every encryption and show that encrypting the same plaintext produces different ciphertexts.
"""

import random

from Crypto.Util.number import bytes_to_long, isPrime

def main():

    # Use fixed educational ElGamal parameters
    # 467 is prime and 2 is a primitive root modulo 467
    p = 467
    g = 2

    # Generate private key
    d = random.randint(1, p - 2)

    # Public key
    e1 = g
    e2 = pow(e1, d, p)

    # Same plaintext is encrypted twice
    pt = input("Enter plaintext: ")
    m = bytes_to_long(pt.encode())

    if m >= p:
        print("Plaintext is too large for the selected p.")
        return

    print("\nPublic Key:", (e1, e2, p))
    print("Private Key:", d)

    # -----------------------------
    # First encryption
    # -----------------------------

    k1 = random.randint(1, p - 2)

    c1_1 = pow(e1, k1, p)
    c2_1 = (m * pow(e2, k1, p)) % p

    print("\nFirst Encryption")
    print("Random k:", k1)
    print("Ciphertext:", (c1_1, c2_1))

    # -----------------------------
    # Second encryption
    # -----------------------------

    k2 = random.randint(1, p - 2)

    c1_2 = pow(e1, k2, p)
    c2_2 = (m * pow(e2, k2, p)) % p

    print("\nSecond Encryption")
    print("Random k:", k2)
    print("Ciphertext:", (c1_2, c2_2))

    # Verify that different k values produce different ciphertexts
    print("\nSame plaintext:", True)
    print("Different k:", k1 != k2)
    print("Different ciphertext:", (c1_1, c2_1) != (c1_2, c2_2))


if __name__ == "__main__":
    main()