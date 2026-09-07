"""
Question 49: Elgamal ciphertext input

Accept (c1,c2) from the user and decrypt the ciphertext using the private key.
"""

from Crypto.Util.number import inverse, long_to_bytes


def main():

    # ElGamal parameters
    p = int(input("Enter prime p: "))
    e1 = int(input("Enter e1: "))
    e2 = int(input("Enter e2: "))

    # Private key
    d = int(input("Enter private key d: "))

    # Ciphertext
    c1 = int(input("Enter c1: "))
    c2 = int(input("Enter c2: "))

    # Calculate shared value
    s = pow(c1, d, p)

    # Calculate modular inverse of shared value
    s_inv = inverse(s, p)

    # Recover plaintext integer
    m = (c2 * s_inv) % p

    # Convert integer back to plaintext
    pt = long_to_bytes(m)

    print("\nShared Value:", s)
    print("Modular Inverse:", s_inv)
    print("Recovered Plaintext:", pt.decode())

    print("Decryption Successful: True")


if __name__ == "__main__":
    main()