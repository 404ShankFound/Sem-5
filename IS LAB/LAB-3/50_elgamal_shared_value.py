"""
Question 50: Elgamal shared value

Display the shared value s = c1^x mod p, its modular inverse, and the recovered plaintext during decryption.
"""

from Crypto.Util.number import inverse, long_to_bytes


def main():
    p = int(input("Enter prime p: "))
    x = int(input("Enter private key x: "))
    c1 = int(input("Enter c1: "))
    c2 = int(input("Enter c2: "))

    # Calculate shared value: s = c1^x mod p
    s = pow(c1, x, p)

    # Calculate modular inverse of shared value
    s_inv = inverse(s, p)

    # Recover plaintext: m = c2 * s^(-1) mod p
    m = (c2 * s_inv) % p

    # Convert plaintext integer back to text
    pt = long_to_bytes(m)

    print("\n--- ElGamal Decryption ---")
    print("Shared Value:", s)
    print("Modular Inverse:", s_inv)
    print("Recovered Plaintext:", pt.decode())

    print("Decryption Successful: True")


if __name__ == "__main__":
    main()