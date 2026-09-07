"""
Question 51: Elgamal hex message

Convert a plaintext message into bytes/integer form, perform ElGamal encryption, and convert the decrypted integer back to text.
"""

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random


def main():
    # Generate ElGamal parameters
    p = getPrime(512)
    g = 2

    # Generate private key x
    x = random.randint(2, p - 2)

    # Generate public key y = g^x mod p
    y = pow(g, x, p)

    # Take plaintext message
    msg = input("Enter plaintext message: ")

    # Convert plaintext to bytes
    pt = msg.encode()

    # Convert bytes to integer
    m = bytes_to_long(pt)

    # Check that message integer is smaller than p
    if m >= p:
        print("Message is too large for the selected prime.")
        return

    # Generate random k for encryption
    k = random.randint(2, p - 2)

    # ElGamal encryption
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    # ElGamal decryption
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m2 = (c2 * s_inv) % p

    # Convert decrypted integer back to bytes
    pt2 = long_to_bytes(m2)

    # Convert bytes back to text
    msg2 = pt2.decode()

    print("\n--- ElGamal ---")
    print("Plaintext Bytes:", pt)
    print("Plaintext Integer:", m)
    print("Ciphertext c1:", c1)
    print("Ciphertext c2:", c2)
    print("Decrypted Integer:", m2)
    print("Recovered Plaintext:", msg2)
    print("Decryption Successful:", msg == msg2)


if __name__ == "__main__":
    main()