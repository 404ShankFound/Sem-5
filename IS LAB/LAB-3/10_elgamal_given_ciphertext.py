"""
10. elgamal_given_ciphertext

Given (p,e1,e2,d) and ciphertext (c1,c2), calculate the shared value,
modular inverse and recover the original plaintext.
"""

from Crypto.Util.number import inverse, long_to_bytes


def main():
    # Enter large prime p.
    p = int(input("Enter prime p: "))

    # Enter public key parameter e1.
    # e1 = g, where g is the primitive root modulo p.
    e1 = int(input("Enter e1: "))

    # Enter public key parameter e2.
    # e2 = e1^d mod p.
    e2 = int(input("Enter e2: "))

    # Enter private/secret key d.
    d = int(input("Enter private key d: "))

    # Enter ciphertext values.
    c1 = int(input("Enter c1: "))
    c2 = int(input("Enter c2: "))

    # Calculate the shared value.
    # s = c1^d mod p
    s = pow(c1, d, p)

    # Find modular inverse of the shared value.
    # s_inv = s^(-1) mod p
    s_inv = inverse(s, p)

    # Recover the original plaintext integer.
    # m = c2 * s^(-1) mod p
    m = (c2 * s_inv) % p

    # Convert the plaintext integer back into bytes
    # and then into a normal string.
    pt = long_to_bytes(m).decode()

    # Display the calculated values.
    print("Shared Value:", s)
    print("Modular Inverse:", s_inv)
    print("Recovered Plaintext:", pt)


if __name__ == "__main__":
    main()