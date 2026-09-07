# %%
"""7. elgamal_basic_encryption_decryption

Given (p,g,d), where g is a primitive root modulo p,
generate the public key (e1,e2,p), encrypt a message using random k,
decrypt using d, and verify the plaintext.
"""

from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import random

def primitive_root(p):
    for g in range(2, p):
        s = set()

        for i in range(1, p):
            s.add(pow(g, i, p))

        if len(s) == p - 1:
            return g
    return None


def main():
    # Enter large prime p.
    p = int(input("Enter prime p: "))

    # Enter primitive root g of p.
    # g must be a primitive root modulo p.
    # g = int(input("Enter primitive root g: "))

    g = primitive_root(p)
    if(g == None):
        print("Primitive root does not exist for", p)
        return None

    print("Smallest Primitive root:", g)

    # Enter private/secret key d.
    # 1 < d < p-1
    d = int(input("Enter private key d: "))

    # Generate public key parameters.
    # e1 = g
    # e2 = e1^d mod p
    e1 = g
    e2 = pow(e1, d, p)

    print("Public Key:", (e1, e2, p))
    print("Private Key:", d)

    # Enter plaintext message.
    pt = input("Enter plaintext: ")

    # Convert plaintext into an integer.
    m = bytes_to_long(pt.encode())

    # ElGamal requires m < p.
    if m >= p:
        print("Plaintext is too large for p.")
        return

    # Generate random k.
    # k must satisfy 1 <= k <= p-2.
    k = random.randint(1, p - 2)

    # ElGamal encryption:
    # c1 = e1^k mod p
    c1 = pow(e1, k, p)

    # c2 = m * e2^k mod p
    c2 = (m * pow(e2, k, p)) % p

    print("Random k:", k)
    print("Ciphertext:", (c1, c2))

    # ElGamal decryption:
    # s = c1^d mod p
    s = pow(c1, d, p)

    # Find inverse of s modulo p.
    s_inv = inverse(s, p)

    # Recover original message:
    # m = c2 * s^(-1) mod p
    md = (c2 * s_inv) % p

    # Convert integer back to bytes and then string.
    dec = long_to_bytes(md).decode()

    print("Decrypted plaintext:", dec)

    # Verify plaintext.
    if pt == dec:
        print("SUCCESS: Messages match")
    else:
        print("FAILURE: Messages do not match")


if __name__ == "__main__":
    main()