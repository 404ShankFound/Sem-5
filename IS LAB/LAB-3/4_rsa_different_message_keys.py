# %%
"""4. rsa_different_message_keys

Modify RSA for different plaintexts, different p,q/e, given public/private
keys, and encryption/decryption of multiple messages.
"""

# %%
from math import gcd
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes


def gen_keys(p, q, e):
    # Calculate n
    n = p * q

    # Calculate phi(n)
    phi = (p - 1) * (q - 1)

    # Check whether e is valid
    if gcd(e, phi) != 1:
        return None

    # Calculate private exponent d
    d = inverse(e, phi)

    return n, e, d


def encrypt(msg, n, e):
    # Convert message to integer
    m = bytes_to_long(msg.encode())

    # RSA requires m < n
    if m >= n:
        return None

    # c = m^e mod n
    c = pow(m, e, n)

    return c


def decrypt(c, n, d):
    # m = c^d mod n
    m = pow(c, d, n)

    # Convert integer back to text
    msg = long_to_bytes(m).decode()

    return msg


def main():
    # First RSA key pair
    p1 = int(input("Enter p1: "))
    q1 = int(input("Enter q1: "))
    e1 = int(input("Enter e1: "))

    k1 = gen_keys(p1, q1, e1)

    if k1 is None:
        print("Invalid e1")
        return

    n1, e1, d1 = k1

    # Second RSA key pair
    p2 = int(input("Enter p2: "))
    q2 = int(input("Enter q2: "))
    e2 = int(input("Enter e2: "))

    k2 = gen_keys(p2, q2, e2)

    if k2 is None:
        print("Invalid e2")
        return

    n2, e2, d2 = k2

    print("\nKey 1:")
    print("Public Key:", (n1, e1))
    print("Private Key:", (n1, d1))

    print("\nKey 2:")
    print("Public Key:", (n2, e2))
    print("Private Key:", (n2, d2))

    # Take multiple messages
    msgs = ["Hi", "Hello"]

    print("\nMessages:", msgs)

    # Encrypt each message using a different public key
    c1 = encrypt(msgs[0], n1, e1)
    c2 = encrypt(msgs[1], n2, e2)

    if c1 is None or c2 is None:
        print("Message is too large for the selected keys.")
        return

    print("Ciphertext 1:", c1)
    print("Ciphertext 2:", c2)

    # Decrypt using the corresponding private keys
    dmsg1 = decrypt(c1, n1, d1)
    dmsg2 = decrypt(c2, n2, d2)

    print("Decrypted 1:", dmsg1)
    print("Decrypted 2:", dmsg2)

if __name__ == "__main__":
    main()