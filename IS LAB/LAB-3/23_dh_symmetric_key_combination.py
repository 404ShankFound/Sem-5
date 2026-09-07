"""
23. dh_symmetric_key_combination

Use Diffie-Hellman to establish a shared secret between two peers; verify
both peers obtain the same key and use the resulting key for secure
communication.
"""

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def main():

    # Public DH parameters
    p = int(input("Enter prime p: "))
    g = int(input("Enter generator g: "))

    # Private keys of Alice and Bob
    a = int(input("Enter Alice private key: "))
    b = int(input("Enter Bob private key: "))

    # Generate public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    print("\nAlice Public Key:", A)
    print("Bob Public Key:", B)

    # Calculate shared secret
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)

    print("\nAlice Shared Secret:", s1)
    print("Bob Shared Secret:", s2)

    # Verify both shared secrets
    if s1 != s2:
        print("Shared secrets do not match.")
        return

    print("Shared Secret Same: True")

    # Convert shared secret into 32 bytes
    sb = s1.to_bytes((s1.bit_length() + 7) // 8 or 1, "big")

    # Derive AES-256 key using SHA-256
    key = SHA256.new(sb).digest()

    print("AES Key:", key.hex())

    # -----------------------------
    # Alice encrypts the message
    # -----------------------------

    pt = input("\nEnter message: ").encode()

    cipher = AES.new(key, AES.MODE_EAX)

    ct, tag = cipher.encrypt_and_digest(pt)

    print("Ciphertext:", ct.hex())

    # -----------------------------
    # Bob decrypts the message
    # -----------------------------

    cipher2 = AES.new(
        key,
        AES.MODE_EAX,
        nonce=cipher.nonce
    )

    recovered = cipher2.decrypt_and_verify(ct, tag)

    print("Recovered Message:", recovered.decode())

    # Verify communication
    print("Communication Successful:", recovered == pt)


if __name__ == "__main__":
    main()