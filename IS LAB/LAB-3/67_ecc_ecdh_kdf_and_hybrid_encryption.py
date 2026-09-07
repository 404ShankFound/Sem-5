"""
Question 67: ECC ECDH, KDF and Hybrid Encryption

Use ECDH to establish a shared secret, apply a KDF/hash-based derivation to obtain a fixed-length symmetric key, and use AES to encrypt/decrypt plaintext. Demonstrate ECC-based hybrid/ECIES-style encryption and decryption.

Flow:
Alice ECC Key Pair ─────┐
                        │
                        ↓
                   ECDH Shared
                     Secret
                        ↓
                       KDF
                        ↓
                   AES Key
                        ↓
Plaintext ───────────→ AES ─────────→ Ciphertext
                                          ↓
                                      AES Decrypt
                                          ↓
                                     Plaintext

Requirements:
- Generate ECC key pairs
- Perform ECDH
- Verify shared secret
- Derive fixed-length symmetric key using KDF
- Use AES for actual plaintext encryption
- Decrypt using derived key
- Verify recovered plaintext
- Handle authentication/decryption failure appropriately

Absorbs: original Q68, Q69.

"""

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os


def main():
    print("--- ECC ECDH + KDF + AES ---")

    # Generate Alice and Bob ECC key pairs
    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    # Get public keys
    QA = alice.public_key().pointQ
    QB = bob.public_key().pointQ

    # ECDH: calculate common shared point
    SA = alice.d * QB
    SB = bob.d * QA

    print("\n--- ECDH ---")
    print("Alice Shared Point:")
    print("x =", SA.x)
    print("y =", SA.y)

    print("\nBob Shared Point:")
    print("x =", SB.x)
    print("y =", SB.y)

    # Verify shared points
    if SA != SB:
        print("\nFAILURE: Shared secrets are different.")
        return

    print("\nSUCCESS: Shared secrets are equal.")

    # Convert shared point x-coordinate to bytes
    s = int(SA.x).to_bytes(32, "big")

    # KDF: SHA-256 derives a fixed 32-byte AES key
    key = SHA256.new(s).digest()

    print("Derived AES Key:", key.hex())

    # Take plaintext
    msg = input("\nEnter plaintext message: ")

    if not msg:
        print("Error: Message cannot be empty.")
        return

    pt = msg.encode()

    # AES-EAX encryption
    cipher = AES.new(key, AES.MODE_EAX)

    ct, tag = cipher.encrypt_and_digest(pt)

    print("\n--- Encryption ---")
    print("Ciphertext:", ct.hex())
    print("Nonce:", cipher.nonce.hex())
    print("Tag:", tag.hex())

    try:
        # AES-EAX decryption
        dec = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
        data = dec.decrypt(ct)

        # Verify authentication tag
        dec.verify(tag)

        msg2 = data.decode()

        print("\n--- Decryption ---")
        print("Recovered Plaintext:", msg2)

        if msg == msg2:
            print("SUCCESS: Plaintext verified.")
        else:
            print("FAILURE: Plaintext verification failed.")

    except (ValueError, UnicodeDecodeError):
        print("FAILURE: Authentication/decryption failed.")


if __name__ == "__main__":
    main()