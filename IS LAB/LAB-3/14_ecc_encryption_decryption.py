"""
14. ecc_encryption_decryption

Implement the ECC encryption/decryption operation specified in the lab;
generate/use public and private keys and verify the recovered message.

ECC / ECDH
Alice -------------------- Bob
  dA                        dB
  ↓                         ↓
 QA = dA G                QB = dB G
  ↓                         ↓
       Exchange QA, QB
             ↓
       Shared secret S
             ↓
        KDF / SHA-256
             ↓
          AES key
             ↓
Alice encrypts pt      Bob decrypts
       ↓                    ↑
   ciphertext ------------+

ECDH  -> Creates shared secret
KDF   -> Converts shared secret into usable key
SHA256 -> Derives a 256-bit key
AES   -> Encrypts/decrypts plaintext
"""

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def main():

    # -----------------------------
    # 1. Generate Alice's ECC key
    # -----------------------------

    alice = ECC.generate(curve="P-256")

    # Alice's private key
    dA = alice.d

    # Alice's public key
    QA = alice.public_key()

    # -----------------------------
    # 2. Generate Bob's ECC key
    # -----------------------------

    bob = ECC.generate(curve="P-256")

    # Bob's private key
    dB = bob.d

    # Bob's public key
    QB = bob.public_key()

    print("Alice Private Key:", dA)
    print("Alice Public Key:", QA.pointQ)

    print("\nBob Private Key:", dB)
    print("Bob Public Key:", QB.pointQ)

    # -----------------------------
    # 3. Calculate shared secret
    # -----------------------------

    # Alice calculates:
    # S = dA * QB
    SA = dA * QB.pointQ

    # Bob calculates:
    # S = dB * QA
    SB = dB * QA.pointQ

    # Both shared secrets must be same
    print("\nShared Secret Same:", SA == SB)

    # Use X-coordinate of shared point
    s = int(SA.x)

    # -----------------------------
    # 4. Derive AES key using SHA-256
    # -----------------------------

    key = SHA256.new(s.to_bytes(32, "big")).digest()

    print("AES Key:", key.hex())

    # -----------------------------
    # 5. Encrypt plaintext using AES
    # -----------------------------

    pt = input("\nEnter plaintext: ").encode()

    # AES-EAX provides encryption + authentication
    cipher = AES.new(key, AES.MODE_EAX)

    ct, tag = cipher.encrypt_and_digest(pt)

    print("Ciphertext:", ct.hex())

    # -----------------------------
    # 6. Decrypt ciphertext
    # -----------------------------

    cipher2 = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)

    recovered = cipher2.decrypt_and_verify(ct, tag)

    print("Recovered Plaintext:", recovered.decode())

    # Verify original and recovered messages
    print("Decryption Successful:", recovered == pt)


if __name__ == "__main__":
    main()