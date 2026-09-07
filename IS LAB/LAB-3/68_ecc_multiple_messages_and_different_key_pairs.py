"""
Question 68: ECC Multiple Messages and Different Key Pairs

Implement ECC-based hybrid encryption/decryption for multiple messages. Demonstrate encryption of multiple messages using the same ECC key pair and separate encryption/decryption operations using different ECC key pairs.

Flow:
ECC Key Pair
     ↓
┌──────────┬──────────┬──────────┐
│ Message1 │ Message2 │ Message3 │
└────┬─────┴────┬─────┴────┬─────┘
     ↓           ↓           ↓
   Encrypt     Encrypt     Encrypt
     ↓           ↓           ↓
   Decrypt     Decrypt     Decrypt
     ↓           ↓           ↓
   Verify      Verify      Verify

Optional:
New ECC Key Pair
     ↓
Separate Encryption/Decryption

Requirements:
- Multiple messages
- Same key pair option
- Different key-pair option
- AES hybrid encryption
- Decryption
- Verification of every message
- Display SUCCESS/FAILURE for each

Absorbs: original Q70, Q71.

"""

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


def encrypt(msg, alice, bob):
    # ECDH shared secret
    s = alice.d * bob.public_key().pointQ

    # Derive 32-byte AES key using SHA-256
    key = SHA256.new(int(s.x).to_bytes(32, "big")).digest()

    # AES-EAX encryption
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(msg.encode())

    return ct, cipher.nonce, tag


def decrypt(ct, nonce, tag, alice, bob):
    # Calculate the same ECDH shared secret
    s = bob.d * alice.public_key().pointQ

    # Derive the same AES key
    key = SHA256.new(int(s.x).to_bytes(32, "big")).digest()

    # AES-EAX decryption
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    pt = cipher.decrypt(ct)

    # Verify authentication tag
    cipher.verify(tag)

    return pt.decode()


def main():
    print("--- ECC Multiple Messages ---")

    # Generate one ECC key pair for same-key mode
    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    while True:
        print("\n--- Menu ---")
        print("1. Multiple Messages - Same Key Pair")
        print("2. Multiple Messages - Different Key Pairs")
        print("3. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            # Use the same Alice/Bob key pair for all messages
            msgs = input(
                "Enter messages separated by |: "
            ).split("|")

            if not all(msgs):
                print("Error: Messages cannot be empty.")
                continue

            print("\n--- Same Key Pair ---")

            for i, msg in enumerate(msgs, 1):
                try:
                    # Encrypt message
                    ct, nonce, tag = encrypt(msg, alice, bob)

                    # Decrypt message
                    rec = decrypt(ct, nonce, tag, alice, bob)

                    print("\nMessage", i, ":", msg)
                    print("Ciphertext:", ct.hex())
                    print("Recovered:", rec)

                    if msg == rec:
                        print("SUCCESS")
                    else:
                        print("FAILURE")

                except (ValueError, UnicodeDecodeError):
                    print("Message", i, ": Decryption/Authentication FAILED")

        elif ch == "2":
            # Generate a new key pair for each message
            msgs = input(
                "Enter messages separated by |: "
            ).split("|")

            if not all(msgs):
                print("Error: Messages cannot be empty.")
                continue

            print("\n--- Different Key Pairs ---")

            for i, msg in enumerate(msgs, 1):
                try:
                    # Generate separate ECC key pairs
                    alice = ECC.generate(curve="secp256r1")
                    bob = ECC.generate(curve="secp256r1")

                    # Encrypt using this key pair
                    ct, nonce, tag = encrypt(msg, alice, bob)

                    # Decrypt using the same key pair
                    rec = decrypt(ct, nonce, tag, alice, bob)

                    print("\nMessage", i, ":", msg)
                    print("Ciphertext:", ct.hex())
                    print("Recovered:", rec)

                    if msg == rec:
                        print("SUCCESS")
                    else:
                        print("FAILURE")

                except (ValueError, UnicodeDecodeError):
                    print("Message", i, ": Decryption/Authentication FAILED")

        elif ch == "3":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()