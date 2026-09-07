"""
Question 70: Diffie-Hellman KDF, AES Communication and Performance

Extend Diffie-Hellman to derive a fixed-length symmetric key from the shared secret and use AES to encrypt/decrypt a message. Measure DH key-generation/shared-secret computation time for different parameter sizes.

Flow:
DH Exchange
    ↓
Shared Secret
    ↓
   KDF
    ↓
 AES Key
    ↓
Plaintext → AES Encrypt → Ciphertext
                           ↓
                       AES Decrypt
                           ↓
                       Plaintext
                           ↓
                       Verify

Performance:
Parameter Size
      ↓
DH Key/Public Calculation
      ↓
Shared Secret Calculation
      ↓
Measure with perf_counter()
      ↓
Comparison Table

Requirements:
- DH exchange
- KDF/hash
- AES encryption/decryption
- Verification
- Different parameter sizes
- time.perf_counter()
- Display timing results

Absorbs: original Q80–82.

"""

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime
import random
import time


def valid(p, g):
    return p > 2 and 1 < g < p


def dh(p, g, a, b):
    # Generate public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Calculate shared secret independently
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)

    return A, B, s1, s2


def derive_key(s, p):
    # Convert shared secret to bytes
    n = (p.bit_length() + 7) // 8
    sb = s.to_bytes(n, "big")

    # SHA-256 KDF gives a fixed 32-byte AES key
    return SHA256.new(sb).digest()


def communication():
    try:
        p = int(input("Enter prime p: "))
        g = int(input("Enter generator g: "))
        a = int(input("Enter Alice private key a: "))
        b = int(input("Enter Bob private key b: "))

        if not valid(p, g) or a <= 0 or b <= 0:
            print("Error: Invalid DH parameters or private keys.")
            return

        # Perform DH exchange
        A, B, s1, s2 = dh(p, g, a, b)

        print("\n--- DH Exchange ---")
        print("Alice Public Key:", A)
        print("Bob Public Key:", B)
        print("Alice Shared Secret:", s1)
        print("Bob Shared Secret:", s2)

        if s1 != s2:
            print("FAILURE: Shared secrets are different.")
            return

        print("SUCCESS: Shared secrets are equal.")

        # Derive AES key from shared secret
        key = derive_key(s1, p)

        print("AES Key:", key.hex())

        msg = input("\nEnter message: ")

        if not msg:
            print("Error: Message cannot be empty.")
            return

        # AES-EAX encryption
        cipher = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(msg.encode())

        print("\n--- AES Encryption ---")
        print("Ciphertext:", ct.hex())

        # AES-EAX decryption
        dec = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
        pt = dec.decrypt(ct)

        # Verify authentication tag
        dec.verify(tag)

        rec = pt.decode()

        print("Recovered Plaintext:", rec)

        if msg == rec:
            print("SUCCESS: Plaintext verified.")
        else:
            print("FAILURE: Plaintext verification failed.")

    except ValueError:
        print("Error: Invalid input.")
    except Exception as e:
        print("Error:", e)


def performance():
    # Predefined prime sizes
    sizes = [512, 1024, 2048]

    print("\n--- DH Performance ---")
    print("Size\tKey/Public\tShared Secret")

    for bits in sizes:
        # Generate prime and use generator 2
        p = getPrime(bits)
        g = 2

        a = random.randint(2, p - 2)
        b = random.randint(2, p - 2)

        # Measure public-key calculation
        st = time.perf_counter()

        A = pow(g, a, p)
        B = pow(g, b, p)

        t1 = time.perf_counter() - st

        # Measure shared-secret calculation
        st = time.perf_counter()

        s1 = pow(B, a, p)
        s2 = pow(A, b, p)

        t2 = time.perf_counter() - st

        print(bits, "bit\t", t1, "\t", t2)

        if s1 != s2:
            print("Verification: FAILURE")


def main():
    print("--- DH + KDF + AES System ---")

    while True:
        print("\n--- Menu ---")
        print("1. DH + KDF + AES Communication")
        print("2. DH Performance")
        print("3. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            communication()

        elif ch == "2":
            performance()

        elif ch == "3":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()