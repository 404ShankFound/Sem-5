"""11. aes_key_size_variations

Modify AES to support 128-bit, 192-bit and 256-bit keys; automatically select
the appropriate number of rounds; display encryption/decryption results for
the selected key size.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
    return ct


def decrypt(ct, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
    return pt


def main():
    print("========== AES KEY SIZE MENU ==========")
    print("1. AES-128")
    print("2. AES-192")
    print("3. AES-256")

    choice = input("Enter choice: ")

    if choice == '1':
        n = 16
        r = 10
    elif choice == '2':
        n = 24
        r = 12
    elif choice == '3':
        n = 32
        r = 14
    else:
        print("Invalid choice.")
        return

    key = input(f"Enter key ({n} characters): ")
    pt = input("Enter plaintext: ")

    if len(key) != n:
        print(f"Key must be exactly {n} characters.")
        return

    print("\nKey size:", n * 8, "bits")
    print("Number of rounds:", r)

    ct = encrypt(pt, key)

    print("Ciphertext (hex):", ct.hex())

    dpt = decrypt(ct, key)

    print("Decrypted text:", dpt)
    print("Verification:", "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()