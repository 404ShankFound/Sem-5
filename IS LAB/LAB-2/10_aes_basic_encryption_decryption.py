"""10. aes_basic_encryption_decryption

Implement AES for a given plaintext and key; support AES-128, AES-192 and
AES-256; perform encryption and decryption; verify the original plaintext;
accept input from the user.
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
    print("========== AES MENU ==========")
    print("1. AES-128")
    print("2. AES-192")
    print("3. AES-256")

    choice = input("Enter choice: ")

    if choice == '1':
        n = 16
    elif choice == '2':
        n = 24
    elif choice == '3':
        n = 32
    else:
        print("Invalid choice.")
        return

    key = input(f"Enter key ({n} characters): ")
    pt = input("Enter plaintext: ")

    if len(key) != n:
        print(f"Key must be exactly {n} characters.")
        return

    ct = encrypt(pt, key)

    print("\nCiphertext (hex):", ct.hex())

    dpt = decrypt(ct, key)

    print("Decrypted text:", dpt)
    print("Verification:", "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()