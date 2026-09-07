"""8. des_3des

Modify DES to implement Triple DES; support encryption and decryption using
three keys or a 3-key hexadecimal key; accept user input and verify the
recovered plaintext.
"""

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), DES3.block_size))
    return ct


def decrypt(ct, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), DES3.block_size).decode()
    return pt


def main():
    print("========== 3DES MENU ==========")
    print("1. Three separate keys")
    print("2. 3-key hexadecimal key")

    choice = input("Enter choice: ")

    if choice == '1':
        k1 = input("Enter key 1 (8 characters): ")
        k2 = input("Enter key 2 (8 characters): ")
        k3 = input("Enter key 3 (8 characters): ")

        if len(k1) != 8 or len(k2) != 8 or len(k3) != 8:
            print("Each key must be exactly 8 characters.")
            return

        key = k1.encode() + k2.encode() + k3.encode()

    elif choice == '2':
        kh = input("Enter 3-key hexadecimal key (48 hex characters): ")

        if len(kh) != 48:
            print("Hexadecimal key must be exactly 48 hex characters.")
            return

        try:
            key = bytes.fromhex(kh)
        except ValueError:
            print("Invalid hexadecimal key.")
            return

    else:
        print("Invalid choice.")
        return

    pt = input("Enter plaintext: ")

    ct = encrypt(pt, key)

    print("\nCiphertext (hex):", ct.hex())

    dpt = decrypt(ct, key)

    print("Decrypted text:", dpt)
    print("Verification:", "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()