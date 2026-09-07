"""7. des_cbc_iv_variations

Implement DES-CBC with a user-provided key and IV; modify the program for
different plaintexts, keys and IVs; encrypt and decrypt and verify the result.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key, iv):
    cipher = DES.new(key.encode(), DES.MODE_CBC, iv.encode())
    ct = cipher.encrypt(pad(pt.encode(), DES.block_size))
    return ct


def decrypt(ct, key, iv):
    cipher = DES.new(key.encode(), DES.MODE_CBC, iv.encode())
    pt = unpad(cipher.decrypt(ct), DES.block_size).decode()
    return pt


def main():
    print("========== DES CBC IV VARIATIONS ==========")

    key = input("Enter key (8 characters): ")
    iv = input("Enter IV (8 characters): ")
    pt = input("Enter plaintext: ")

    if len(key) != 8:
        print("Key must be exactly 8 characters.")
        return

    if len(iv) != 8:
        print("IV must be exactly 8 characters.")
        return

    ct = encrypt(pt, key, iv)

    print("\nCiphertext (hex):", ct.hex())

    dpt = decrypt(ct, key, iv)

    print("Decrypted text:", dpt)
    print("Verification:", "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()