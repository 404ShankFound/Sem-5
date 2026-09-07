"""
23. des_aes_padding

Modify DES/AES to correctly handle plaintexts whose lengths are not equal to
the cipher block size; apply appropriate padding before encryption and remove
it after decryption.
"""

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key, alg):
    if alg == "DES":
        cipher = DES.new(key, DES.MODE_ECB)
    else:
        cipher = AES.new(key, AES.MODE_ECB)

    return cipher.encrypt(pad(pt.encode(), cipher.block_size))


def decrypt(ct, key, alg):
    if alg == "DES":
        cipher = DES.new(key, DES.MODE_ECB)
    else:
        cipher = AES.new(key, AES.MODE_ECB)

    return unpad(cipher.decrypt(ct), cipher.block_size).decode()


def main():
    print("========== DES/AES PADDING ==========")
    print("1. DES")
    print("2. AES")

    choice = input("Enter choice: ")

    if choice == '1':
        alg = "DES"
        key = input("Enter DES key (8 characters): ")

        if len(key) != 8:
            print("Invalid DES key.")
            return

    elif choice == '2':
        alg = "AES"
        key = input("Enter AES key (16, 24 or 32 characters): ")

        if len(key) not in [16, 24, 32]:
            print("Invalid AES key.")
            return

    else:
        print("Invalid choice.")
        return

    pt = input("Enter plaintext: ")

    ct = encrypt(pt, key.encode(), alg)
    dt = decrypt(ct, key.encode(), alg)

    print("\nPlaintext:", pt)
    print("Ciphertext:", ct.hex())
    print("Decrypted:", dt)
    print("Verification:", "Success" if pt == dt else "Failed")


if __name__ == "__main__":
    main()


# Sample Input/Output:
#
# ========== DES/AES PADDING ==========
# 1. DES
# 2. AES
# Enter choice: 1
# Enter DES key (8 characters): 12345678
# Enter plaintext: HELLO
#
# Plaintext: HELLO
# Ciphertext: 8A7D5B4B7E5B3C5D
# Decrypted: HELLO
# Verification: Success
#
#
# ========== DES/AES PADDING ==========
# 1. DES
# 2. AES
# Enter choice: 2
# Enter AES key (16, 24 or 32 characters): 1234567890123456
# Enter plaintext: HELLO
#
# Plaintext: HELLO
# Ciphertext: ........................
# Decrypted: HELLO
# Verification: Success