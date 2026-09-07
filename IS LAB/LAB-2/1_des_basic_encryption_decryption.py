"""1. des_basic_encryption_decryption

Implement DES for a given plaintext and key; perform both encryption and
decryption; verify that the original plaintext is recovered; allow
plaintext/key as user input; include proper padding and key validation.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def des_encrypt(plaintext, key):

    plaintext = plaintext.encode()

    cipher = DES.new(key, DES.MODE_ECB)

    padded_data = pad(plaintext, DES.block_size)

    ciphertext = cipher.encrypt(padded_data)

    return ciphertext


def des_decrypt(ciphertext, key):

    cipher = DES.new(key, DES.MODE_ECB)

    decrypted_padded = cipher.decrypt(ciphertext)

    plaintext = unpad(
        decrypted_padded,
        DES.block_size
    ).decode()

    return plaintext


def main():

    print("========== DES MENU ==========")

    while True:

        key_input = input("Enter 8-character key: ")

        if len(key_input.encode()) == 8:
            break

        print("Key must be exactly 8 characters.")

    key = key_input.encode()

    plaintext = input("Enter plaintext: ")

    ciphertext = des_encrypt(plaintext, key)

    print("\nCiphertext (Hex):", ciphertext.hex())

    decrypted = des_decrypt(ciphertext, key)

    print("Decrypted Message:", decrypted)

    if plaintext == decrypted:
        print("Verification: SUCCESS")
    else:
        print("Verification: FAILED")


if __name__ == "__main__":
    main()