"""6. des_modes

Modify DES to support different modes of operation such as ECB, CBC, CFB and
OFB; accept the required IV where applicable; perform encryption and
decryption; compare the modes using the same plaintext/key.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt_ecb(plaintext, key):

    cipher = DES.new(key, DES.MODE_ECB)

    padded_data = pad(plaintext.encode(), DES.block_size)

    return cipher.encrypt(padded_data)


def decrypt_ecb(ciphertext, key):

    cipher = DES.new(key, DES.MODE_ECB)

    plaintext = cipher.decrypt(ciphertext)

    return unpad(plaintext, DES.block_size).decode()


def encrypt_cbc(plaintext, key, iv):

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded_data = pad(plaintext.encode(), DES.block_size)

    return cipher.encrypt(padded_data)


def decrypt_cbc(ciphertext, key, iv):

    cipher = DES.new(key, DES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext)

    return unpad(plaintext, DES.block_size).decode()


def encrypt_cfb(plaintext, key, iv):

    cipher = DES.new(key, DES.MODE_CFB, iv)

    return cipher.encrypt(plaintext.encode())


def decrypt_cfb(ciphertext, key, iv):

    cipher = DES.new(key, DES.MODE_CFB, iv)

    return cipher.decrypt(ciphertext).decode()


def encrypt_ofb(plaintext, key, iv):

    cipher = DES.new(key, DES.MODE_OFB, iv)

    return cipher.encrypt(plaintext.encode())


def decrypt_ofb(ciphertext, key, iv):

    cipher = DES.new(key, DES.MODE_OFB, iv)

    return cipher.decrypt(ciphertext).decode()


def main():

    print("========== DES MODES ==========")

    key_input = input("Enter 8-character key: ")

    if len(key_input.encode()) != 8:
        print("Key must be exactly 8 characters.")
        return

    plaintext = input("Enter plaintext: ")

    key = key_input.encode()

    print("\nEnter IV for CBC/CFB/OFB")
    iv_input = input("Enter 8-character IV: ")

    if len(iv_input.encode()) != 8:
        print("IV must be exactly 8 characters.")
        return

    iv = iv_input.encode()

    # ------------------------------------------------------------
    # ECB
    # ------------------------------------------------------------

    ciphertext = encrypt_ecb(plaintext, key)
    decrypted = decrypt_ecb(ciphertext, key)

    print("\n========== ECB ==========")
    print("Ciphertext (Hex):", ciphertext.hex())
    print("Decrypted:", decrypted)

    # ------------------------------------------------------------
    # CBC
    # ------------------------------------------------------------

    ciphertext = encrypt_cbc(plaintext, key, iv)
    decrypted = decrypt_cbc(ciphertext, key, iv)

    print("\n========== CBC ==========")
    print("Ciphertext (Hex):", ciphertext.hex())
    print("Decrypted:", decrypted)

    # ------------------------------------------------------------
    # CFB
    # ------------------------------------------------------------

    ciphertext = encrypt_cfb(plaintext, key, iv)
    decrypted = decrypt_cfb(ciphertext, key, iv)

    print("\n========== CFB ==========")
    print("Ciphertext (Hex):", ciphertext.hex())
    print("Decrypted:", decrypted)

    # ------------------------------------------------------------
    # OFB
    # ------------------------------------------------------------

    ciphertext = encrypt_ofb(plaintext, key, iv)
    decrypted = decrypt_ofb(ciphertext, key, iv)

    print("\n========== OFB ==========")
    print("Ciphertext (Hex):", ciphertext.hex())
    print("Decrypted:", decrypted)


if __name__ == "__main__":
    main()