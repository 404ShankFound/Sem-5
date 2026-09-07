"""14. aes_cbc_ctr

Implement AES in CBC and CTR modes using user-provided key and IV/nonce;
modify plaintext, key and IV/nonce; perform both encryption and decryption
and verify the plaintext.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key, mode, iv):
    if mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
    else:
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        ct = cipher.encrypt(pt.encode())

    return ct


def decrypt(ct, key, mode, iv):
    if mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
    else:
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        pt = cipher.decrypt(ct).decode()

    return pt


def main():
    print("========== AES CBC / CTR ==========")
    print("1. CBC")
    print("2. CTR")

    choice = input("Enter choice: ")

    if choice == '1':
        mode = 'CBC'
    elif choice == '2':
        mode = 'CTR'
    else:
        print("Invalid choice.")
        return

    key = input("Enter key (16 characters): ").encode()
    pt = input("Enter plaintext: ")

    if len(key) != 16:
        print("Key must be exactly 16 characters.")
        return

    if mode == 'CBC':
        iv = input("Enter IV (16 characters): ").encode()

        if len(iv) != 16:
            print("IV must be exactly 16 characters.")
            return

    else:
        iv = input("Enter nonce (8 characters): ").encode()

        if len(iv) != 8:
            print("Nonce must be exactly 8 characters.")
            return

    ct = encrypt(pt, key, mode, iv)

    print("\nMode:", mode)
    print("Ciphertext (hex):", ct.hex())

    dpt = decrypt(ct, key, mode, iv)

    print("Decrypted text:", dpt)
    print("Verification:", "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()