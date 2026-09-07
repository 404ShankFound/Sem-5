"""13. aes_modes

Modify AES to support different modes such as ECB, CBC, CFB, OFB and CTR;
accept IV/nonce where required; perform encryption and decryption and compare
the modes.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key, mode, iv=None):
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(pt.encode(), AES.block_size))

    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(pt.encode(), AES.block_size))

    elif mode == 'CFB':
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ct = cipher.encrypt(pt.encode())

    elif mode == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB, iv)
        ct = cipher.encrypt(pt.encode())

    elif mode == 'CTR':
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        ct = cipher.encrypt(pt.encode())

    return ct


def decrypt(ct, key, mode, iv=None):
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode()

    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode()

    elif mode == 'CFB':
        cipher = AES.new(key, AES.MODE_CFB, iv)
        pt = cipher.decrypt(ct).decode()

    elif mode == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB, iv)
        pt = cipher.decrypt(ct).decode()

    elif mode == 'CTR':
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        pt = cipher.decrypt(ct).decode()

    return pt


def main():
    print("========== AES MODES MENU ==========")
    print("1. ECB")
    print("2. CBC")
    print("3. CFB")
    print("4. OFB")
    print("5. CTR")

    choice = input("Enter choice: ")

    if choice == '1':
        mode = 'ECB'
    elif choice == '2':
        mode = 'CBC'
    elif choice == '3':
        mode = 'CFB'
    elif choice == '4':
        mode = 'OFB'
    elif choice == '5':
        mode = 'CTR'
    else:
        print("Invalid choice.")
        return

    key = input("Enter key (16 characters): ").encode()
    pt = input("Enter plaintext: ")

    if len(key) != 16:
        print("Key must be exactly 16 characters.")
        return

    iv = None

    if mode != 'ECB':
        if mode == 'CTR':
            iv = input("Enter nonce (8 characters): ").encode()

            if len(iv) != 8:
                print("Nonce must be exactly 8 characters.")
                return
        else:
            iv = input("Enter IV (16 characters): ").encode()

            if len(iv) != 16:
                print("IV must be exactly 16 characters.")
                return

    ct = encrypt(pt, key, mode, iv)

    print("\nMode:", mode)
    print("Ciphertext (hex):", ct.hex())

    dpt = decrypt(ct, key, mode, iv)

    print("Decrypted text:", dpt)
    print("Verification:", "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()