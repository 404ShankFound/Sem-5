"""21. des_aes_mode_key_combination

Given a DES/AES program, modify it to change the algorithm, key size, mode,
plaintext, IV/nonce and encryption/decryption operation according to user
input; validate all parameters and display the corresponding ciphertext and
recovered plaintext.
"""

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key, alg, mode, iv=None):
    if alg == "DES":
        if mode == "ECB":
            cipher = DES.new(key, DES.MODE_ECB)
        else:
            cipher = DES.new(key, DES.MODE_CBC, iv)

        ct = cipher.encrypt(pad(pt.encode(), DES.block_size))

    else:
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
            ct = cipher.encrypt(pad(pt.encode(), AES.block_size))

        elif mode == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ct = cipher.encrypt(pad(pt.encode(), AES.block_size))

        elif mode == "CFB":
            cipher = AES.new(key, AES.MODE_CFB, iv)
            ct = cipher.encrypt(pt.encode())

        elif mode == "OFB":
            cipher = AES.new(key, AES.MODE_OFB, iv)
            ct = cipher.encrypt(pt.encode())

        else:
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
            ct = cipher.encrypt(pt.encode())

    return ct


def decrypt(ct, key, alg, mode, iv=None):
    if alg == "DES":
        if mode == "ECB":
            cipher = DES.new(key, DES.MODE_ECB)
        else:
            cipher = DES.new(key, DES.MODE_CBC, iv)

        pt = unpad(cipher.decrypt(ct), DES.block_size).decode()

    else:
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), AES.block_size).decode()

        elif mode == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size).decode()

        elif mode == "CFB":
            cipher = AES.new(key, AES.MODE_CFB, iv)
            pt = cipher.decrypt(ct).decode()

        elif mode == "OFB":
            cipher = AES.new(key, AES.MODE_OFB, iv)
            pt = cipher.decrypt(ct).decode()

        else:
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
            pt = cipher.decrypt(ct).decode()

    return pt


def main():
    print("========== DES / AES COMBINATION ==========")
    print("1. DES")
    print("2. AES")

    alg = input("Enter algorithm: ")

    if alg == '1':
        alg = "DES"
        key_len = 8

        print("\n1. ECB")
        print("2. CBC")

    elif alg == '2':
        alg = "AES"

        print("\n1. AES-128")
        print("2. AES-192")
        print("3. AES-256")

        ks = input("Enter key size: ")

        if ks == '1':
            key_len = 16
        elif ks == '2':
            key_len = 24
        elif ks == '3':
            key_len = 32
        else:
            print("Invalid key size.")
            return

        print("\n1. ECB")
        print("2. CBC")
        print("3. CFB")
        print("4. OFB")
        print("5. CTR")

    else:
        print("Invalid algorithm.")
        return

    mc = input("Enter mode: ")

    if mc == '1':
        mode = "ECB"
    elif mc == '2':
        mode = "CBC"
    elif mc == '3' and alg == "AES":
        mode = "CFB"
    elif mc == '4' and alg == "AES":
        mode = "OFB"
    elif mc == '5' and alg == "AES":
        mode = "CTR"
    else:
        print("Invalid mode.")
        return

    key = input(f"Enter key ({key_len} characters): ").encode()

    if len(key) != key_len:
        print(f"Key must be exactly {key_len} characters.")
        return

    pt = input("Enter plaintext: ")

    iv = None

    if mode != "ECB":

        if mode == "CTR":
            iv = input("Enter nonce (8 characters): ").encode()

            if len(iv) != 8:
                print("Nonce must be exactly 8 characters.")
                return

        else:
            if alg == "DES":
                iv = input("Enter IV (8 characters): ").encode()

                if len(iv) != 8:
                    print("IV must be exactly 8 characters.")
                    return

            else:
                iv = input("Enter IV (16 characters): ").encode()

                if len(iv) != 16:
                    print("IV must be exactly 16 characters.")
                    return

    print("\n========== ENCRYPTION ==========")

    ct = encrypt(pt, key, alg, mode, iv)

    print("Algorithm:", alg)
    print("Mode:", mode)
    print("Ciphertext (hex):", ct.hex())

    print("\n========== DECRYPTION ==========")

    dpt = decrypt(ct, key, alg, mode, iv)

    print("Recovered plaintext:", dpt)
    print("Verification:",
          "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()

'''
| Algorithm   | Mode | Key |   IV / Nonce | Plaintext |
| ----------- | ---- | --: | -----------: | --------- |
| **DES**     | ECB  |   8 |         None | Any       |
| **DES**     | CBC  |   8 |     **8 IV** | Any       |
| **AES-128** | ECB  |  16 |         None | Any       |
| **AES-128** | CBC  |  16 |    **16 IV** | Any       |
| **AES-128** | CFB  |  16 |    **16 IV** | Any       |
| **AES-128** | OFB  |  16 |    **16 IV** | Any       |
| **AES-128** | CTR  |  16 | **8 nonce*** | Any       |
| **AES-192** | ECB  |  24 |         None | Any       |
| **AES-192** | CBC  |  24 |    **16 IV** | Any       |
| **AES-192** | CFB  |  24 |    **16 IV** | Any       |
| **AES-192** | OFB  |  24 |    **16 IV** | Any       |
| **AES-192** | CTR  |  24 | **8 nonce*** | Any       |
| **AES-256** | ECB  |  32 |         None | Any       |
| **AES-256** | CBC  |  32 |    **16 IV** | Any       |
| **AES-256** | CFB  |  32 |    **16 IV** | Any       |
| **AES-256** | OFB  |  32 |    **16 IV** | Any       |
| **AES-256** | CTR  |  32 | **8 nonce*** | Any       |


Plaintext:
Hello World

DES key:
12345678

AES-128 key:
1234567890123456

AES-192 key:
123456789012345678901234

AES-256 key:
12345678901234567890123456789012

AES/DES IV:
1234567890ABCDEF   ← AES
12345678           ← DES

CTR nonce:
12345678
'''