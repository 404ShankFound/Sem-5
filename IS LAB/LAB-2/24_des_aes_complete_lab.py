"""
24. des_aes_complete_lab

Implement a complete interactive DES/AES system supporting encryption/
decryption, user input, key validation, padding, multiple blocks, DES/AES
variants, modes, IV/nonce, execution-time measurement and performance
comparison.
"""

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time


def encrypt(pt, key, alg, mode, iv=None, nonce=None):
    if alg == "DES":
        if mode == "ECB":
            cipher = DES.new(key, DES.MODE_ECB)
        elif mode == "CBC":
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif mode == "CFB":
            cipher = DES.new(key, DES.MODE_CFB, iv)
        elif mode == "OFB":
            cipher = DES.new(key, DES.MODE_OFB, iv)

    else:
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode == "CFB":
            cipher = AES.new(key, AES.MODE_CFB, iv)
        elif mode == "OFB":
            cipher = AES.new(key, AES.MODE_OFB, iv)
        elif mode == "CTR":
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    if mode in ["ECB", "CBC"]:
        pt = pad(pt, cipher.block_size)

    return cipher.encrypt(pt)


def decrypt(ct, key, alg, mode, iv=None, nonce=None):
    if alg == "DES":
        if mode == "ECB":
            cipher = DES.new(key, DES.MODE_ECB)
        elif mode == "CBC":
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif mode == "CFB":
            cipher = DES.new(key, DES.MODE_CFB, iv)
        elif mode == "OFB":
            cipher = DES.new(key, DES.MODE_OFB, iv)

    else:
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode == "CFB":
            cipher = AES.new(key, AES.MODE_CFB, iv)
        elif mode == "OFB":
            cipher = AES.new(key, AES.MODE_OFB, iv)
        elif mode == "CTR":
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    pt = cipher.decrypt(ct)

    if mode in ["ECB", "CBC"]:
        pt = unpad(pt, cipher.block_size)

    return pt


def main():
    print("========== DES/AES COMPLETE LAB ==========")
    print("1. DES")
    print("2. AES")

    choice = input("Enter algorithm: ")

    if choice == '1':
        alg = "DES"
        key = input("Enter DES key (8 characters): ")

        if len(key) != 8:
            print("Invalid DES key.")
            return

    elif choice == '2':
        alg = "AES"
        print("1. AES-128")
        print("2. AES-192")
        print("3. AES-256")

        v = input("Enter AES variant: ")

        if v == '1':
            key = input("Enter AES-128 key (16 characters): ")
            if len(key) != 16:
                print("Invalid AES key.")
                return
        elif v == '2':
            key = input("Enter AES-192 key (24 characters): ")
            if len(key) != 24:
                print("Invalid AES key.")
                return
        elif v == '3':
            key = input("Enter AES-256 key (32 characters): ")
            if len(key) != 32:
                print("Invalid AES key.")
                return
        else:
            print("Invalid choice.")
            return

    else:
        print("Invalid choice.")
        return

    print("\n========== MODE ==========")

    if alg == "DES":
        print("1. ECB")
        print("2. CBC")
        print("3. CFB")
        print("4. OFB")
    else:
        print("1. ECB")
        print("2. CBC")
        print("3. CFB")
        print("4. OFB")
        print("5. CTR")

    m = input("Enter mode: ")

    modes = {
        '1': "ECB",
        '2': "CBC",
        '3': "CFB",
        '4': "OFB",
        '5': "CTR"
    }

    if m not in modes or (alg == "DES" and m == '5'):
        print("Invalid mode.")
        return

    mode = modes[m]

    iv = None
    nonce = None

    if mode in ["CBC", "CFB", "OFB"]:
        n = 8 if alg == "DES" else 16
        iv = input(f"Enter IV ({n} characters): ").encode()

        if len(iv) != n:
            print("Invalid IV.")
            return

    elif mode == "CTR":
        nonce = input("Enter nonce (8 characters): ").encode()

        if len(nonce) != 8:
            print("Invalid nonce.")
            return

    print("\n========== MULTIPLE BLOCKS ==========")
    n = int(input("Enter number of messages: "))

    pts = []

    for i in range(n):
        pt = input(f"Enter message {i + 1}: ")
        pts.append(pt.encode())

    key = key.encode()

    print("\n========== ENCRYPTION ==========")

    cts = []
    st = time.perf_counter()

    for pt in pts:
        ct = encrypt(pt, key, alg, mode, iv, nonce)
        cts.append(ct)
        print("Ciphertext:", ct.hex())

    et = time.perf_counter() - st

    print("\n========== DECRYPTION ==========")

    dts = []
    st = time.perf_counter()

    for ct in cts:
        dt = decrypt(ct, key, alg, mode, iv, nonce)
        dts.append(dt)
        print("Decrypted:", dt.decode())

    dt = time.perf_counter() - st

    print("\n========== PERFORMANCE ==========")
    print("Encryption time:", et, "seconds")
    print("Decryption time:", dt, "seconds")

    print("\n========== VERIFICATION ==========")

    for i in range(n):
        if pts[i] == dts[i]:
            print(f"Message {i + 1}: Success")
        else:
            print(f"Message {i + 1}: Failed")


if __name__ == "__main__":
    main()


# Sample Input/Output:
#
# ========== DES/AES COMPLETE LAB ==========
# 1. DES
# 2. AES
# Enter algorithm: 1
# Enter DES key (8 characters): 12345678
#
# ========== MODE ==========
# 1. ECB
# 2. CBC
# 3. CFB
# 4. OFB
# Enter mode: 1
#
# ========== MULTIPLE BLOCKS ==========
# Enter number of messages: 2
# Enter message 1: HELLO
# Enter message 2: INFORMATION SECURITY
#
# ========== ENCRYPTION ==========
# Ciphertext: 8A7D5B4B7E5B3C5D
# Ciphertext: ...
#
# ========== DECRYPTION ==========
# Decrypted: HELLO
# Decrypted: INFORMATION SECURITY
#
# ========== PERFORMANCE ==========
# Encryption time: ... seconds
# Decryption time: ... seconds
#
# ========== VERIFICATION ==========
# Message 1: Success
# Message 2: Success