"""16. des_aes_comparison

Encrypt and decrypt the same set of messages using DES and AES; measure
encryption/decryption time and compare their performance.
"""

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time


def des_encrypt(pt, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), DES.block_size))
    return ct


def des_decrypt(ct, key):
    cipher = DES.new(key, DES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), DES.block_size).decode()
    return pt


def aes_encrypt(pt, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
    return ct


def aes_decrypt(ct, key):
    cipher = AES.new(key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
    return pt


def main():
    print("========== DES vs AES PERFORMANCE ==========")

    pt = input("Enter plaintext: ")

    dk = input("Enter DES key (8 characters): ").encode()
    ak = input("Enter AES key (16 characters): ").encode()

    if len(dk) != 8:
        print("DES key must be exactly 8 characters.")
        return

    if len(ak) != 16:
        print("AES key must be exactly 16 characters.")
        return

    # DES encryption
    st = time.perf_counter()
    dct = des_encrypt(pt, dk)
    et = time.perf_counter()
    de = et - st

    # DES decryption
    st = time.perf_counter()
    dpt = des_decrypt(dct, dk)
    et = time.perf_counter()
    dd = et - st

    # AES encryption
    st = time.perf_counter()
    act = aes_encrypt(pt, ak)
    et = time.perf_counter()
    ae = et - st

    # AES decryption
    st = time.perf_counter()
    apt = aes_decrypt(act, ak)
    et = time.perf_counter()
    ad = et - st

    print("\n========== RESULTS ==========")

    print("\nDES")
    print("Ciphertext (hex):", dct.hex())
    print("Encryption time:", de, "seconds")
    print("Decryption time:", dd, "seconds")
    print("Verification:", "Successful" if pt == dpt else "Failed")

    print("\nAES")
    print("Ciphertext (hex):", act.hex())
    print("Encryption time:", ae, "seconds")
    print("Decryption time:", ad, "seconds")
    print("Verification:", "Successful" if pt == apt else "Failed")

    print("\n========== COMPARISON ==========")
    print("DES encryption time:", de)
    print("AES encryption time:", ae)
    print("DES decryption time:", dd)
    print("AES decryption time:", ad)


if __name__ == "__main__":
    main()