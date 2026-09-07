"""17. aes_keysize_performance

Encrypt the same messages using AES-128, AES-192 and AES-256; measure
execution time for encryption and decryption; compare the performance of all
three key sizes.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time


def encrypt(pt, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
    return ct


def decrypt(ct, key):
    cipher = AES.new(key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
    return pt


def main():
    print("========== AES KEY SIZE PERFORMANCE ==========")

    pt = input("Enter plaintext: ")

    k128 = input("Enter AES-128 key (16 characters): ").encode()
    k192 = input("Enter AES-192 key (24 characters): ").encode()
    k256 = input("Enter AES-256 key (32 characters): ").encode()

    keys = [
        ("AES-128", k128),
        ("AES-192", k192),
        ("AES-256", k256)
    ]

    for name, key in keys:

        if len(key) not in [16, 24, 32]:
            print(name, "has an invalid key length.")
            continue

        st = time.perf_counter()
        ct = encrypt(pt, key)
        et = time.perf_counter()

        enc_time = et - st

        st = time.perf_counter()
        dpt = decrypt(ct, key)
        et = time.perf_counter()

        dec_time = et - st

        print("\n", name)
        print("Ciphertext (hex):", ct.hex())
        print("Encryption time:", enc_time, "seconds")
        print("Decryption time:", dec_time, "seconds")
        print("Verification:", "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()