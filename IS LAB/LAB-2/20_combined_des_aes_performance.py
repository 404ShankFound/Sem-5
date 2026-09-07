"""20. combined_des_aes_performance

Build a single program that takes multiple messages, encrypts/decrypts them
using DES, AES-128, AES-192 and AES-256, optionally uses different modes,
measures encryption/decryption time and presents a comparison/graph.
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
    print("========== DES / AES PERFORMANCE ==========")

    dk = input("Enter DES key (8 characters): ").encode()
    k128 = input("Enter AES-128 key (16 characters): ").encode()
    k192 = input("Enter AES-192 key (24 characters): ").encode()
    k256 = input("Enter AES-256 key (32 characters): ").encode()

    if len(dk) != 8:
        print("DES key must be exactly 8 characters.")
        return

    if len(k128) != 16:
        print("AES-128 key must be exactly 16 characters.")
        return

    if len(k192) != 24:
        print("AES-192 key must be exactly 24 characters.")
        return

    if len(k256) != 32:
        print("AES-256 key must be exactly 32 characters.")
        return

    msg = []

    for i in range(5):
        pt = input(f"Enter message {i + 1}: ")
        msg.append(pt)

    algos = [
        ("DES", dk),
        ("AES-128", k128),
        ("AES-192", k192),
        ("AES-256", k256)
    ]

    print("\n========== RESULTS ==========")

    for name, key in algos:

        te = 0
        td = 0

        for pt in msg:

            if name == "DES":
                st = time.perf_counter()
                ct = des_encrypt(pt, key)
                et = time.perf_counter()
                te += et - st

                st = time.perf_counter()
                dpt = des_decrypt(ct, key)
                et = time.perf_counter()
                td += et - st

            else:
                st = time.perf_counter()
                ct = aes_encrypt(pt, key)
                et = time.perf_counter()
                te += et - st

                st = time.perf_counter()
                dpt = aes_decrypt(ct, key)
                et = time.perf_counter()
                td += et - st

        print("\n", name)
        print("Total encryption time:", te, "seconds")
        print("Total decryption time:", td, "seconds")


if __name__ == "__main__":
    main()