"""18. mode_performance_comparison

Encrypt the same messages using different DES/AES modes; measure execution
time for each mode; compare the results and optionally plot a performance
graph.
"""

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
import time


def des_ecb(pt, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(pt.encode(), DES.block_size))


def des_cbc(pt, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(pt.encode(), DES.block_size))


def aes_ecb(pt, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(pt.encode(), AES.block_size))


def aes_cbc(pt, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(pt.encode(), AES.block_size))


def aes_cfb(pt, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.encrypt(pt.encode())


def aes_ofb(pt, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(pt.encode())


def aes_ctr(pt, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(pt.encode())


def main():
    print("========== MODE PERFORMANCE COMPARISON ==========")

    pt = input("Enter plaintext: ")

    dk = input("Enter DES key (8 characters): ").encode()
    div = input("Enter DES IV (8 characters): ").encode()

    ak = input("Enter AES key (16 characters): ").encode()
    aiv = input("Enter AES IV (16 characters): ").encode()
    nonce = input("Enter AES nonce (8 characters): ").encode()

    if len(dk) != 8 or len(div) != 8:
        print("DES key and IV must be exactly 8 characters.")
        return

    if len(ak) != 16 or len(aiv) != 16:
        print("AES key must be 16 characters and IV must be 16 characters.")
        return

    if len(nonce) != 8:
        print("Nonce must be exactly 8 characters.")
        return

    modes = [
        ("DES-ECB", lambda: des_ecb(pt, dk)),
        ("DES-CBC", lambda: des_cbc(pt, dk, div)),
        ("AES-ECB", lambda: aes_ecb(pt, ak)),
        ("AES-CBC", lambda: aes_cbc(pt, ak, aiv)),
        ("AES-CFB", lambda: aes_cfb(pt, ak, aiv)),
        ("AES-OFB", lambda: aes_ofb(pt, ak, aiv)),
        ("AES-CTR", lambda: aes_ctr(pt, ak, nonce))
    ]

    print("\n========== RESULTS ==========")

    for name, func in modes:

        st = time.perf_counter()
        ct = func()
        et = time.perf_counter()

        t = et - st

        print("\n", name)
        print("Ciphertext (hex):", ct.hex())
        print("Encryption time:", t, "seconds")


if __name__ == "__main__":
    main()