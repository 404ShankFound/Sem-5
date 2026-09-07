"""9. des_performance

Measure DES encryption time and decryption time for one or multiple messages/
blocks; display the execution time and optionally compare different DES modes.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import time


def encrypt(pt, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), DES.block_size))
    return ct


def decrypt(ct, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), DES.block_size).decode()
    return pt


def main():
    print("========== DES PERFORMANCE ==========")

    key = input("Enter key (8 characters): ")
    pt = input("Enter plaintext: ")

    if len(key) != 8:
        print("Key must be exactly 8 characters.")
        return

    st = time.perf_counter()
    ct = encrypt(pt, key)
    et = time.perf_counter()

    enc_time = et - st

    st = time.perf_counter()
    dpt = decrypt(ct, key)
    et = time.perf_counter()

    dec_time = et - st

    print("\nCiphertext (hex):", ct.hex())
    print("Decrypted text:", dpt)

    print("\nEncryption time:", enc_time, "seconds")
    print("Decryption time:", dec_time, "seconds")

    print("Verification:", "Successful" if pt == dpt else "Failed")


if __name__ == "__main__":
    main()