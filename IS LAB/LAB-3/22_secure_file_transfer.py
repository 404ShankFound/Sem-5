"""
22. secure_file_transfer

Build a secure file-transfer program using RSA and ECC; generate/exchange
keys, encrypt/decrypt files of different sizes and measure key-generation,
encryption/decryption time and overhead.
"""

import time
import os

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# RSA key generation
def rsa_keygen():

    t = time.perf_counter()

    key = RSA.generate(2048)

    et = time.perf_counter() - t

    return key, et


# ECC key generation
def ecc_keygen():

    t = time.perf_counter()

    alice = ECC.generate(curve="P-256")
    bob = ECC.generate(curve="P-256")

    et = time.perf_counter() - t

    return alice, bob, et


# RSA secure file transfer
def rsa_transfer(data):

    key, key_time = rsa_keygen()

    # Generate AES session key
    aes_key = get_random_bytes(32)

    # RSA encrypts AES key
    t = time.perf_counter()

    cipher_rsa = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256)
    enc_key = cipher_rsa.encrypt(aes_key)

    # AES encrypts file
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ct, tag = cipher_aes.encrypt_and_digest(data)

    enc_time = time.perf_counter() - t

    # RSA decrypt AES key
    t = time.perf_counter()

    cipher_rsa = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    dec_key = cipher_rsa.decrypt(enc_key)

    # AES decrypt file
    cipher_aes = AES.new(
        dec_key,
        AES.MODE_EAX,
        nonce=cipher_aes.nonce
    )

    pt = cipher_aes.decrypt_and_verify(ct, tag)

    dec_time = time.perf_counter() - t

    # Total transmitted data
    overhead = len(enc_key) + len(cipher_aes.nonce) + len(tag)

    return key_time, enc_time, dec_time, overhead, pt == data


# ECC secure file transfer
def ecc_transfer(data):

    # Generate receiver key
    receiver, sender, key_time = ecc_keygen()

    # Generate temporary sender key
    t = time.perf_counter()

    eph = ECC.generate(curve="P-256")

    # Sender calculates shared secret
    s = eph.d * receiver.public_key().pointQ

    # Derive AES key
    aes_key = SHA256.new(
        int(s.x).to_bytes(32, "big")
    ).digest()

    # Encrypt file using AES
    cipher = AES.new(aes_key, AES.MODE_EAX)

    ct, tag = cipher.encrypt_and_digest(data)

    enc_time = time.perf_counter() - t

    # Receiver calculates same shared secret
    t = time.perf_counter()

    s2 = receiver.d * eph.public_key().pointQ

    aes_key2 = SHA256.new(
        int(s2.x).to_bytes(32, "big")
    ).digest()

    # Decrypt file
    cipher2 = AES.new(
        aes_key2,
        AES.MODE_EAX,
        nonce=cipher.nonce
    )

    pt = cipher2.decrypt_and_verify(ct, tag)

    dec_time = time.perf_counter() - t

    # ECC public key coordinates + nonce + authentication tag
    eph_pub = eph.public_key().export_key(format="DER")

    overhead = len(eph_pub) + len(cipher.nonce) + len(tag)

    return key_time, enc_time, dec_time, overhead, pt == data


def rsa_test():

    print("\n========== RSA SECURE FILE TRANSFER ==========")

    sizes = [16, 64, 128, 256, 512, 1024]

    for size in sizes:

        data = os.urandom(size)

        kt, et, dt, ov, ok = rsa_transfer(data)

        print("\nFile Size:", size, "bytes")
        print("Key Generation:", kt, "seconds")
        print("Encryption:", et, "seconds")
        print("Decryption:", dt, "seconds")
        print("Overhead:", ov, "bytes")
        print("Verified:", ok)


def ecc_test():

    print("\n========== ECC SECURE FILE TRANSFER ==========")

    sizes = [16, 64, 128, 256, 512, 1024]

    for size in sizes:

        data = os.urandom(size)

        kt, et, dt, ov, ok = ecc_transfer(data)

        print("\nFile Size:", size, "bytes")
        print("Key Generation:", kt, "seconds")
        print("Encryption:", et, "seconds")
        print("Decryption:", dt, "seconds")
        print("Overhead:", ov, "bytes")
        print("Verified:", ok)


def comparison():

    print("\n========== RSA vs ECC FILE TRANSFER ==========")

    sizes = [16, 64, 128, 256, 512, 1024]

    for size in sizes:

        data = os.urandom(size)

        rk, re, rd, ro, rok = rsa_transfer(data)
        ek, ee, ed, eo, eok = ecc_transfer(data)

        print("\nFile Size:", size, "bytes")

        print("\nRSA:")
        print("Key Generation:", rk)
        print("Encryption:", re)
        print("Decryption:", rd)
        print("Overhead:", ro)
        print("Verified:", rok)

        print("\nECC:")
        print("Key Generation:", ek)
        print("Encryption:", ee)
        print("Decryption:", ed)
        print("Overhead:", eo)
        print("Verified:", eok)


def main():

    while True:

        print("\n========== SECURE FILE TRANSFER ==========")
        print("1. RSA file transfer")
        print("2. ECC file transfer")
        print("3. Compare RSA and ECC")
        print("4. Exit")

        ch = int(input("Enter your choice: "))

        if ch == 1:
            rsa_test()

        elif ch == 2:
            ecc_test()

        elif ch == 3:
            comparison()

        elif ch == 4:
            print("Exiting...")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()