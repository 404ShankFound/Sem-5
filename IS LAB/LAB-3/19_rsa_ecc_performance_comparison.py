"""
19. rsa_ecc_performance_comparison

Implement RSA and ECC for secure communication/file transfer; compare
key-generation time, encryption/decryption speed, key sizes, storage overhead
and computational performance.
"""
import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# RSA key generation
def rsa_keygen(size):

    t = time.perf_counter()

    key = RSA.generate(size)

    et = time.perf_counter() - t

    return key, et


# ECC key generation
def ecc_keygen(curve):

    t = time.perf_counter()

    key = ECC.generate(curve=curve)

    et = time.perf_counter() - t

    return key, et


# RSA encryption/decryption
def rsa_test(key, pt):

    cipher = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256)

    t = time.perf_counter()
    ct = cipher.encrypt(pt)
    enc = time.perf_counter() - t

    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)

    t = time.perf_counter()
    dt = cipher.decrypt(ct)
    dec = time.perf_counter() - t

    return enc, dec


# ECC + AES hybrid encryption/decryption
def ecc_test(key, pt):

    # Generate temporary ECC key
    eph = ECC.generate(curve=key.curve)

    # Calculate shared secret
    s = eph.d * key.public_key().pointQ

    # Derive AES key
    k = SHA256.new(int(s.x).to_bytes(32, "big")).digest()

    # Encrypt using AES
    t = time.perf_counter()

    cipher = AES.new(k, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(pt)

    enc = time.perf_counter() - t

    # Decrypt
    t = time.perf_counter()

    cipher = AES.new(k, AES.MODE_EAX, nonce=cipher.nonce)
    dt = cipher.decrypt_and_verify(ct, tag)

    dec = time.perf_counter() - t

    return enc, dec


def key_comparison():

    print("\n========== KEY GENERATION ==========")

    rkey, rt = rsa_keygen(2048)
    ekey, et = ecc_keygen("P-256")

    print("RSA-2048 Key Generation:", rt, "seconds")
    print("ECC-P-256 Key Generation:", et, "seconds")


def encryption_comparison():

    print("\n========== ENCRYPTION / DECRYPTION ==========")

    pt = b"A" * 100

    rkey, rt = rsa_keygen(2048)
    ekey, et = ecc_keygen("P-256")

    re, rd = rsa_test(rkey, pt)
    ee, ed = ecc_test(ekey, pt)

    print("RSA Encryption:", re, "seconds")
    print("RSA Decryption:", rd, "seconds")

    print("\nECC + AES Encryption:", ee, "seconds")
    print("ECC + AES Decryption:", ed, "seconds")


def size_comparison():

    print("\n========== KEY SIZE / STORAGE ==========")

    rkey, rt = rsa_keygen(2048)
    ekey, et = ecc_keygen("P-256")

    # RSA key size in bytes
    rsa_size = len(rkey.export_key())

    # ECC private/public key size in bytes
    ecc_private = len(ekey.export_key(format="PEM"))
    ecc_public = len(ekey.public_key().export_key(format="PEM"))

    print("RSA Key Size: 2048 bits")
    print("RSA Storage:", rsa_size, "bytes")

    print("\nECC Curve: P-256")
    print("ECC Private Key Storage:", ecc_private, "bytes")
    print("ECC Public Key Storage:", ecc_public, "bytes")


def file_transfer():

    print("\n========== FILE TRANSFER ==========")

    sizes = [16, 64, 128, 256]

    rkey, rt = rsa_keygen(2048)
    ekey, et = ecc_keygen("P-256")

    print("RSA Key Generation:", rt, "seconds")
    print("ECC Key Generation:", et, "seconds")

    for size in sizes:

        pt = b"A" * size

        # RSA
        if size <= 190:

            re, rd = rsa_test(rkey, pt)

            print("\nFile Size:", size, "bytes")
            print("RSA Encryption:", re)
            print("RSA Decryption:", rd)

        else:

            print("\nFile Size:", size, "bytes")
            print("RSA: File too large for RSA-OAEP-SHA256")

        # ECC hybrid
        ee, ed = ecc_test(ekey, pt)

        print("ECC + AES Encryption:", ee)
        print("ECC + AES Decryption:", ed)


def main():

    while True:

        print("\n========== RSA vs ECC PERFORMANCE ==========")
        print("1. Compare key-generation time")
        print("2. Compare encryption/decryption speed")
        print("3. Compare key size and storage overhead")
        print("4. Compare file-transfer performance")
        print("5. Run complete comparison")
        print("6. Exit")

        ch = int(input("Enter your choice: "))

        if ch == 1:
            key_comparison()

        elif ch == 2:
            encryption_comparison()

        elif ch == 3:
            size_comparison()

        elif ch == 4:
            file_transfer()

        elif ch == 5:
            key_comparison()
            encryption_comparison()
            size_comparison()
            file_transfer()

        elif ch == 6:
            print("Exiting...")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()