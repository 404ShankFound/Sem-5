"""
Question 78: Complete RSA, ElGamal and ECC Analysis

Using the implementations from the cryptographic system, perform a
comprehensive comparison of RSA, ElGamal and ECC based on key
size/storage overhead, key-generation time, encryption time and
decryption time.

Requirements:
- RSA
- ElGamal
- ECC
- Key-size comparison
- Storage overhead
- Key generation time
- Encryption time
- Decryption time
- Comparison table
- Identify relative strengths/performance

Absorbs: original Q121.
"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, getRandomRange, inverse
import os
import time


def aes_enc(data, key):
    # AES encrypts the actual message
    c = AES.new(key, AES.MODE_EAX)

    ct, tag = c.encrypt_and_digest(data)

    return ct, c.nonce, tag


def aes_dec(ct, nonce, tag, key):
    # AES decrypts and authenticates the message
    c = AES.new(key, AES.MODE_EAX, nonce=nonce)

    pt = c.decrypt(ct)
    c.verify(tag)

    return pt


def rsa_test(data):
    # RSA key generation
    st = time.perf_counter()

    pri = RSA.generate(2048)
    pub = pri.publickey()

    kg = time.perf_counter() - st

    # Generate AES session key
    key = os.urandom(32)

    # RSA encryption + AES encryption
    st = time.perf_counter()

    ek = PKCS1_OAEP.new(pub).encrypt(key)
    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # RSA decryption + AES decryption
    st = time.perf_counter()

    key2 = PKCS1_OAEP.new(pri).decrypt(ek)
    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    # Public key storage size
    pub_size = len(pub.export_key(format="DER"))

    return kg, et, dt, pub_size, pt


def elgamal_test(data):
    # ElGamal key generation
    st = time.perf_counter()

    p = getPrime(512)
    g = 2
    x = getRandomRange(2, p - 2)
    y = pow(g, x, p)

    kg = time.perf_counter() - st

    # Generate AES session key
    key = os.urandom(32)
    m = int.from_bytes(key, "big")

    if m >= p:
        raise ValueError("AES key is too large for ElGamal modulus.")

    # ElGamal encryption + AES encryption
    st = time.perf_counter()

    k = getRandomRange(2, p - 2)

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # ElGamal decryption + AES decryption
    st = time.perf_counter()

    s = pow(c1, x, p)
    m2 = (c2 * inverse(s, p)) % p

    key2 = m2.to_bytes(32, "big")

    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    # Approximate public-key storage
    pub_size = (
        len(str(p).encode()) +
        len(str(g).encode()) +
        len(str(y).encode())
    )

    return kg, et, dt, pub_size, pt


def ecc_test(data):
    # ECC key generation
    st = time.perf_counter()

    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    kg = time.perf_counter() - st

    # ECDH + AES encryption
    st = time.perf_counter()

    s1 = alice.d * bob.public_key().pointQ

    x1 = int(s1.x).to_bytes(32, "big")
    key = SHA256.new(x1).digest()

    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # ECDH + AES decryption
    st = time.perf_counter()

    s2 = bob.d * alice.public_key().pointQ

    x2 = int(s2.x).to_bytes(32, "big")
    key2 = SHA256.new(x2).digest()

    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    # Store ECC public point
    pub = alice.public_key().export_key(format="DER")
    pub_size = len(pub)

    return kg, et, dt, pub_size, pt


def main():
    print("=" * 65)
    print("       COMPLETE RSA, ELGAMAL AND ECC ANALYSIS")
    print("=" * 65)

    msg = input("\nEnter message for comparison: ")

    if not msg:
        print("FAILURE: Message cannot be empty.")
        return

    data = msg.encode()

    print("\nRunning RSA test...")
    rkg, re, rd, rs, rpt = rsa_test(data)

    print("Running ElGamal test...")
    ekg, ee, ed, es, ept = elgamal_test(data)

    print("Running ECC test...")
    ckg, ce, cd, cs, cpt = ecc_test(data)

    print("\n--- Verification ---")

    print(
        "RSA:",
        "SUCCESS" if rpt == data else "FAILURE"
    )

    print(
        "ElGamal:",
        "SUCCESS" if ept == data else "FAILURE"
    )

    print(
        "ECC:",
        "SUCCESS" if cpt == data else "FAILURE"
    )

    print("\n--- Comparison Table ---")

    print(
        "Algorithm\tKey Size\tStorage\tKeyGen\t\tEncrypt\t\tDecrypt"
    )

    print(
        "RSA\t\t2048-bit\t",
        rs,
        "\t",
        f"{rkg:.6f}",
        "\t",
        f"{re:.6f}",
        "\t",
        f"{rd:.6f}"
    )

    print(
        "ElGamal\t\t512-bit\t\t",
        es,
        "\t",
        f"{ekg:.6f}",
        "\t",
        f"{ee:.6f}",
        "\t",
        f"{ed:.6f}"
    )

    print(
        "ECC\t\t256-bit\t\t",
        cs,
        "\t",
        f"{ckg:.6f}",
        "\t",
        f"{ce:.6f}",
        "\t",
        f"{cd:.6f}"
    )

    print("\n--- Analysis ---")

    kg = {
        "RSA": rkg,
        "ElGamal": ekg,
        "ECC": ckg
    }

    enc = {
        "RSA": re,
        "ElGamal": ee,
        "ECC": ce
    }

    dec = {
        "RSA": rd,
        "ElGamal": ed,
        "ECC": cd
    }

    storage = {
        "RSA": rs,
        "ElGamal": es,
        "ECC": cs
    }

    print(
        "Fastest Key Generation:",
        min(kg, key=kg.get)
    )

    print(
        "Fastest Encryption:",
        min(enc, key=enc.get)
    )

    print(
        "Fastest Decryption:",
        min(dec, key=dec.get)
    )

    print(
        "Lowest Storage:",
        min(storage, key=storage.get)
    )

    print("\n--- Relative Strengths ---")

    print("RSA:")
    print("- Widely used and mature.")
    print("- Larger keys provide strong security.")
    print("- Higher key/storage overhead than ECC.")

    print("\nElGamal:")
    print("- Probabilistic encryption using random k.")
    print("- Ciphertext/key representation is relatively large.")
    print("- Useful for studying discrete-log based cryptography.")

    print("\nECC:")
    print("- Provides strong security with smaller keys.")
    print("- Lower key/storage overhead.")
    print("- ECDH is well suited for hybrid encryption.")

    print("\n--- Final Result ---")

    total = {
        "RSA": re + rd,
        "ElGamal": ee + ed,
        "ECC": ce + cd
    }

    print(
        "Lowest total encryption/decryption time:",
        min(total, key=total.get)
    )


if __name__ == "__main__":
    main()