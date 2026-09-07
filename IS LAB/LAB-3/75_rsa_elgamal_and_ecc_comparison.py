"""
Question 75: RSA, ElGamal and ECC Comparison

Implement RSA, ElGamal and ECC-based encryption/decryption for common input data and compare their key-generation, encryption and decryption performance.

Menu:
1. Compare All Algorithms
2. Pairwise Comparison
3. Multiple Messages
4. Different Message Sizes
5. Key and Storage Size Comparison
6. Algorithm Suitability
7. Exit

Requirements:
- RSA
- ElGamal
- ECC hybrid encryption
- Same input message
- Multiple messages
- Different message sizes
- Key-generation timing
- Encryption timing
- Decryption timing
- Key/storage-size comparison
- Pairwise comparison
- Three-way comparison
- Determine suitable algorithm for different message sizes

Absorbs: original Q103–108.
"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, getRandomRange, inverse
import os
import time


def aes_enc(data, key):
    # AES-EAX encrypts the actual message
    c = AES.new(key, AES.MODE_EAX)

    ct, tag = c.encrypt_and_digest(data)

    return ct, c.nonce, tag


def aes_dec(ct, nonce, tag, key):
    # AES-EAX decrypts and authenticates the message
    c = AES.new(key, AES.MODE_EAX, nonce=nonce)

    pt = c.decrypt(ct)

    c.verify(tag)

    return pt


def rsa_setup():
    # Generate RSA-2048 key pair and measure key generation
    st = time.perf_counter()

    pri = RSA.generate(2048)
    pub = pri.publickey()

    kt = time.perf_counter() - st

    return pub, pri, kt


def elgamal_setup():
    # Generate ElGamal parameters and private/public key
    st = time.perf_counter()

    p = getPrime(512)
    g = 2
    x = getRandomRange(2, p - 2)
    y = pow(g, x, p)

    kt = time.perf_counter() - st

    return p, g, x, y, kt


def ecc_setup():
    # Generate ECC P-256 key pairs
    st = time.perf_counter()

    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    kt = time.perf_counter() - st

    return alice, bob, kt


def rsa_test(data, pub, pri):
    # Generate AES session key
    key = os.urandom(32)

    # RSA protects the AES key
    st = time.perf_counter()

    ek = PKCS1_OAEP.new(pub).encrypt(key)

    # AES encrypts actual data
    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # RSA decrypts the AES key
    st = time.perf_counter()

    key2 = PKCS1_OAEP.new(pri).decrypt(ek)

    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return et, dt, pt


def elgamal_test(data, p, g, x, y):
    # Generate AES session key
    key = os.urandom(32)

    # Convert AES key to integer
    m = int.from_bytes(key, "big")

    if m >= p:
        raise ValueError("AES key is too large for ElGamal modulus.")

    # ElGamal protects the AES key
    st = time.perf_counter()

    k = getRandomRange(2, p - 2)

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    # AES encrypts actual data
    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # ElGamal decrypts the AES key
    st = time.perf_counter()

    s = pow(c1, x, p)
    m2 = (c2 * inverse(s, p)) % p

    key2 = m2.to_bytes(32, "big")

    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return et, dt, pt


def ecc_test(data, alice, bob):
    # ECDH derives the AES key
    st = time.perf_counter()

    s1 = alice.d * bob.public_key().pointQ

    x1 = int(s1.x).to_bytes(32, "big")
    key = SHA256.new(x1).digest()

    # AES encrypts actual data
    ct, nonce, tag = aes_enc(data, key)

    et = time.perf_counter() - st

    # ECDH derives the same AES key
    st = time.perf_counter()

    s2 = bob.d * alice.public_key().pointQ

    x2 = int(s2.x).to_bytes(32, "big")
    key2 = SHA256.new(x2).digest()

    pt = aes_dec(ct, nonce, tag, key2)

    dt = time.perf_counter() - st

    return et, dt, pt


def generate_keys():
    print("\nGenerating RSA keys...")
    rsa_pub, rsa_pri, rsa_kt = rsa_setup()

    print("Generating ElGamal keys...")
    ep, eg, ex, ey, elg_kt = elgamal_setup()

    print("Generating ECC keys...")
    alice, bob, ecc_kt = ecc_setup()

    return (
        rsa_pub, rsa_pri, rsa_kt,
        ep, eg, ex, ey, elg_kt,
        alice, bob, ecc_kt
    )


def all_comparison():
    data = input("\nEnter message: ")

    if not data:
        print("Error: Message cannot be empty.")
        return

    data = data.encode()

    keys = generate_keys()

    (
        rsa_pub, rsa_pri, rsa_kt,
        p, g, x, y, elg_kt,
        alice, bob, ecc_kt
    ) = keys

    re, rd, rpt = rsa_test(data, rsa_pub, rsa_pri)
    ee, ed, ept = elgamal_test(data, p, g, x, y)
    ce, cd, cpt = ecc_test(data, alice, bob)

    print("\n--- Three-Way Comparison ---")
    print("Algorithm\tKey Gen\t\tEncrypt\t\tDecrypt")

    print(
        "RSA\t\t",
        f"{rsa_kt:.6f}",
        "\t",
        f"{re:.6f}",
        "\t",
        f"{rd:.6f}"
    )

    print(
        "ElGamal\t\t",
        f"{elg_kt:.6f}",
        "\t",
        f"{ee:.6f}",
        "\t",
        f"{ed:.6f}"
    )

    print(
        "ECC\t\t",
        f"{ecc_kt:.6f}",
        "\t",
        f"{ce:.6f}",
        "\t",
        f"{cd:.6f}"
    )

    print("\nVerification:")
    print("RSA:", "SUCCESS" if rpt == data else "FAILURE")
    print("ElGamal:", "SUCCESS" if ept == data else "FAILURE")
    print("ECC:", "SUCCESS" if cpt == data else "FAILURE")


def pairwise():
    data = input("\nEnter message: ")

    if not data:
        print("Error: Message cannot be empty.")
        return

    data = data.encode()

    print("\n--- Pairwise Comparison ---")
    print("1. RSA vs ElGamal")
    print("2. RSA vs ECC")
    print("3. ElGamal vs ECC")

    ch = input("Enter choice: ")

    keys = generate_keys()

    (
        rsa_pub, rsa_pri, rsa_kt,
        p, g, x, y, elg_kt,
        alice, bob, ecc_kt
    ) = keys

    if ch == "1":
        re, rd, rdata = rsa_test(data, rsa_pub, rsa_pri)
        ee, ed, edata = elgamal_test(data, p, g, x, y)

        print("\nRSA vs ElGamal")
        print("RSA Total:", f"{re + rd:.6f}")
        print("ElGamal Total:", f"{ee + ed:.6f}")

        if re + rd < ee + ed:
            print("Faster: RSA")
        else:
            print("Faster: ElGamal")

    elif ch == "2":
        re, rd, rdata = rsa_test(data, rsa_pub, rsa_pri)
        ce, cd, cdata = ecc_test(data, alice, bob)

        print("\nRSA vs ECC")
        print("RSA Total:", f"{re + rd:.6f}")
        print("ECC Total:", f"{ce + cd:.6f}")

        if re + rd < ce + cd:
            print("Faster: RSA")
        else:
            print("Faster: ECC")

    elif ch == "3":
        ee, ed, edata = elgamal_test(data, p, g, x, y)
        ce, cd, cdata = ecc_test(data, alice, bob)

        print("\nElGamal vs ECC")
        print("ElGamal Total:", f"{ee + ed:.6f}")
        print("ECC Total:", f"{ce + cd:.6f}")

        if ee + ed < ce + cd:
            print("Faster: ElGamal")
        else:
            print("Faster: ECC")

    else:
        print("Error: Invalid choice.")


def multiple_messages():
    print("\n--- Multiple Messages ---")

    msgs = input("Enter messages separated by |: ").split("|")

    keys = generate_keys()

    (
        rsa_pub, rsa_pri, rsa_kt,
        p, g, x, y, elg_kt,
        alice, bob, ecc_kt
    ) = keys

    for i, msg in enumerate(msgs, 1):
        if not msg:
            print("Message", i, ": FAILURE - Empty message")
            continue

        data = msg.encode()

        _, _, r = rsa_test(data, rsa_pub, rsa_pri)
        _, _, e = elgamal_test(data, p, g, x, y)
        _, _, c = ecc_test(data, alice, bob)

        print(
            "Message", i,
            "RSA:", "OK" if r == data else "FAIL",
            "ElGamal:", "OK" if e == data else "FAIL",
            "ECC:", "OK" if c == data else "FAIL"
        )


def message_sizes():
    # Test several message sizes
    sizes = [16, 64, 256, 1024, 4096]

    keys = generate_keys()

    (
        rsa_pub, rsa_pri, rsa_kt,
        p, g, x, y, elg_kt,
        alice, bob, ecc_kt
    ) = keys

    print("\n--- Different Message Sizes ---")
    print("Size\tRSA\t\tElGamal\t\tECC")

    for size in sizes:
        data = b"A" * size

        re, rd, r = rsa_test(data, rsa_pub, rsa_pri)
        ee, ed, e = elgamal_test(data, p, g, x, y)
        ce, cd, c = ecc_test(data, alice, bob)

        print(
            size,
            "\t",
            f"{re + rd:.6f}",
            "\t",
            f"{ee + ed:.6f}",
            "\t",
            f"{ce + cd:.6f}"
        )


def key_storage():
    print("\n--- Key / Storage Size Comparison ---")

    rsa_pub, rsa_pri, _ = rsa_setup()
    p, g, x, y, _ = elgamal_setup()
    alice, bob, _ = ecc_setup()

    rsa_size = len(rsa_pub.export_key())
    elg_size = len(str(p).encode()) + len(str(g).encode()) + len(str(y).encode())
    ecc_size = len(str(alice.public_key().pointQ.x).encode()) + \
               len(str(alice.public_key().pointQ.y).encode())

    print("RSA public key size:", rsa_size, "bytes")
    print("ElGamal public key values:", elg_size, "bytes")
    print("ECC public key values:", ecc_size, "bytes")

    print("\nNominal security/key sizes:")
    print("RSA  : 2048 bits")
    print("ElGamal: 512-bit modulus")
    print("ECC  : P-256")


def suitability():
    print("\n--- Algorithm Suitability ---")

    print("\nSmall messages:")
    print("RSA is convenient for small data/key protection.")

    print("\nLarge messages:")
    print("ECC + AES or RSA + AES hybrid encryption is suitable.")

    print("\nLow key/storage overhead:")
    print("ECC is generally preferred because it provides strong security with smaller keys.")

    print("\nSimple public-key encryption:")
    print("RSA is widely used and straightforward to implement with OAEP.")

    print("\nEducational ElGamal:")
    print("ElGamal demonstrates randomized public-key encryption and is useful for studying discrete-log based cryptography.")


def main():
    print("--- RSA, ElGamal and ECC Comparison ---")

    while True:
        print("\n--- Menu ---")
        print("1. Compare All Algorithms")
        print("2. Pairwise Comparison")
        print("3. Multiple Messages")
        print("4. Different Message Sizes")
        print("5. Key and Storage Size Comparison")
        print("6. Algorithm Suitability")
        print("7. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            all_comparison()

        elif ch == "2":
            pairwise()

        elif ch == "3":
            multiple_messages()

        elif ch == "4":
            message_sizes()

        elif ch == "5":
            key_storage()

        elif ch == "6":
            suitability()

        elif ch == "7":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()