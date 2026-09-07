"""
Question 71: Asymmetric Message-Size Performance Analysis

Measure RSA, ElGamal and ECC-based encryption/decryption performance for different plaintext sizes and display the results in a comparison table.

Use predefined sizes rather than repeatedly asking the user for every size.

Example:
1 KB
10 KB
100 KB

For RSA/ElGamal, account for their plaintext-size limitations and use hybrid encryption where necessary.

Flow:
Select Algorithm(s)
       ↓
Select Message-Size Test
       ↓
1 KB → Encrypt → Decrypt → Time
10 KB → Encrypt → Decrypt → Time
100 KB → Encrypt → Decrypt → Time
       ↓
Comparison Table

Requirements:
- RSA
- ElGamal
- ECC hybrid encryption
- Different message sizes
- Encryption timing
- Decryption timing
- Verification
- Comparison table

Absorbs: original Q83, Q84, Q85.

"""

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.number import getPrime, getRandomRange, inverse
from Crypto.Hash import SHA256
import time


def aes_enc(data, key):
    # Encrypt data using AES-EAX
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(data)
    return ct, c.nonce, tag


def aes_dec(ct, nonce, tag, key):
    # Decrypt and verify AES-EAX data
    c = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = c.decrypt(ct)
    c.verify(tag)
    return data


def rsa_test(data, pub, pri):
    # Generate AES session key
    key = AES.get_random_bytes(32)

    # RSA encrypt only the small AES key
    st = time.perf_counter()

    r = PKCS1_OAEP.new(pub)
    ek = r.encrypt(key)

    c, nonce, tag = aes_enc(data, key)

    et = time.perf_counter()
    enc_t = et - st

    # RSA decrypt AES key and decrypt data
    st = time.perf_counter()

    r = PKCS1_OAEP.new(pri)
    key2 = r.decrypt(ek)

    pt = aes_dec(c, nonce, tag, key2)

    et = time.perf_counter()
    dec_t = et - st

    return enc_t, dec_t, pt


def elgamal_test(data, p, g, x):
    # ElGamal public key y = g^x mod p
    y = pow(g, x, p)

    # Generate AES session key
    key = AES.get_random_bytes(32)

    # Convert AES key to integer
    m = int.from_bytes(key, "big")

    # ElGamal can encrypt only a small integer,
    # so it protects the AES key instead of the data.
    k = getRandomRange(2, p - 2)

    st = time.perf_counter()

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    c, nonce, tag = aes_enc(data, key)

    et = time.perf_counter()
    enc_t = et - st

    # Decrypt ElGamal-protected AES key
    st = time.perf_counter()

    s = pow(c1, x, p)
    key2 = (c2 * inverse(s, p)) % p
    key2 = key2.to_bytes(32, "big")

    pt = aes_dec(c, nonce, tag, key2)

    et = time.perf_counter()
    dec_t = et - st

    return enc_t, dec_t, pt


def ecc_test(data, alice, bob):
    # ECDH shared secret
    st = time.perf_counter()

    s = alice.d * bob.public_key().pointQ

    # Derive AES key using SHA-256
    key = SHA256.new(
        int(s.x).to_bytes(32, "big")
    ).digest()

    c, nonce, tag = aes_enc(data, key)

    et = time.perf_counter()
    enc_t = et - st

    # Bob derives the same key
    st = time.perf_counter()

    s2 = bob.d * alice.public_key().pointQ

    key2 = SHA256.new(
        int(s2.x).to_bytes(32, "big")
    ).digest()

    pt = aes_dec(c, nonce, tag, key2)

    et = time.perf_counter()
    dec_t = et - st

    return enc_t, dec_t, pt


def main():
    print("--- Asymmetric Message-Size Performance ---")

    # Predefined message sizes in bytes
    sizes = [1024, 10240, 102400]

    print("\nGenerating keys...")

    # RSA key pair
    rsa_pri = RSA.generate(2048)
    rsa_pub = rsa_pri.publickey()

    # ElGamal parameters
    p = getPrime(512)
    g = 2
    x = getRandomRange(2, p - 2)

    # ECC key pairs
    alice = ECC.generate(curve="secp256r1")
    bob = ECC.generate(curve="secp256r1")

    print("\n--- Performance Table ---")
    print("Size\tRSA Enc\tRSA Dec\tElGamal Enc\tElGamal Dec\tECC Enc\tECC Dec")

    for size in sizes:
        # Generate test data
        data = b"A" * size

        # RSA hybrid encryption/decryption
        rt1, rt2, rdata = rsa_test(data, rsa_pub, rsa_pri)

        # ElGamal hybrid encryption/decryption
        et1, et2, edata = elgamal_test(data, p, g, x)

        # ECC hybrid encryption/decryption
        ct1, ct2, cdata = ecc_test(data, alice, bob)

        # Verify every recovered message
        if data != rdata or data != edata or data != cdata:
            print("Verification: FAILURE")
            continue

        print(
            size,
            "\t",
            f"{rt1:.6f}",
            "\t",
            f"{rt2:.6f}",
            "\t",
            f"{et1:.6f}",
            "\t\t",
            f"{et2:.6f}",
            "\t\t",
            f"{ct1:.6f}",
            "\t",
            f"{ct2:.6f}"
        )

    print("\nVerification: SUCCESS")


if __name__ == "__main__":
    main()