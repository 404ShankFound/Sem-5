"""Question 27: Rsa different key sizes
Generate RSA keys of 1024, 2048 and 3072 bits; perform encryption/decryption and compare key-generation and execution times.
"""

import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def main():

    # Same plaintext is used for every key size
    msg = input("Enter plaintext: ")
    data = msg.encode()

    # RSA key sizes to compare
    sizes = [1024, 2048, 3072]

    print("\nRSA Performance Comparison")
    print("-" * 60)
    print("Size\tKey Gen\t\tEncryption\tDecryption")

    for size in sizes:

        # --------------------------------------------------
        # KEY GENERATION
        # Generate a new RSA key pair of given size
        # --------------------------------------------------

        t1 = time.perf_counter()

        key = RSA.generate(size)
        pub = key.publickey()

        t2 = time.perf_counter()

        kg = t2 - t1

        # --------------------------------------------------
        # ENCRYPTION
        # Encrypt using the public key
        # --------------------------------------------------

        cipher = PKCS1_OAEP.new(pub)

        t1 = time.perf_counter()

        ct = cipher.encrypt(data)

        t2 = time.perf_counter()

        et = t2 - t1

        # --------------------------------------------------
        # DECRYPTION
        # Decrypt using the private key
        # --------------------------------------------------

        cipher = PKCS1_OAEP.new(key)

        t1 = time.perf_counter()

        pt = cipher.decrypt(ct)

        t2 = time.perf_counter()

        dt = t2 - t1

        # Convert decrypted bytes back to string
        dec = pt.decode()

        # Verify result
        if dec == msg:
            result = "SUCCESS"
        else:
            result = "FAILED"

        # Display timings
        print(f"{size}\t{kg:.6f}s\t{et:.6f}s\t{dt:.6f}s")

        print("Result:", result)


if __name__ == "__main__":
    main()