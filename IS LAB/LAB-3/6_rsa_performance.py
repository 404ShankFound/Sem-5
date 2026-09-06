"""
6. rsa_performance

Measure RSA key-generation, encryption and decryption time for different
message sizes; display and compare the results.
"""

# %%
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def main():
    # Different message sizes to test.
    # These are in bytes.

    sizes = [16, 64, 128, 190]

    print("RSA Performance")
    print("-" * 65)
    print(f"{'Size':<10}{'Key Gen':<15}{'Encryption':<15}{'Decryption':<15}")

    # Test RSA for each message size.
    for size in sizes:

        # Generate a new RSA key pair.
        # 2048 is the RSA key size in bits.
        t1 = time.perf_counter()
        key = RSA.generate(2048)
        pub = key.publickey()
        t2 = time.perf_counter()

        # Calculate key-generation time.
        kg = t2 - t1

        # Generate a message of the required size.
        # b"A" is repeated 'size' times.
        data = b"A" * size  
        # Create RSA encryption object using the public key.
        cipher = PKCS1_OAEP.new(pub)

        # Measure encryption time.
        t1 = time.perf_counter()
        ct = cipher.encrypt(data)
        t2 = time.perf_counter()

        et = t2 - t1

        # Create RSA decryption object using the private key.
        cipher = PKCS1_OAEP.new(key)

        # Measure decryption time.
        t1 = time.perf_counter()
        pt = cipher.decrypt(ct)
        t2 = time.perf_counter()

        dt = t2 - t1

        # Verify that decryption produced the original message.
        if pt == data:
            print(f"{size:<10}{kg:<15.6f}{et:<15.6f}{dt:<15.6f}")
        else:
            print("Decryption failed.")


if __name__ == "__main__":
    main()