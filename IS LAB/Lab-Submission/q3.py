import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad


def performance_menu():
    print("========== PERFORMANCE BENCHMARK MENU ==========")
    des_key_input = input("Enter 8-character DES key (default 'A1B2C3D4'): ")
    des_key = des_key_input.encode() if des_key_input else b"A1B2C3D4"

    aes_key_input = input("Enter 32-character AES-256 key (default '0123456789ABCDEF0123456789ABCDEF'): ")
    aes_key = aes_key_input.encode() if aes_key_input else b"0123456789ABCDEF0123456789ABCDEF"

    while True:
        print("\n========== MENU ==========")
        print("1. Compare DES Encryption/Decryption Time")
        print("2. Compare AES-256 Encryption/Decryption Time")
        print("3. Run Both & Compare Performance")
        print("4. Exit")

        choice = input("Enter choice: ").strip()

        if choice == '1':
            message = input("Enter plaintext for DES: ")
            print("\n--- DES PERFORMANCE TEST ---")

            # DES Padding (8 bytes block size)
            block_size = DES.block_size
            pad_len = block_size - (len(message.encode()) % block_size)
            padded_msg = message.encode() + b'\x00' * pad_len

            # Timing Encryption
            start_time = time.perf_counter()
            cipher_des = DES.new(des_key, DES.MODE_ECB)
            ciphertext = cipher_des.encrypt(padded_msg)
            end_time = time.perf_counter()
            des_enc_time = (end_time - start_time) * 1000  # in milliseconds

            # Timing Decryption
            start_time = time.perf_counter()
            decipher_des = DES.new(des_key, DES.MODE_ECB)
            decrypted_padded = decipher_des.decrypt(ciphertext)
            end_time = time.perf_counter()
            des_dec_time = (end_time - start_time) * 1000

            print(f"Ciphertext (Hex) : {ciphertext.hex()}")
            print(f"Encryption Time  : {des_enc_time:.6f} ms")
            print(f"Decryption Time  : {des_dec_time:.6f} ms")

        elif choice == '2':
            message = input("Enter plaintext for AES-256: ")
            print("\n--- AES-256 PERFORMANCE TEST ---")

            # AES Padding (16 bytes block size)
            padded_msg = pad(message.encode(), AES.block_size)

            # Timing Encryption
            start_time = time.perf_counter()
            cipher_aes = AES.new(aes_key, AES.MODE_ECB)
            ciphertext = cipher_aes.encrypt(padded_msg)
            end_time = time.perf_counter()
            aes_enc_time = (end_time - start_time) * 1000

            # Timing Decryption
            start_time = time.perf_counter()
            decipher_aes = AES.new(aes_key, AES.MODE_ECB)
            decrypted_padded = decipher_aes.decrypt(ciphertext)
            end_time = time.perf_counter()
            aes_dec_time = (end_time - start_time) * 1000

            print(f"Ciphertext (Hex) : {ciphertext.hex()}")
            print(f"Encryption Time  : {aes_enc_time:.6f} ms")
            print(f"Decryption Time  : {aes_dec_time:.6f} ms")

        elif choice == '3':
            message = input("Enter plaintext for benchmark (default 'Performance Testing of Encryption Algorithms'): ")
            if not message:
                message = "Performance Testing of Encryption Algorithms"

            print("\n================ INPUT ================")
            print(f"Message         : {message}")
            print(f"Message Length  : {len(message.encode())} bytes\n")

            # --- DES Test ---
            des_pad_len = DES.block_size - (len(message.encode()) % DES.block_size)
            des_padded = message.encode() + b'\x00' * des_pad_len

            # DES Encrypt
            t0 = time.perf_counter()
            c_des = DES.new(des_key, DES.MODE_ECB).encrypt(des_padded)
            t1 = time.perf_counter()
            des_enc = (t1 - t0) * 1000

            # DES Decrypt
            t0 = time.perf_counter()
            DES.new(des_key, DES.MODE_ECB).decrypt(c_des)
            t1 = time.perf_counter()
            des_dec = (t1 - t0) * 1000

            # --- AES-256 Test ---
            aes_padded = pad(message.encode(), AES.block_size)

            # AES Encrypt
            t0 = time.perf_counter()
            c_aes = AES.new(aes_key, AES.MODE_ECB).encrypt(aes_padded)
            t1 = time.perf_counter()
            aes_enc = (t1 - t0) * 1000

            # AES Decrypt
            t0 = time.perf_counter()
            AES.new(aes_key, AES.MODE_ECB).decrypt(c_aes)
            t1 = time.perf_counter()
            aes_dec = (t1 - t0) * 1000

            print("================ RESULTS ================")
            print(f"{'Algorithm':<12} | {'Enc Time (ms)':<15} | {'Dec Time (ms)':<15}")
            print("-" * 48)
            print(f"{'DES':<12} | {des_enc:<15.6f} | {des_dec:<15.6f}")
            print(f"{'AES-256':<12} | {aes_enc:<15.6f} | {aes_dec:<15.6f}\n")

            print("--- FINDINGS & REPORT ---")
            print("1. AES-256 generally offers higher security with advanced block structures.")
            print(
                "2. Depending on hardware architecture and Python overhead, performance values may vary, but AES cryptographic primitives are highly optimized.")

        elif choice == '4':
            print("Exiting performance benchmark program. Goodbye!")
            break
        else:
            print("Invalid choice! Please select between 1 and 4.")


if __name__ == "__main__":
    performance_menu()