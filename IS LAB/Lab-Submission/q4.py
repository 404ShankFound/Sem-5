from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def triple_des_menu():
    print("========== TRIPLE DES (3DES) MENU ==========")
    # Using a valid 24-byte ASCII key
    default_key = b"123456789012345678901234"  # Exactly 24 bytes

    key_input = input("Enter 24-character key (default '123456789012345678901234'): ")
    if not key_input:
        key = default_key
    else:
        key = key_input.encode()
        # Automatically adjust or pad/truncate to meet the strict 24-byte requirement for 3DES
        if len(key) < 24:
            key = key.ljust(24, b'0')
        elif len(key) > 24:
            key = key[:24]

    while True:
        print("\n========== MENU ==========")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Encrypt and Verify")
        print("4. Exit")

        choice = input("Enter choice: ").strip()

        if choice == '1':
            message = input("Enter plaintext: ")
            try:
                cipher = DES3.new(key, DES3.MODE_ECB)
                padded_data = pad(message.encode(), DES3.block_size)
                ciphertext = cipher.encrypt(padded_data)
                print(f"\nCiphertext (Hex): {ciphertext.hex()}")
            except Exception as e:
                print(f"\nEncryption failed: {e}")

        elif choice == '2':
            hex_ciphertext = input("Enter ciphertext (Hex): ")
            try:
                ciphertext = bytes.fromhex(hex_ciphertext)
                decipher = DES3.new(key, DES3.MODE_ECB)
                decrypted_padded = decipher.decrypt(ciphertext)
                decrypted_message = unpad(decrypted_padded, DES3.block_size).decode()
                print(f"\nDecrypted Message: {decrypted_message}")
            except Exception as e:
                print(f"\nDecryption failed: {e}")

        elif choice == '3':
            message = input("Enter plaintext to encrypt & verify (default 'Classified Text'): ")
            if not message:
                message = "Classified Text"

            print("\n--- INPUT ---")
            print(f"Original Message : {message}")
            print(f"Message Length   : {len(message.encode())} bytes")
            print(f"3DES Key         : {key.decode(errors='ignore')}\n")

            # Encrypt
            cipher = DES3.new(key, DES3.MODE_ECB)
            padded_data = pad(message.encode(), DES3.block_size)
            ciphertext = cipher.encrypt(padded_data)

            print("--- ENCRYPTION (ECB Mode) ---")
            print(f"Padded Length        : {len(padded_data)} bytes")
            print(f"Ciphertext (Hex)     : {ciphertext.hex()}\n")

            # Decrypt
            decipher = DES3.new(key, DES3.MODE_ECB)
            decrypted_padded = decipher.decrypt(ciphertext)
            decrypted_message = unpad(decrypted_padded, DES3.block_size).decode()

            print("--- VERIFICATION (DECRYPTION) ---")
            print(f"Decrypted Raw Bytes  : {decrypted_padded}")
            print(f"Final Clean Message  : {decrypted_message}")

        elif choice == '4':
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice! Please select between 1 and 4.")


if __name__ == "__main__":
    triple_des_menu()