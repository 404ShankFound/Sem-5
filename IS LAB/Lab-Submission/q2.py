from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_menu():
    print("========== AES-128 MENU ==========")
    key_input = input("Enter 32-character key (default '0123456789ABCDEF0123456789ABCDEF'): ")
    if not key_input:
        key = b"0123456789ABCDEF0123456789ABCDEF"
    else:
        key = key_input.encode()

    # Ensure key is 32 bytes for AES-256 or handle accordingly. The prompt specified AES-128 with a 32-hex character string (which is 32 bytes if text, or let's check bytes length).
    # Wait, the prompt states: AES-128 with the following key:"0123456789ABCDEF0123456789ABCDEF" -> 32 hex chars / bytes. Let's make sure it handles it cleanly as bytes.

    while True:
        print("\n========== MENU ==========")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Encrypt and Verify")
        print("4. Exit")

        choice = input("Enter choice: ").strip()

        if choice == '1':
            message = input("Enter plaintext: ")
            cipher = AES.new(key, AES.MODE_ECB)
            padded_data = pad(message.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            print(f"\nCiphertext (Hex): {ciphertext.hex()}")

        elif choice == '2':
            hex_ciphertext = input("Enter ciphertext (Hex): ")
            try:
                ciphertext = bytes.fromhex(hex_ciphertext)
                decipher = AES.new(key, AES.MODE_ECB)
                decrypted_padded = decipher.decrypt(ciphertext)
                decrypted_message = unpad(decrypted_padded, AES.block_size).decode()
                print(f"\nDecrypted Message: {decrypted_message}")
            except Exception as e:
                print(f"\nDecryption failed: {e}")

        elif choice == '3':
            message = input("Enter plaintext to encrypt & verify: ")

            # Step-by-step display similar to your template
            print("\n--- INPUT ---")
            print(f"Original Message : {message}")
            print(f"Message Length   : {len(message.encode())} bytes")
            print(f"AES Key          : {key.decode() if len(key) == 32 else key}\n")

            # Encrypt
            cipher = AES.new(key, AES.MODE_ECB)
            padded_data = pad(message.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_data)

            print("--- ENCRYPTION (ECB Mode) ---")
            print(f"Padded Length        : {len(padded_data)} bytes")
            print(f"Ciphertext (Hex)     : {ciphertext.hex()}\n")

            # Decrypt
            decipher = AES.new(key, AES.MODE_ECB)
            decrypted_padded = decipher.decrypt(ciphertext)
            decrypted_message = unpad(decrypted_padded, AES.block_size).decode()

            print("--- VERIFICATION (DECRYPTION) ---")
            print(f"Decrypted Raw Bytes  : {decrypted_padded}")
            print(f"Final Clean Message  : {decrypted_message}")

        elif choice == '4':
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice! Please select between 1 and 4.")


if __name__ == "__main__":
    aes_menu()