"""2. des_implementation_variations

Modify the DES program for different plaintexts, keys, message lengths,
multiple messages and multiple 64-bit blocks; support both text and
hexadecimal input/output.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def des_encrypt(plaintext, key):

    plaintext = plaintext.encode()

    cipher = DES.new(key, DES.MODE_ECB)

    padded_data = pad(plaintext, DES.block_size)

    ciphertext = cipher.encrypt(padded_data)

    return ciphertext


def des_decrypt(ciphertext, key):

    cipher = DES.new(key, DES.MODE_ECB)

    decrypted_padded = cipher.decrypt(ciphertext)

    plaintext = unpad(
        decrypted_padded,
        DES.block_size
    ).decode()

    return plaintext


def main():

    print("========== DES VARIATIONS MENU ==========")

    while True:

        print("\n========== MENU ==========")
        print("1. Text Input")
        print("2. Hexadecimal Input")
        print("3. Multiple Messages")
        print("4. Exit")

        choice = input("Enter choice: ")

        if choice == '1':

            key_input = input("Enter 8-character key: ")

            if len(key_input.encode()) != 8:
                print("Key must be exactly 8 bytes.")
                continue

            plaintext = input("Enter plaintext: ")

            key = key_input.encode()

            ciphertext = des_encrypt(plaintext, key)

            print("\nCiphertext (Hex):", ciphertext.hex())

            decrypted = des_decrypt(ciphertext, key)

            print("Decrypted Message:", decrypted)

        elif choice == '2':

            key_input = input("Enter 16-character hexadecimal key: ")

            try:
                key = bytes.fromhex(key_input)

                if len(key) != 8:
                    print("Key must be exactly 8 bytes.")
                    continue

                hex_plaintext = input("Enter plaintext in hexadecimal: ")

                plaintext = bytes.fromhex(hex_plaintext)

                cipher = DES.new(key, DES.MODE_ECB)

                padded_data = pad(plaintext, DES.block_size)

                ciphertext = cipher.encrypt(padded_data)

                print("\nCiphertext (Hex):", ciphertext.hex())

                decrypted_padded = cipher.decrypt(ciphertext)

                decrypted = unpad(
                    decrypted_padded,
                    DES.block_size
                )

                print("Decrypted (Hex):", decrypted.hex())

            except Exception as e:
                print("Invalid hexadecimal input:", e)

        elif choice == '3':

            key_input = input("Enter 8-character key: ")

            if len(key_input.encode()) != 8:
                print("Key must be exactly 8 bytes.")
                continue

            key = key_input.encode()

            n = int(input("Enter number of messages: "))

            for i in range(n):

                plaintext = input(
                    f"Enter plaintext {i + 1}: "
                )

                ciphertext = des_encrypt(plaintext, key)

                print("Ciphertext (Hex):", ciphertext.hex())

                decrypted = des_decrypt(ciphertext, key)

                print("Decrypted Message:", decrypted)

                if plaintext == decrypted:
                    print("Verification: SUCCESS")
                else:
                    print("Verification: FAILED")

        elif choice == '4':

            print("Program terminated.")
            break

        else:

            print("Invalid choice.")


if __name__ == "__main__":
    main()