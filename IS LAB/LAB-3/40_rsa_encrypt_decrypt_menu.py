# %%
"""Question 40: Rsa encrypt decrypt menu

Create a menu-driven RSA program supporting key generation, encryption,
decryption, parameter display and exit.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def main():

    # Initially no RSA key has been generated
    key = None
    pub = None

    while True:

        print("\n--- RSA MENU ---")
        print("1. Generate Keys")
        print("2. Encrypt")
        print("3. Decrypt")
        print("4. Display Parameters")
        print("5. Exit")

        ch = input("Enter choice: ")

        # Generate RSA key pair
        if ch == "1":

            # Generate 2048-bit RSA private key
            key = RSA.generate(2048)

            # Generate public key from private key
            pub = key.publickey()

            print("RSA keys generated successfully.")

        # Encrypt message
        elif ch == "2":

            # Check whether keys have been generated
            if key is None:
                print("Generate keys first.")
                continue

            msg = input("Enter plaintext: ")

            # Convert plaintext to bytes and encrypt using public key
            cipher = PKCS1_OAEP.new(pub)
            ct = cipher.encrypt(msg.encode())

            print("Ciphertext:", ct.hex())

        # Decrypt message
        elif ch == "3":

            # Check whether keys have been generated
            if key is None:
                print("Generate keys first.")
                continue

            # Take hexadecimal ciphertext
            ct = input("Enter ciphertext (hex): ")

            # Convert hexadecimal string back to bytes
            ct = bytes.fromhex(ct)

            # Decrypt using private key
            cipher = PKCS1_OAEP.new(key)
            pt = cipher.decrypt(ct)

            # Convert bytes back to string
            print("Decrypted message:", pt.decode())

        # Display RSA parameters
        elif ch == "4":

            # Check whether keys have been generated
            if key is None:
                print("Generate keys first.")
                continue

            print("\nPublic Parameters:")
            print("n =", pub.n)
            print("e =", pub.e)

            print("\nPrivate Parameters:")
            print("p =", key.p)
            print("q =", key.q)
            print("d =", key.d)

        # Exit
        elif ch == "5":
            print("Exiting...")
            break

        # Invalid menu choice
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()