"""19. des_multi_message_block_encryption

Encrypt five different messages using the same DES algorithm and key; handle
messages of different lengths and multiple blocks; decrypt all ciphertexts and
verify the original messages.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), DES.block_size))
    return ct


def decrypt(ct, key):
    cipher = DES.new(key, DES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), DES.block_size).decode()
    return pt


def main():
    print("========== MULTI MESSAGE ENCRYPTION ==========")

    key = input("Enter DES key (8 characters): ").encode()

    if len(key) != 8:
        print("Key must be exactly 8 characters.")
        return

    msg = []

    for i in range(5):
        pt = input(f"Enter message {i + 1}: ")
        msg.append(pt)

    print("\n========== RESULTS ==========")

    for i in range(5):

        ct = encrypt(msg[i], key)
        dpt = decrypt(ct, key)

        print(f"\nMessage {i + 1}")
        print("Plaintext :", msg[i])
        print("Ciphertext:", ct.hex())
        print("Decrypted :", dpt)
        print("Verification:",
              "Successful" if msg[i] == dpt else "Failed")


if __name__ == "__main__":
    main()