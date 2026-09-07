"""19. multi_message_block_encryption

Encrypt five different messages using the same algorithm and key; handle
messages of different lengths and multiple blocks; decrypt all ciphertexts and
verify the original messages.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt(pt, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
    return ct


def decrypt(ct, key):
    cipher = AES.new(key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
    return pt


def main():
    print("========== MULTI MESSAGE ENCRYPTION ==========")

    key = input("Enter AES key (16 characters): ").encode()

    if len(key) != 16:
        print("Key must be exactly 16 characters.")
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