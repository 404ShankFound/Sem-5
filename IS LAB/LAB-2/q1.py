# ============================================================
# VERSION 1: ENCRYPTION + DECRYPTION TOGETHER
# Simple approach without separate functions
# ============================================================

'''
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Take key and plaintext as input and convert them to bytes
key = input("Enter the key: ").encode()
plaintext = input("Enter the plaintext: ").encode()

Your DES key must be exactly 8 bytes.

Since you do:

key = input("Enter key: ").encode()

the user must enter an 8-character ASCII key, for example:

12345678

or

abcdefgh

If they enter 1234, DES will give:

ValueError: Incorrect DES key length. It must be exactly 8 bytes long.

# Create DES cipher using ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Pad plaintext and encrypt it
ciphertext = cipher.encrypt(pad(plaintext, 8))

# Display ciphertext in hexadecimal format
print("CipherText:", ciphertext.hex())

# Decrypt the ciphertext
plaintext = cipher.decrypt(ciphertext)

# Remove the padding
plaintext = unpad(plaintext, 8)

# Convert bytes back to text and display
print("Decrypted message:", plaintext.decode())
'''


# ============================================================
# VERSION 2: ENCRYPTION AND DECRYPTION USING SEPARATE FUNCTIONS
# ============================================================

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


# ------------------------------------------------------------
# ENCRYPTION
#
# Steps:
# 1. Text to Bytes       -> .encode()
# 2. Add Padding         -> pad(message, block_size)
# 3. Create DES Cipher   -> DES.new(key, DES.MODE_ECB)
# 4. Encrypt             -> .encrypt()
# 5. Display Ciphertext  -> .hex()
# ------------------------------------------------------------

def des_encrypt(plaintext, key):

    # Convert plaintext from text to bytes
    plaintext = plaintext.encode()

    # Create DES cipher using ECB mode
    cipher = DES.new(key, DES.MODE_ECB)

    # Pad plaintext and encrypt it
    ciphertext = cipher.encrypt(pad(plaintext, 8))

    # Convert ciphertext bytes to hexadecimal for display
    print("CipherText:", ciphertext.hex())


# ------------------------------------------------------------
# DECRYPTION
#
# Steps:
# 1. Hexadecimal Ciphertext to Bytes -> bytes.fromhex()
# 2. Decrypt                       -> .decrypt()
# 3. Remove Padding                -> unpad(message, block_size)
# 4. Bytes to Text                 -> .decode()
# ------------------------------------------------------------

def des_decrypt(ciphertext, key):

    # Convert hexadecimal ciphertext to encrypted bytes
    ciphertext = bytes.fromhex(ciphertext)

    # Create DES cipher using ECB mode
    cipher = DES.new(key, DES.MODE_ECB)

    # Decrypt ciphertext
    plaintext = cipher.decrypt(ciphertext)

    # Remove padding from decrypted plaintext
    plaintext = unpad(plaintext, 8)

    # Convert plaintext bytes to text and display
    print("PlainText:", plaintext.decode())


# ------------------------------------------------------------
# INPUT FUNCTION
# ------------------------------------------------------------

def takeinput():

    # This can be:
    # 1. Plaintext when encryption is selected so we convert this to bytes in encryption fn.
    # 2. Ciphertext in hexadecimal first when decryption is selected
    msg = input("Enter message/ciphertext: ")

    # DES key is converted from text to bytes
    key = input("Enter key: ").encode()

    return msg, key


# ------------------------------------------------------------
# MAIN FUNCTION
# ------------------------------------------------------------

def main():

    while True:

        print("\nSELECT")
        task = int(input("1. ENCRYPT\n2. DECRYPT\n3. EXIT\n"))

        if task == 1:

            # Take plaintext and key
            plaintext, key = takeinput()

            # Encrypt plaintext
            des_encrypt(plaintext, key)

        elif task == 2:

            # Take hexadecimal ciphertext and key
            ciphertext, key = takeinput()

            # Decrypt ciphertext
            des_decrypt(ciphertext, key)

        elif task == 3:

            # Exit the program
            break

        else:

            print("INVALID CHOICE")


# Call main() only when this file is executed directly
if __name__ == "__main__":
    main()