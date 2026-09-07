# 
"""22. des_aes_hex_blocks

Modify the program to accept hexadecimal blocks as input, encrypt each block
using the specified DES/AES key, display hexadecimal ciphertext for every
block and decrypt the ciphertext back to the original blocks.
"""

from Crypto.Cipher import DES, AES


def encrypt(pt, key, alg):
    if alg == "DES":
        cipher = DES.new(key, DES.MODE_ECB)
    else:
        cipher = AES.new(key, AES.MODE_ECB)

    ct = cipher.encrypt(pt)
    return ct


def decrypt(ct, key, alg):
    if alg == "DES":
        cipher = DES.new(key, DES.MODE_ECB)
    else:
        cipher = AES.new(key, AES.MODE_ECB)

    pt = cipher.decrypt(ct)
    return pt


def main():
    print("========== DES / AES HEX BLOCKS ==========")
    print("1. DES")
    print("2. AES")

    choice = input("Enter choice: ")

    if choice == '1':
        alg = "DES"
        n = 16
        key_len = 8

    elif choice == '2':
        alg = "AES"

        print("\n1. AES-128")
        print("2. AES-192")
        print("3. AES-256")

        ks = input("Enter key size: ")

        if ks == '1':
            key_len = 16
        elif ks == '2':
            key_len = 24
        elif ks == '3':
            key_len = 32
        else:
            print("Invalid key size.")
            return

        n = 32

    else:
        print("Invalid choice.")
        return

    key = input(f"Enter key ({key_len} characters): ")

    if len(key) != key_len:
        print(f"Key must be exactly {key_len} characters.")
        return

    try:
        key = key.encode()
    except:
        print("Invalid key.")
        return

    b = int(input("Enter number of blocks: "))

    blocks = []

    for i in range(b):
        x = input(f"Enter block {i + 1} ({n} hex characters): ")

        if len(x) != n:
            print(f"Block must be exactly {n} hex characters.")
            return

        try:
            x = bytes.fromhex(x)
        except ValueError:
            print("Invalid hexadecimal block.")
            return

        blocks.append(x)

    print("\n========== ENCRYPTION ==========")

    cts = []

    for i in range(b):
        ct = encrypt(blocks[i], key, alg)
        cts.append(ct)

        print(f"Block {i + 1} ciphertext:", ct.hex().upper())

    print("\n========== DECRYPTION ==========")

    for i in range(b):
        pt = decrypt(cts[i], key, alg)

        print(f"Block {i + 1} plaintext:", pt.hex().upper())

        if pt == blocks[i]:
            print("Verification: Successful")
        else:
            print("Verification: Failed")


if __name__ == "__main__":
    main()


# SAMPLE INPUT / OUTPUT
#
# ---------- DES ----------
#
# ========== DES / AES HEX BLOCKS ==========
# 1. DES
# 2. AES
# Enter choice: 1
# Enter key (8 characters): 12345678
# Enter number of blocks: 2
# Enter block 1 (16 hex characters): 0123456789ABCDEF
# Enter block 2 (16 hex characters): 1111111111111111
#
# ========== ENCRYPTION ==========
# Block 1 ciphertext: 56CC09E7CFDC4CEF
# Block 2 ciphertext: F40379AB9E0EC533
#
# ========== DECRYPTION ==========
# Block 1 plaintext: 0123456789ABCDEF
# Verification: Successful
# Block 2 plaintext: 1111111111111111
# Verification: Successful
#
#
# ---------- AES-128 ----------
#
# ========== DES / AES HEX BLOCKS ==========
# 1. DES
# 2. AES
# Enter choice: 2
#
# 1. AES-128
# 2. AES-192
# 3. AES-256
# Enter key size: 1
# Enter key (16 characters): 1234567890123456
# Enter number of blocks: 2
# Enter block 1 (32 hex characters): 00112233445566778899AABBCCDDEEFF
# Enter block 2 (32 hex characters): 112233445566778899AABBCCDDEEFF00
#
# ========== ENCRYPTION ==========
# Block 1 ciphertext: ...
# Block 2 ciphertext: ...
#
# ========== DECRYPTION ==========
# Block 1 plaintext: 00112233445566778899AABBCCDDEEFF
# Verification: Successful
# Block 2 plaintext: 112233445566778899AABBCCDDEEFF00
# Verification: Successful