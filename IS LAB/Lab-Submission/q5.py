'''from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def aes192_menu():
    print("========== AES-192 MENU ==========")
    default_hex_key = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"  # 48 hex chars = 24 bytes
    key_input = input(f"Enter 48-character hex key (default AES-192 key): ")

    if not key_input:
        key = bytes.fromhex("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210")
    else:
        try:
            # Try parsing as hex if user typed hex characters
            key = bytes.fromhex(key_input)
        except ValueError:
            # Fallback to standard bytes encode if not pure hex
            key = key_input.encode()

        # Ensure exact 24 bytes for AES-192
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
            message = input("Enter plaintext to encrypt & verify (default 'Top Secret Data'): ")
            if not message:
                message = "Top Secret Data"

            print("\n--- INPUT ---")
            print(f"Original Message : {message}")
            print(f"Message Length   : {len(message.encode())} bytes")
            print(f"AES-192 Key (Hex): {key.hex()}\n")

            # Step-by-step documentation for AES-192 rounds
            print("--- AES-192 THEORETICAL & STRUCTURAL STEPS ---")
            print(
                "1. Key Expansion   : Expands the 192-bit key into 13 round keys (1 initial + 12 round keys for 12 rounds).")
            print("2. Initial Round   : AddRoundKey (XORs the state block with the 0th round key).")
            print("3. Main Rounds     : 11 rounds of SubBytes, ShiftRows, MixColumns, and AddRoundKey.")
            print("4. Final Round     : 1 round of SubBytes, ShiftRows, and AddRoundKey (omits MixColumns).\n")

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
    aes192_menu()
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES S-BOX
SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

RCON = [0,1,2,4,8,16,32,64,128,27,54]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def expand_key(key):

    w = [key[i:i+4] for i in range(0, 24, 4)]

    for i in range(6, 52):

        t = w[i-1]

        if i % 6 == 0:
            t = t[1:] + t[:1]
            t = bytes(SBOX[x] for x in t)
            t = bytes([t[0] ^ RCON[i//6]]) + t[1:]

        w.append(xor(w[i-6], t))

    keys = [b''.join(w[i:i+4]) for i in range(0, 52, 4)]

    print("\n========== KEY EXPANSION ==========")

    for i, k in enumerate(keys):
        print(f"Round Key {i:02}: {k.hex().upper()}")

    return keys


def show(name, data):
    print(f"{name:<18}: {data.hex().upper()}")


def sub_bytes(s):
    return bytes(SBOX[x] for x in s)


def shift_rows(s):
    return bytes([
        s[0],s[5],s[10],s[15],
        s[4],s[9],s[14],s[3],
        s[8],s[13],s[2],s[7],
        s[12],s[1],s[6],s[11]
    ])


def gmul(a, b):

    r = 0

    for _ in range(8):

        if b & 1:
            r ^= a

        a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 255
        b >>= 1

    return r


def mix_columns(s):

    r = bytearray(16)

    for i in range(0, 16, 4):

        a,b,c,d = s[i:i+4]

        r[i]   = gmul(a,2)^gmul(b,3)^c^d
        r[i+1] = a^gmul(b,2)^gmul(c,3)^d
        r[i+2] = a^b^gmul(c,2)^gmul(d,3)
        r[i+3] = gmul(a,3)^b^c^gmul(d,2)

    return bytes(r)


def encrypt(text, key):

    data = pad(text.encode(), 16)
    s = data[:16]

    print("\n========== INPUT ==========")
    print("Plaintext :", text)
    print("Padded    :", data.hex().upper())

    keys = expand_key(key)

    print("\n========== INITIAL ROUND ==========")

    s = xor(s, keys[0])
    show("AddRoundKey", s)

    for r in range(1, 12):

        print(f"\n========== ROUND {r} ==========")

        s = sub_bytes(s)
        show("SubBytes", s)

        s = shift_rows(s)
        show("ShiftRows", s)

        s = mix_columns(s)
        show("MixColumns", s)

        s = xor(s, keys[r])
        show("AddRoundKey", s)

    print("\n========== FINAL ROUND 12 ==========")

    s = sub_bytes(s)
    show("SubBytes", s)

    s = shift_rows(s)
    show("ShiftRows", s)

    print("MixColumns       : SKIPPED")

    s = xor(s, keys[12])
    show("AddRoundKey", s)

    print("\nCiphertext:", s.hex().upper())

    return s


def verify(ciphertext, key):

    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()


def main():

    key = bytes.fromhex(
        "FEDCBA9876543210"
        "FEDCBA9876543210"
        "FEDCBA9876543210"
    )

    print("========== AES-192 LAB ==========")
    print("Key       :", key.hex().upper())
    print("Key Size  :", len(key) * 8, "bits")

    while True:

        print("\n1. Encrypt")
        print("2. Encrypt & Verify")
        print("3. Exit")

        choice = input("Enter choice: ")

        if choice in ("1", "2"):

            text = input(
                "Enter plaintext "
                "(default: Top Secret Data): "
            ) or "Top Secret Data"

            cipher = encrypt(text, key)

            if choice == "2":

                decrypted = verify(cipher, key)

                print("\n========== VERIFICATION ==========")
                print("Original :", text)
                print("Decrypted:", decrypted)

                if text == decrypted:
                    print("Verification: SUCCESS")
                else:
                    print("Verification: FAILED")

        elif choice == "3":

            print("Program terminated.")
            break

        else:

            print("Invalid choice.")


if __name__ == "__main__":
    main()

