##LAB-1 : 27/07/2026
"""
1. Encrypt the message "I am learning information security" using one of the following ciphers.
Ignore the space between words. Decrypt the message to get the original plaintext:
a) Additive cipher with key = 20
b) Multiplicative cipher with key = 15
c) Affine cipher with key = (15, 20)
"""
import sys

def e_additive_cipher(plain: str):
    key = int(input("Enter the key: "))
    encrypted = ""
    A_BASE = ord('A')
    a_base = ord('a')
    for char in plain:
        if char.isupper():
            encrypted += chr((ord(char) - A_BASE + key) % 26 + A_BASE)
        elif char.islower():
            encrypted += chr((ord(char) - a_base + key) % 26 + a_base)
        else:
            encrypted += char
    return encrypted


def d_additive_cipher(plain: str):
    key = int(input("Enter the key: "))
    encrypted = ""
    A_BASE = ord('A')
    a_base = ord('a')
    for char in plain:
        if char.isupper():
            encrypted += chr((ord(char) - A_BASE - key) % 26 + A_BASE)
        elif char.islower():
            encrypted += chr((ord(char) - a_base - key) % 26 + a_base)
        else:
            encrypted += char
    return encrypted


def e_multiplicative_cipher(plain: str):
    key = int(input("Enter the key: "))
    encrypted = ""
    A_BASE = ord('A')
    a_base = ord('a')
    for char in plain:
        if char.isupper():
            encrypted += chr(((ord(char) - A_BASE) * key) % 26 + A_BASE)
        elif char.islower():
            encrypted += chr(((ord(char) - a_base) * key) % 26 + a_base)
        else:
            encrypted += char
    return encrypted


def d_multiplicative_cipher(plain: str):
    key = int(input("Enter the key: "))
    inv_key = pow(key, -1, 26)
    encrypted = ""
    A_BASE = ord('A')
    a_base = ord('a')
    for char in plain:
        if char.isupper():
            encrypted += chr(((ord(char) - A_BASE) * inv_key) % 26 + A_BASE)
        elif char.islower():
            encrypted += chr(((ord(char) - a_base) * inv_key) % 26 + a_base)
        else:
            encrypted += char
    return encrypted


def e_affine_cipher(plain: str):
    print("Enter the keys (a and b) for Affine cipher:")
    key_a = int(input("Enter key a (multiplicative): "))
    key_b = int(input("Enter key b (additive): "))
    encrypted = ""
    A_BASE = ord('A')
    a_base = ord('a')
    for char in plain:
        if char.isupper():
            encrypted += chr(((ord(char) - A_BASE) * key_a + key_b) % 26 + A_BASE)
        elif char.islower():
            encrypted += chr(((ord(char) - a_base) * key_a + key_b) % 26 + a_base)
        else:
            encrypted += char
    return encrypted


def d_affine_cipher(plain: str):
    print("Enter the keys (a and b) for Affine cipher:")
    key_a = int(input("Enter key a (multiplicative): "))
    key_b = int(input("Enter key b (additive): "))
    inv_key_a = pow(key_a, -1, 26)
    encrypted = ""
    A_BASE = ord('A')
    a_base = ord('a')
    for char in plain:
        if char.isupper():
            encrypted += chr((inv_key_a * (ord(char) - A_BASE - key_b)) % 26 + A_BASE)
        elif char.islower():
            encrypted += chr((inv_key_a * (ord(char) - a_base - key_b)) % 26 + a_base)
        else:
            encrypted += char
    return encrypted


while (1):
    print("\n1) Encrypt\n2) Decrypt\n3) Exit\n")
    choice_input = input("Select your choice: ").strip()
    if not choice_input:
        continue
    choice = int(choice_input)

    if choice == 1:
        plaintext = input("Enter the text to encrypt: ")
        print(f"Entered text: {plaintext}")
        print(
            "1) Additive cipher\n2) Multiplicative cipher\n3) Affine cipher\n")
        cipher = int(input("Select the encryption method: "))
        match cipher:
            case 1:
                result = e_additive_cipher(plaintext)
                print(f" Encrypted msg: {result}")
            case 2:
                result = e_multiplicative_cipher(plaintext)
                print(f" Encrypted msg: {result}")
            case 3:
                result = e_affine_cipher(plaintext)
                print(f" Encrypted msg: {result}")
    elif choice == 2:
        ciphertext = input("Enter the text to decrypt: ")
        print(f"Entered text: {ciphertext}")
        print(
            "1) Additive cipher\n2) Multiplicative cipher\n3) Affine cipher\n")
        cipher = int(input("Select the decryption method: "))
        match cipher:
            case 1:
                result = d_additive_cipher(ciphertext)
                print(f" Decrypted msg: {result}")
            case 2:
                result = d_multiplicative_cipher(ciphertext)
                print(f" Decrypted msg: {result}")
            case 3:
                result = d_affine_cipher(ciphertext)
                print(f" Decrypted msg: {result}")
    elif choice == 3:
        sys.exit()
