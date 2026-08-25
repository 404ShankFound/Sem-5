import math
def affine_encrypt(plaintext, a, b):
    encrypted_text = []
    for char in plaintext:
        if char.isalpha():
            ascii_offset = ord("A") if char.isupper() else ord("a")
            x = ord(char) - ascii_offset
            y = (a * x + b) % 26
            encrypted_text.append(chr(y + ascii_offset))
        else:
            encrypted_text.append(char)
    return "".join(encrypted_text)

def affine_decrypt(ciphertext, a, b):
    try:
        a_inv = pow(a, -1, 26)
    except ValueError:
        return None

    decrypted_text = []

    for char in ciphertext:
        if char.isalpha():
            ascii_offset = ord("A") if char.isupper() else ord("a")
            y = ord(char) - ascii_offset
            x = (a_inv * (y - b)) % 26
            decrypted_text.append(chr(x + ascii_offset))
        else:
            decrypted_text.append(char)

    return "".join(decrypted_text)

def affine_known_plaintext_attack(known_cipher, known_plain):
    if len(known_cipher) < 2 or len(known_plain) < 2:
        print("Known plaintext and ciphertext must contain at least 2 letters.")
        return []

    y1 = ord(known_cipher[0].upper()) - ord("A")
    y2 = ord(known_cipher[1].upper()) - ord("A")

    x1 = ord(known_plain[0].lower()) - ord("a")
    x2 = ord(known_plain[1].lower()) - ord("a")

    valid_keys = []

    valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

    for a in valid_a:
        b = (y1 - a * x1) % 26

        if (a * x2 + b) % 26 == y2:
            valid_keys.append((a, b))

    return valid_keys

known_plain = input("Enter known plaintext (Example: ab): ").strip()
known_cipher = input("Enter corresponding ciphertext (Example: GL): ").strip()
target_ciphertext = input("Enter ciphertext to decrypt: ").strip()

keys = affine_known_plaintext_attack(known_cipher, known_plain)

if not keys:
    print("\nNo valid affine key found.")
else:
    print("\nDerived Affine Key(s):")
    for a, b in keys:
        print(f"a = {a}, b = {b}")

    print("\nDecryption Results:")
    for a, b in keys:
        plaintext = affine_decrypt(target_ciphertext, a, b)
        print(f"Using a={a}, b={b} -> {plaintext}")
