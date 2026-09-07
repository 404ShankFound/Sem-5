"""14. Chosen-Plaintext Attack (CPA)."""

import math

def affine_encrypt(pt, a, b):
    ct = ""

    for c in pt:
        if c.isalpha():
            z = ord('A') if c.isupper() else ord('a')
            x = ord(c) - z
            ct += chr((a*x + b) % 26 + z)
        else:
            ct += c

    return ct


def find_affine_key(pt, ct):
    p1 = ord(pt[0].lower()) - ord('a')
    p2 = ord(pt[1].lower()) - ord('a')

    c1 = ord(ct[0].lower()) - ord('a')
    c2 = ord(ct[1].lower()) - ord('a')

    d = (p1 - p2) % 26

    if math.gcd(d, 26) != 1:
        return None

    a = ((c1 - c2) * pow(d, -1, 26)) % 26
    b = (c1 - a*p1) % 26

    return a, b


def main():
    print("Chosen Plaintext Attack on Affine Cipher")

    # Attacker chooses plaintext
    pt = input("Enter chosen plaintext (2 letters): ")

    # Encryption system provides ciphertext
    a = int(input("Enter actual key a: "))
    b = int(input("Enter actual key b: "))

    ct = affine_encrypt(pt, a, b)

    print("Chosen Plaintext:", pt)
    print("Received Ciphertext:", ct)

    key = find_affine_key(pt, ct)

    if key is None:
        print("Key cannot be found directly")
    else:
        a1, b1 = key
        print("Found a =", a1)
        print("Found b =", b1)


if __name__ == "__main__":
    main()