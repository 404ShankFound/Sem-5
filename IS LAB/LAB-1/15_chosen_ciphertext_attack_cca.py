"""15. Chosen-Ciphertext Attack (CCA)."""

import math


def affine_decrypt(ct, a, b):
    pt = ""

    a1 = pow(a, -1, 26)

    for c in ct:
        if c.isalpha():
            z = ord('A') if c.isupper() else ord('a')
            x = ord(c) - z
            pt += chr((a1 * (x - b)) % 26 + z)
        else:
            pt += c

    return pt


def find_affine_key(p1, c1, p2, c2):
    p1 = ord(p1.lower()) - ord('a')
    c1 = ord(c1.lower()) - ord('a')
    p2 = ord(p2.lower()) - ord('a')
    c2 = ord(c2.lower()) - ord('a')

    d = (p1 - p2) % 26

    if math.gcd(d, 26) != 1:
        return None

    a = ((c1 - c2) * pow(d, -1, 26)) % 26
    b = (c1 - a * p1) % 26

    return a, b


def main():

    # Attacker chooses ciphertext
    ct = input("Enter chosen ciphertext (2 letters): ")

    # Decryption system provides plaintext
    a = int(input("Enter actual key a: "))
    b = int(input("Enter actual key b: "))

    pt = affine_decrypt(ct, a, b)

    print("Chosen Ciphertext:", ct)
    print("Received Plaintext:", pt)

    key = find_affine_key(pt[0], ct[0], pt[1], ct[1])

    if key is None:
        print("Key cannot be found directly")
    else:
        a1, b1 = key
        print("Found a =", a1)
        print("Found b =", b1)


if __name__ == "__main__":
    main()