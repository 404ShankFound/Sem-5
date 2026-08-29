"""
12. Known Plaintext Attack

PT-CT PAIRS  | KEY FORMULA                                         | REQUIREMENT

Shift: 1     | k = (C - P) mod 26                                  | None

Multip: 1    | a = C * P^(-1) mod 26                               | P^(-1) must exist in Z-26

Affine: 2    | a = (C1-C2) * (P1-P2)^(-1) mod 26                   | (P1-P2)^(-1) must exist in Z-26
               b = (C1 - a*P1) mod 26                              

Affine: 2    | Try valid a, calculate b, verify with pair 2        | gcd(a,26) = 1
Affine: 2    | Direct if possible, otherwise brute force           | Same as above
"""

import math

def find_shift_key(p, c):
    p = ord(p.lower()) - ord('a')
    c = ord(c.lower()) - ord('a')

    return (c - p) % 26


def decrypt_shift(ct, k):
    pt = ""

    for c in ct:
        if c.isalpha():
            b = ord('A') if c.isupper() else ord('a')
            pt += chr((ord(c) - b - k) % 26 + b)
        else:
            pt += c

    return pt


def find_multiplicative_key(p, c):
    p = ord(p.lower()) - ord('a')
    c = ord(c.lower()) - ord('a')

    if math.gcd(p, 26) != 1:
        return None

    return (c * pow(p, -1, 26)) % 26


def decrypt_multiplicative(ct, k):
    pt = ""
    k1 = pow(k, -1, 26)

    for c in ct:
        if c.isalpha():
            b = ord('A') if c.isupper() else ord('a')
            pt += chr(((ord(c) - b) * k1) % 26 + b)
        else:
            pt += c

    return pt


def find_affine_key_direct(p1, c1, p2, c2):
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


def find_affine_keys_bruteforce(p1, c1, p2, c2):
    p1 = ord(p1.lower()) - ord('a')
    c1 = ord(c1.lower()) - ord('a')
    p2 = ord(p2.lower()) - ord('a')
    c2 = ord(c2.lower()) - ord('a')

    keys = []

    for a in range(26):
        if math.gcd(a, 26) == 1:
            b = (c1 - a * p1) % 26

            if (a * p2 + b) % 26 == c2:
                keys.append((a, b))

    return keys


def find_affine_key(p1, c1, p2, c2):
    p1 = ord(p1.lower()) - ord('a')
    c1 = ord(c1.lower()) - ord('a')
    p2 = ord(p2.lower()) - ord('a')
    c2 = ord(c2.lower()) - ord('a')

    d = (p1 - p2) % 26

    # Direct method
    if math.gcd(d, 26) == 1:
        a = ((c1 - c2) * pow(d, -1, 26)) % 26
        b = (c1 - a * p1) % 26

        return [(a, b)]

    # Brute-force method
    keys = []

    for a in range(26):
        if math.gcd(a, 26) == 1:
            b = (c1 - a * p1) % 26

            if (a * p2 + b) % 26 == c2:
                keys.append((a, b))

    return keys


def decrypt_affine(ct, a, b):
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


def main():

    while True:

        print("\n1. Shift KPA - Direct")
        print("2. Multiplicative KPA")
        print("3. Affine KPA - Direct (Not always Possible)")
        print("4. Affine KPA - Brute Force")
        print("5. Affine KPA - Direct or Brute Force")
        print("6. Exit")

        ch = int(input("Enter choice: "))

        # ---------------- SHIFT KPA ----------------

        if ch == 1:

            p = input("Enter known plaintext character: ")
            c = input("Enter corresponding ciphertext character: ")
            ct = input("Enter target ciphertext: ")

            k = find_shift_key(p, c)

            print("Key:", k)
            print("PlainText:", decrypt_shift(ct, k))


        # ---------------- MULTIPLICATIVE KPA ----------------

        elif ch == 2:

            p = input("Enter known plaintext character: ")
            c = input("Enter corresponding ciphertext character: ")
            ct = input("Enter target ciphertext: ")

            k = find_multiplicative_key(p, c)

            if k is None:
                print("Direct calculation not possible")
            else:
                print("Key:", k)
                print("PlainText:", decrypt_multiplicative(ct, k))


        # ---------------- AFFINE DIRECT ----------------

        elif ch == 3:

            p1 = input("Enter plaintext 1: ")
            c1 = input("Enter ciphertext 1: ")
            p2 = input("Enter plaintext 2: ")
            c2 = input("Enter ciphertext 2: ")
            ct = input("Enter target ciphertext: ")

            key = find_affine_key_direct(p1, c1, p2, c2)

            if key is None:
                print("Direct calculation not possible")
            else:
                a, b = key
                print("a =", a)
                print("b =", b)
                print("PlainText:", decrypt_affine(ct, a, b))


        # ---------------- AFFINE BRUTE FORCE ----------------

        elif ch == 4:

            p1 = input("Enter plaintext 1: ")
            c1 = input("Enter ciphertext 1: ")
            p2 = input("Enter plaintext 2: ")
            c2 = input("Enter ciphertext 2: ")
            ct = input("Enter target ciphertext: ")

            keys = find_affine_keys_bruteforce(p1, c1, p2, c2)

            if not keys:
                print("No valid key found")
            else:
                for a, b in keys:
                    print("a =", a, "b =", b)
                    print("PlainText:", decrypt_affine(ct, a, b))


        # ---------------- AFFINE DIRECT / BRUTE FORCE ----------------

        elif ch == 5:

            p1 = input("Enter plaintext 1: ")
            c1 = input("Enter ciphertext 1: ")
            p2 = input("Enter plaintext 2: ")
            c2 = input("Enter ciphertext 2: ")
            ct = input("Enter target ciphertext: ")

            keys = find_affine_key(p1, c1, p2, c2)

            if not keys:
                print("No valid key found")
            else:
                for a, b in keys:
                    print("a =", a, "b =", b)
                    print("PlainText:", decrypt_affine(ct, a, b))


        else:
            break


if __name__ == "__main__":
    main()