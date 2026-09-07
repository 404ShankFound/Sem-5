"""17. Brute force for affine."""

import math

A = ord('A')
a = ord('a')

def decrypt(ct, k, b):
    pt = ""
    k1 = pow(k, -1, 26)

    for c in ct:
        if c.isalpha():
            x = ord(c) - A if c.isupper() else ord(c) - a
            x = (k1 * (x - b)) % 26
            pt += chr(x + (A if c.isupper() else a))
        else:
            pt += c

    return pt


def main():
    ct = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

    # Known plaintext "ab" -> ciphertext "GL"
    p1 = ord('a') - a
    p2 = ord('b') - a
    c1 = ord('G') - A
    c2 = ord('L') - A

    print("Possible plaintexts:")

    for k in range(26):
        if math.gcd(k, 26) == 1:
            b = (c1 - k * p1) % 26

            # Verify with second known pair
            if (k * p2 + b) % 26 == c2:
                pt = decrypt(ct, k, b)
                print("a =", k, "b =", b, "->", pt)


if __name__ == "__main__":
    main()