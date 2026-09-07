"""16. Ciphertext-Only Attack (COA)."""

A = ord('A')
a = ord('a')


def decrypt_shift(ct, k):
    pt = ""

    for c in ct:
        if c.isalpha():
            b = A if c.isupper() else a
            pt += chr((ord(c) - b - k) % 26 + b)
        else:
            pt += c

    return pt


def ciphertext_only_attack(ct):
    for k in range(26):
        pt = decrypt_shift(ct, k)
        print("Key =", k, "PlainText =", pt)


def main():
    ct = input("Enter ciphertext: ")

    print("\nPossible plaintexts:")

    ciphertext_only_attack(ct)


if __name__ == "__main__":
    main()