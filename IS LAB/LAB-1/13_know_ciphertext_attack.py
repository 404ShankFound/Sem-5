"""13. Ciphertext-only attack."""

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
    for k in range(1, 26):
        print("Key =", k, "->", decrypt_shift(ct, k))


def main():
    ct = input("Enter ciphertext: ")

    print("\nPossible plaintexts:")

    ciphertext_only_attack(ct)


if __name__ == "__main__":
    main()