"""22. Combined Columnar transposition."""

def encrypt(pt, key):
    n = len(key)
    ct = ""

    for i in sorted(range(n), key=lambda x: key[x]):
        for j in range(i, len(pt), n):
            ct += pt[j]

    return ct


def decrypt(ct, key):
    n = len(key)
    r = (len(ct) + n - 1) // n
    pt = [""] * len(ct)

    k = 0
    for i in sorted(range(n), key=lambda x: key[x]):
        for j in range(i, len(ct), n):
            pt[j] = ct[k]
            k += 1

    return "".join(pt)


def main():
    pt = input("Enter plaintext: ")
    k1 = input("Enter first key: ")
    k2 = input("Enter second key: ")

    ct = encrypt(pt, k1)
    ct = encrypt(ct, k2)

    print("CipherText:", ct)

    pt = decrypt(ct, k2)
    pt = decrypt(pt, k1)

    print("PlainText:", pt)


if __name__ == "__main__":
    main()