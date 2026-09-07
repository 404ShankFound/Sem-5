"""20. Keyless transposition."""

def encrypt(pt, n):
    ct = ""

    for i in range(n):
        for j in range(i, len(pt), n):
            ct += pt[j]

    return ct


def decrypt(ct, n):
    pt = ""
    r = (len(ct) + n - 1) // n

    for i in range(r):
        for j in range(i, len(ct), r):
            pt += ct[j]

    return pt


def main():
    pt = input("Enter plaintext: ")
    n = int(input("Enter number of columns: "))

    ct = encrypt(pt, n)
    print("CipherText:", ct)

    pt = decrypt(ct, n)
    print("PlainText:", pt)


if __name__ == "__main__":
    main()