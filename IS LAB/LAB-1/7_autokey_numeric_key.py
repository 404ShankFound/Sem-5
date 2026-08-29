"""7. Autokey with numeric key."""

A = ord('A')
a = ord('a')

def encrypt(pt, k):
    ct = ""
    cur = k

    for c in pt:
        if c.isalpha():
            b = A if c.isupper() else a
            p = ord(c) - b
            c1 = (p + cur) % 26
            ct += chr(c1 + b)
            cur = p
        else:
            ct += c

    print("CipherText:", ct)


def decrypt(ct, k):
    pt = ""
    cur = k

    for c in ct:
        if c.isalpha():
            b = A if c.isupper() else a
            c1 = ord(c) - b
            p = (c1 - cur) % 26
            pt += chr(p + b)
            cur = p
        else:
            pt += c

    print("PlainText:", pt)


def main():
    while True:
        ch = int(input("\n1. Encrypt\n2. Decrypt\n3. Exit\nChoice: "))

        if ch == 1:
            pt = input("Enter plaintext: ")
            k = int(input("Enter numeric key: "))
            encrypt(pt, k)

        elif ch == 2:
            ct = input("Enter ciphertext: ")
            k = int(input("Enter numeric key: "))
            decrypt(ct, k)

        else:
            break


if __name__ == "__main__":
    main()