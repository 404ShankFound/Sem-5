"""8. Autokey with text key."""

A = ord('A')
a = ord('a')

def encrypt(pt, key):
    ct = ""
    key = key.lower()
    j = 0

    for c in pt:
        if c.isalpha():
            b = A if c.isupper() else a
            p = ord(c) - b

            if j < len(key):
                k = ord(key[j]) - a
            else:
                k = ord(pt[j - len(key)]) - (A if pt[j - len(key)].isupper() else a)

            c1 = (p + k) % 26
            ct += chr(c1 + b)
            j += 1

        else:
            ct += c

    print("CipherText:", ct)


def decrypt(ct, key):
    pt = ""
    key = key.lower()
    j = 0

    for c in ct:
        if c.isalpha():
            b = A if c.isupper() else a
            c1 = ord(c) - b

            if j < len(key):
                k = ord(key[j]) - a
            else:
                k = ord(pt[j - len(key)].lower()) - a

            p = (c1 - k) % 26
            pt += chr(p + b)
            j += 1

        else:
            pt += c

    print("PlainText:", pt)


def main():
    while True:
        ch = int(input("\n1. Encrypt\n2. Decrypt\n3. Exit\nChoice: "))

        if ch == 1:
            pt = input("Enter plaintext: ")
            key = input("Enter text key: ")
            encrypt(pt, key)

        elif ch == 2:
            ct = input("Enter ciphertext: ")
            key = input("Enter text key: ")
            decrypt(ct, key)

        else:
            break


if __name__ == "__main__":
    main()