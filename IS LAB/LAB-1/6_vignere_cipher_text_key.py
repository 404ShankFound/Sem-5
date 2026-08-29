"""6. Vigenere cipher with text key."""

A = ord('A')
a = ord('a')

def encrypt(pt, key):
    ct = ""
    key = key.lower()
    j = 0

    for c in pt:
        if c.isalpha():
            b = A if c.isupper() else a
            k = ord(key[j % len(key)]) - a
            ct += chr((ord(c) - b + k) % 26 + b)
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
            k = ord(key[j % len(key)]) - a
            pt += chr((ord(c) - b - k) % 26 + b)
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

