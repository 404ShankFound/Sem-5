"""6. Vigenere cipher with text key."""

A = ord('A')
a = ord('a')

def encrypt(pt, key):
    ct = ""
    j = 0

    for c in pt:
        if c.isalpha():

            b = A if c.isupper() else a

            # Convert key character to 0-51
            k = key[j % len(key)]
            if k.isupper():
                k = ord(k) - A
            else:
                k = ord(k) - a + 26

            n = (ord(c) - b if c.isupper() else ord(c) - a + 26)
            n = (n + k) % 52

            # Convert 0-51 back to A-Z / a-z
            if n < 26:
                ct += chr(n + A)
            else:
                ct += chr(n - 26 + a)

            j += 1

        else:
            ct += c

    print("CipherText:", ct)


def decrypt(ct, key):
    pt = ""
    j = 0

    for c in ct:
        if c.isalpha():

            # Convert ciphertext character to 0-51
            if c.isupper():
                n = ord(c) - A
            else:
                n = ord(c) - a + 26

            # Convert key character to 0-51
            k = key[j % len(key)]
            if k.isupper():
                k = ord(k) - A
            else:
                k = ord(k) - a + 26

            n = (n - k) % 52

            # Convert 0-51 back to A-Z / a-z
            if n < 26:
                pt += chr(n + A)
            else:
                pt += chr(n - 26 + a)

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