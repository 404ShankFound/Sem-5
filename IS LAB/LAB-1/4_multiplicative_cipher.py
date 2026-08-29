import math

A = ord('A')
a = ord('a')

def encrypt(pt, k):
    ct = ""

    for c in pt:
        if c.isalpha():
            b = A if c.isupper() else a
            ct += chr(((ord(c)-b)*k) % 26 + b)

        elif c.isdigit():
            ct += str((int(c)*k) % 10)

        else:
            ct += c

    print("CipherText:", ct)


def decrypt(ct, k):
    pt = ""

    # Inverse of key for letters and digits
    k1 = pow(k, -1, 26)
    k2 = pow(k, -1, 10)

    for c in ct:
        if c.isalpha():
            b = A if c.isupper() else a
            pt += chr(((ord(c)-b)*k1) % 26 + b)

        elif c.isdigit():
            pt += str((int(c)*k2) % 10)

        else:
            pt += c

    print("PlainText:", pt)


def main():
    while True:
        ch = int(input("\n1. Encrypt\n2. Decrypt\n3. Exit\nChoice: "))

        if ch == 1:
            pt = input("Enter plaintext: ")
            k = int(input("Enter key: "))

            if math.gcd(k % 26, 26) == 1 and math.gcd(k % 10, 10) == 1:
                encrypt(pt, k)
            else:
                print("Key cannot be used")

        elif ch == 2:
            ct = input("Enter ciphertext: ")
            k = int(input("Enter key: "))

            if math.gcd(k % 26, 26) == 1 and math.gcd(k % 10, 10) == 1:
                decrypt(ct, k)       # FIXED
            else:
                print("Key cannot be used")

        else:
            break


if __name__ == "__main__":
    main()