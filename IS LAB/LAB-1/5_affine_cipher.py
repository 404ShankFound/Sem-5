import math

A = ord('A')
a = ord('a')

def encrypt(pt, x, b):
    ct = ""

    for c in pt:
        if c.isalpha():
            z = A if c.isupper() else a
            ct += chr((x*(ord(c)-z) + b) % 26 + z)

        elif c.isdigit():
            ct += str((x*int(c) + b) % 10)

        else:
            ct += c

    print("CipherText:", ct)


def decrypt(ct, x, b):
    pt = ""

    x1 = pow(x, -1, 26)
    x2 = pow(x, -1, 10)

    for c in ct:
        if c.isalpha():
            z = A if c.isupper() else a
            pt += chr((x1*(ord(c)-z-b)) % 26 + z)

        elif c.isdigit():
            pt += str((x2*(int(c)-b)) % 10)

        else:
            pt += c

    print("PlainText:", pt)


def main():
    while True:
        ch = int(input("\n1. Encrypt\n2. Decrypt\n3. Exit\nChoice: "))

        if ch == 1:
            pt = input("Enter plaintext: ")
            x = int(input("Enter a: "))
            b = int(input("Enter b: "))

            if math.gcd(x % 26, 26) == 1 and math.gcd(x % 10, 10) == 1:
                encrypt(pt, x, b)
            else:
                print("Key cannot be used")

        elif ch == 2:
            ct = input("Enter ciphertext: ")
            x = int(input("Enter a: "))
            b = int(input("Enter b: "))

            if math.gcd(x % 26, 26) == 1 and math.gcd(x % 10, 10) == 1:
                decrypt(ct, x, b)
            else:
                print("Key cannot be used")

        else:
            break


if __name__ == "__main__":
    main()