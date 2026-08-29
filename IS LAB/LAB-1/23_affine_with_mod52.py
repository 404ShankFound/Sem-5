import math

A = ord('A')
a = ord('a')

def encrypt(pt, x, b):
    ct = ""

    for c in pt:

        if c.isalpha():

            # Uppercase: A-Z -> 0-25
            if c.isupper():
                n = ord(c) - A
                n = (x * n + b) % 52
            # Lowercase: a-z -> 26-51
            else:
                n = ord(c) - a + 26
                n = (x * n + b) % 52

            # Convert 0-51 back to A-Z / a-z
            if n < 26:
                ct += chr(n + A)
            else:
                ct += chr(n - 26 + a)

        # Digits: 0-9 -> modulo 10
        elif c.isdigit():
            ct += str((x * int(c) + b) % 10)

        # Keep spaces and symbols unchanged
        else:
            ct += c

    print("CipherText:", ct)


def decrypt(ct, x, b):
    pt = ""

    # Modular inverse of x
    x1 = pow(x % 52, -1, 52)
    x2 = pow(x % 10, -1, 10)

    for c in ct:

        if c.isalpha():

            # Convert A-Z / a-z to 0-51
            if c.isupper():
                n = ord(c) - A
            else:
                n = ord(c) - a + 26

            # Decryption formula
            n = (x1 * (n - b)) % 52

            # Convert 0-51 back to character
            if n < 26:
                pt += chr(n + A)
            else:
                pt += chr(n - 26 + a)

        # Decrypt digits
        elif c.isdigit():
            pt += str((x2 * (int(c) - b)) % 10)

        # Keep spaces and symbols unchanged
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

            # a must be invertible in both Z-52 and Z-10
            if math.gcd(x % 52, 52) == 1 and math.gcd(x % 10, 10) == 1:
                encrypt(pt, x, b)
            else:
                print("Key cannot be used")

        elif ch == 2:

            ct = input("Enter ciphertext: ")
            x = int(input("Enter a: "))
            b = int(input("Enter b: "))

            # a must be invertible in both Z-52 and Z-10
            if math.gcd(x % 52, 52) == 1 and math.gcd(x % 10, 10) == 1:
                decrypt(ct, x, b)
            else:
                print("Key cannot be used")

        else:
            break


if __name__ == "__main__":
    main()

'''
EASIER METHOD:

alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def encrypt(pt, x, b):
    ct = ""

    for c in pt:
        if c in alpha:
            n = alpha.index(c)
            ct += alpha[(x*n+b) % 52]

        elif c.isdigit():
            ct += str((x*int(c)+b) % 10)

        else:
            ct += c

    print("CipherText:", ct)


def decrypt(ct, x, b):
    pt = ""

    x1 = pow(x, -1, 52)
    x2 = pow(x, -1, 10)

    for c in ct:
        if c in alpha:
            n = alpha.index(c)
            pt += alpha[(x1*(n-b)) % 52]

        elif c.isdigit():
            pt += str((x2*(int(c)-b)) % 10)

        else:
            pt += c

    print("PlainText:", pt)
'''