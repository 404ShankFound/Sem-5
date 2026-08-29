"""10. Hill cipher."""

import math
import numpy as np

A = ord('A')
a = ord('a')

def get_inverse(K):
    n = len(K)

    aug = [K[i][:] + [1 if i == j else 0 for j in range(n)]
           for i in range(n)]

    for i in range(n):

        # Find an invertible pivot
        p = i
        while p < n and math.gcd(aug[p][i] % 26, 26) != 1:
            p += 1

        if p == n:
            return None

        aug[i], aug[p] = aug[p], aug[i]

        inv = pow(aug[i][i] % 26, -1, 26)

        # Make pivot = 1
        for j in range(2*n):
            aug[i][j] = (aug[i][j] * inv) % 26

        # Make other elements in column = 0
        for r in range(n):
            if r != i:
                x = aug[r][i]
                for j in range(2*n):
                    aug[r][j] = (aug[r][j] - x*aug[i][j]) % 26

    return [row[n:] for row in aug]


def encrypt(pt, K):
    n = len(K)

    # Remove non-alphabet characters
    s = "".join(c for c in pt if c.isalpha()).lower()

    # Add x if length is not divisible by matrix size
    while len(s) % n != 0:
        s += 'x'

    ct = ""

    for i in range(0, len(s), n):
        p = [ord(c)-a for c in s[i:i+n]]

        for row in K:
            x = sum(row[j]*p[j] for j in range(n)) % 26
            ct += chr(x+a)

    print("CipherText:", ct)


def decrypt(ct, K):
    K = get_inverse(K)

    if K is None:
        print("Matrix is NOT invertible")
        return

    n = len(K)
    s = "".join(c for c in ct if c.isalpha()).lower()

    pt = ""

    for i in range(0, len(s), n):
        c = [ord(x)-a for x in s[i:i+n]]

        for row in K:
            x = sum(row[j]*c[j] for j in range(n)) % 26
            pt += chr(x+a)

    print("PlainText:", pt)


def main():

    while True:
        ch = int(input("\n1. Encrypt\n2. Decrypt\n3. Exit\nChoice: "))

        if ch == 1:
            n = int(input("Enter matrix dimension: "))

            nums = list(map(int, input(
                f"Enter {n*n} key numbers: ").split()))

            K = [nums[i:i+n] for i in range(0, n*n, n)]

            pt = input("Enter plaintext: ")
            encrypt(pt, K)

        elif ch == 2:
            n = int(input("Enter matrix dimension: "))

            nums = list(map(int, input(
                f"Enter {n*n} key numbers: ").split()))

            K = [nums[i:i+n] for i in range(0, n*n, n)]

            ct = input("Enter ciphertext: ")
            decrypt(ct, K)

        else:
            break


if __name__ == "__main__":
    main()