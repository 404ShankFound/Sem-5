"""9. Playfair cipher."""

def encrypt(pt, key):
    key = "".join(dict.fromkeys(key.lower().replace('j', 'i')))
    alpha = "abcdefghiklmnopqrstuvwxyz"

    # Create 5x5 matrix
    x = []
    for c in key + alpha:
        if c not in x and c.isalpha():
            x.append(c)

    mat = [x[i:i+5] for i in range(0, 25, 5)]

    print("Matrix:")
    for row in mat:
        print(" ".join(row).upper())

    # Find position of character
    def pos(c):
        for i in range(5):
            for j in range(5):
                if mat[i][j] == c:
                    return i, j

    # Prepare plaintext pairs
    s = "".join(c.lower().replace('j', 'i') for c in pt if c.isalpha())
    pairs = []
    i = 0

    while i < len(s):
        if i+1 == len(s):   #Checks if we encounter last element as single
            pairs.append(s[i] + 'x')
            i += 1
        elif s[i] == s[i+1]:    #Checks for repeatition
            pairs.append(s[i] + 'x')
            i += 1
        else:
            pairs.append(s[i:i+2])
            i += 2

    # Encrypt pairs
    ct = ""

    for p in pairs:
        r1, c1 = pos(p[0])
        r2, c2 = pos(p[1])

        if r1 == r2:
            ct += mat[r1][(c1+1)%5] + mat[r2][(c2+1)%5]

        elif c1 == c2:
            ct += mat[(r1+1)%5][c1] + mat[(r2+1)%5][c2]

        else:
            ct += mat[r1][c2] + mat[r2][c1]

    print("CipherText:", ct)


def decrypt(ct, key):
    key = "".join(dict.fromkeys(key.lower().replace('j', 'i')))
    alpha = "abcdefghiklmnopqrstuvwxyz"

    # Create 5x5 matrix
    x = []
    for c in key + alpha:
        if c not in x and c.isalpha():
            x.append(c)

    mat = [x[i:i+5] for i in range(0, 25, 5)]

    def pos(c):
        for i in range(5):
            for j in range(5):
                if mat[i][j] == c:
                    return i, j

    # Decrypt pairs
    ct = "".join(c.lower().replace('j', 'i') for c in ct if c.isalpha())
    pt = ""

    for i in range(0, len(ct), 2):
        p = ct[i:i+2]

        r1, c1 = pos(p[0])
        r2, c2 = pos(p[1])

        if r1 == r2:
            pt += mat[r1][(c1-1)%5] + mat[r2][(c2-1)%5]

        elif c1 == c2:
            pt += mat[(r1-1)%5][c1] + mat[(r2-1)%5][c2]

        else:
            pt += mat[r1][c2] + mat[r2][c1]

    print("PlainText:", pt)


def main():
    while True:
        ch = int(input("\n1. Encrypt\n2. Decrypt\n3. Exit\nChoice: "))

        if ch == 1:
            pt = input("Enter plaintext: ")
            key = input("Enter key: ")
            encrypt(pt, key)

        elif ch == 2:
            ct = input("Enter ciphertext: ")
            key = input("Enter key: ")
            decrypt(ct, key)

        else:
            break


if __name__ == "__main__":
    main()