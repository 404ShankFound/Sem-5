"""11. Railfence cipher."""

def encrypt(pt, n):
    rail = [""] * n
    r = 0
    d = 1

    for c in pt:
        rail[r] += c

        if r == 0:
            d = 1
        elif r == n - 1:
            d = -1

        r += d

    ct = "".join(rail)
    print("CipherText:", ct)


def decrypt(ct, n):
    # Find the rail number for each character
    pos = []
    r = 0
    d = 1

    for c in ct:
        pos.append(r)

        if r == 0:
            d = 1
        elif r == n - 1:
            d = -1

        r += d

    # Count characters in each rail
    cnt = [pos.count(i) for i in range(n)]

    # Fill rails from ciphertext
    rail = []
    j = 0

    for x in cnt:
        rail.append(list(ct[j:j+x]))
        j += x

    # Read characters in zig-zag order
    pt = ""
    ind = [0] * n

    for r in pos:
        pt += rail[r][ind[r]]
        ind[r] += 1

    print("PlainText:", pt)


def main():
    while True:
        ch = int(input("\n1. Encrypt\n2. Decrypt\n3. Exit\nChoice: "))

        if ch == 1:
            pt = input("Enter plaintext: ")
            n = int(input("Enter number of rails: "))
            encrypt(pt, n)

        elif ch == 2:
            ct = input("Enter ciphertext: ")
            n = int(input("Enter number of rails: "))
            decrypt(ct, n)

        else:
            break


if __name__ == "__main__":
    main()