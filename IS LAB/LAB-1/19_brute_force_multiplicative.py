"""19. Brute force for Multiplicative."""

import math

def decrypt_multiplicative(ct, k):
    pt = ""
    k1 = pow(k, -1, 26)

    for c in ct:
        if c.isalpha():
            x = (ord(c) - ord('A')) * k1 % 26
            pt += chr(x + ord('A'))
        else:
            pt += c

    return pt


def main():
    ct = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

    print("Brute-Force Results Around Key 13:")

    # Birthday = 13, range = ±3
    for k in range(10, 17):
        if math.gcd(k, 26) == 1:
            pt = decrypt_multiplicative(ct, k)
            print("Key", k, ":", pt)


if __name__ == "__main__":
    main()