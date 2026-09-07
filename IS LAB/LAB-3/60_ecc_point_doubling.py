"""
Question 60: Ecc point doubling

Given a point P, calculate 2P using elliptic-curve point doubling.
"""


def inv(a, p):
    return pow(a, -1, p)


def double(P, a, p):
    x1, y1 = P

    # If y1 = 0, then 2P is the point at infinity
    if y1 % p == 0:
        return None

    # Point doubling slope
    m = ((3 * x1 * x1 + a) * inv(2 * y1, p)) % p

    # Calculate 2P
    x3 = (m * m - 2 * x1) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def main():
    # Elliptic curve: y^2 = x^3 + ax + b mod p
    p = int(input("Enter prime p: "))
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))

    # Point P
    x = int(input("Enter P.x: "))
    y = int(input("Enter P.y: "))

    P = (x, y)

    # Calculate 2P
    R = double(P, a, p)

    print("\n--- ECC Point Doubling ---")
    print("P =", P)

    if R is None:
        print("2P = Point at Infinity")
    else:
        print("2P =", R)
        print("x =", R[0])
        print("y =", R[1])


if __name__ == "__main__":
    main()