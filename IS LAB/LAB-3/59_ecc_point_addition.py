"""
Question 59: Ecc point addition

Given two points on an elliptic curve, calculate their point addition and display the resulting point.
"""


def inv(a, p):
    return pow(a, -1, p)


def add(P, Q, a, p):
    # If P is point at infinity, P + Q = Q
    if P is None:
        return Q

    # If Q is point at infinity, P + Q = P
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # P + (-P) = point at infinity
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    # Point doubling: P + P
    if P == Q:
        m = ((3 * x1 * x1 + a) * inv(2 * y1, p)) % p

    # Normal point addition: P + Q
    else:
        m = ((y2 - y1) * inv(x2 - x1, p)) % p

    # Calculate resulting point
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def main():
    # Elliptic curve: y^2 = x^3 + ax + b mod p
    p = int(input("Enter prime p: "))
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))

    # First point P
    x1 = int(input("Enter P.x: "))
    y1 = int(input("Enter P.y: "))

    # Second point Q
    x2 = int(input("Enter Q.x: "))
    y2 = int(input("Enter Q.y: "))

    P = (x1, y1)
    Q = (x2, y2)

    # Calculate P + Q
    R = add(P, Q, a, p)

    print("\n--- ECC Point Addition ---")
    print("P =", P)
    print("Q =", Q)

    if R is None:
        print("P + Q = Point at Infinity")
    else:
        print("P + Q =", R)
        print("x =", R[0])
        print("y =", R[1])


if __name__ == "__main__":
    main()