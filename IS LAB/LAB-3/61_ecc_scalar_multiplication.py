"""
Question 61: Ecc scalar multiplication

Given a point P and integer k, calculate kP using repeated point addition/doubling.
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

    # Point doubling
    if P == Q:
        if y1 % p == 0:
            return None

        m = ((3 * x1 * x1 + a) * inv(2 * y1, p)) % p

    # Point addition
    else:
        m = ((y2 - y1) * inv(x2 - x1, p)) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def mul(k, P, a, p):
    # Calculate kP using repeated addition and doubling
    R = None

    while k > 0:
        # Add P when current bit of k is 1
        if k % 2 == 1:
            R = add(R, P, a, p)

        # Double P
        P = add(P, P, a, p)

        # Move to next bit
        k //= 2

    return R


def main():
    # Elliptic curve: y^2 = x^3 + ax + b mod p
    p = int(input("Enter prime p: "))
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))

    # Point P
    x = int(input("Enter P.x: "))
    y = int(input("Enter P.y: "))

    # Integer k
    k = int(input("Enter k: "))

    P = (x, y)

    # Calculate kP
    R = mul(k, P, a, p)

    print("\n--- ECC Scalar Multiplication ---")
    print("P =", P)
    print("k =", k)

    if R is None:
        print("kP = Point at Infinity")
    else:
        print("kP =", R)
        print("x =", R[0])
        print("y =", R[1])


if __name__ == "__main__":
    main()