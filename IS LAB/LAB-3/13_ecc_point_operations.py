"""
13. ecc_point_operations

Implement elliptic-curve point addition, point doubling and scalar
multiplication; use them to calculate public keys.
"""

# Elliptic curve:
# y^2 = x^3 + ax + b (mod p)

p = 17
a = 2
b = 2

# Base point G
G = (5, 1)


# Point addition: P + Q
def add(P, Q):
    # If P is the point at infinity
    if P is None:
        return Q

    # If Q is the point at infinity
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # P + (-P) = point at infinity
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    # Point doubling: P + P
    if P == Q:
        # If y1 = 0, tangent is vertical
        if y1 % p == 0:
            return None

        # Slope for doubling
        m = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p

    # Normal point addition
    else:
        # Slope
        m = ((y2 - y1) * pow(x2 - x1, -1, p)) % p

    # Calculate new x and y
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


# Scalar multiplication: kP
def mul(k, P):
    R = None

    # Repeatedly add P using double-and-add
    while k > 0:

        # If current bit is 1, add P to result
        if k % 2 == 1:
            R = add(R, P)

        # Double P
        P = add(P, P)

        # Move to next bit
        k = k // 2

    return R


def main():

    # Private key
    d = int(input("Enter private key d: "))

    # Calculate public key Q = dG
    Q = mul(d, G)

    print("Curve: y^2 = x^3 +", a, "x +", b, "mod", p)
    print("Base Point G:", G)
    print("Private Key d:", d)
    print("Public Key Q = dG:", Q)

    # Demonstrate point addition
    P = G
    R = mul(2, G)

    print("G + G:", R)

    # Demonstrate scalar multiplication
    k = int(input("Enter scalar k: "))
    print("kG:", mul(k, G))


if __name__ == "__main__":
    main()