"""
Question 62: Ecc combined operations

Implement point addition, point doubling and scalar multiplication and use them to calculate an ECC public key.
"""


def inv(a, p):
    return pow(a, -1, p)


def add(P, Q, a, p):
    # Handle point at infinity
    if P is None:
        return Q

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


def double(P, a, p):
    # Point doubling: 2P
    return add(P, P, a, p)


def mul(k, P, a, p):
    # Scalar multiplication: kP
    R = None

    while k > 0:
        # Add current point when bit is 1
        if k % 2 == 1:
            R = add(R, P, a, p)

        # Double the point
        P = double(P, a, p)

        # Move to next bit
        k //= 2

    return R


def main():
    # Elliptic curve: y^2 = x^3 + ax + b mod p
    p = int(input("Enter prime p: "))
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))

    # Base point G
    gx = int(input("Enter Gx: "))
    gy = int(input("Enter Gy: "))

    # Private key d
    d = int(input("Enter private key d: "))

    G = (gx, gy)

    # Calculate public key Q = dG
    Q = mul(d, G, a, p)

    print("\n--- ECC Combined Operations ---")
    print("Base Point G:", G)
    print("Private Key d:", d)

    # Show point doubling
    D = double(G, a, p)
    print("2G:", D)

    # Show scalar multiplication
    print("Public Key Q = dG:", Q)

    if Q is not None:
        print("Qx =", Q[0])
        print("Qy =", Q[1])


if __name__ == "__main__":
    main()