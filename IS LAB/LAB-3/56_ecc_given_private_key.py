"""
Question 56: Ecc given private key

Given a curve, base point G, and private key d, calculate and display the public key Q=dG.
"""

def inv(a, p):
    return pow(a, -1, p)

def add(P, Q, a, p):
    # If P is point at infinity, return Q
    if P is None:
        return Q

    # If Q is point at infinity, return P
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # P + (-P) = point at infinity
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    # Point doubling
    if P == Q:
        m = ((3 * x1 * x1 + a) * inv(2 * y1, p)) % p

    # Point addition
    else:
        m = ((y2 - y1) * inv(x2 - x1, p)) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def mul(k, P, a, p):
    # Scalar multiplication: kP
    R = None

    while k > 0:
        if k % 2 == 1:
            R = add(R, P, a, p)

        P = add(P, P, a, p)
        k //= 2

    return R


def main():
    # Curve: y^2 = x^3 + ax + b mod p
    p = int(input("Enter prime p: "))
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))

    # Base point G
    gx = int(input("Enter Gx: "))
    gy = int(input("Enter Gy: "))

    # Private key
    d = int(input("Enter private key d: "))

    G = (gx, gy)

    # Calculate public key Q = dG
    Q = mul(d, G, a, p)

    print("\n--- ECC Public Key ---")
    print("Base Point G:", G)
    print("Private Key d:", d)
    print("Public Key Q = dG:", Q)

    if Q is not None:
        print("Qx =", Q[0])
        print("Qy =", Q[1])


if __name__ == "__main__":
    main()