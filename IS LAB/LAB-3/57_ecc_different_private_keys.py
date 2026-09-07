"""
Question 57: Ecc different private keys

Use different private keys with the same curve and calculate the corresponding public keys.
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
        m = ((3 * x1 * x1 + a) * inv(2 * y1, p)) % p

    # Point addition
    else:
        m = ((y2 - y1) * inv(x2 - x1, p)) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def mul(k, P, a, p):
    # Calculate kP using repeated doubling
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

    # Same base point G for all private keys
    gx = int(input("Enter Gx: "))
    gy = int(input("Enter Gy: "))

    G = (gx, gy)

    # Enter different private keys
    ds = list(map(int, input("Enter private keys separated by space: ").split()))

    print("\n--- ECC Public Keys ---")

    # Calculate public key for each private key
    for d in ds:
        Q = mul(d, G, a, p)

        print("Private Key:", d)
        print("Public Key Q = dG:", Q)
        print()


if __name__ == "__main__":
    main()