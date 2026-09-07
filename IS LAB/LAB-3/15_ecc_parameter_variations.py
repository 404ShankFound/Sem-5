"""
15. ecc_parameter_variations

Modify ECC for different curve parameters, base points and private keys;
calculate the corresponding public keys and perform the required
cryptographic operation.
"""


# Check whether a point lies on the curve
def valid_point(P, a, b, p):

    if P is None:
        return True

    x, y = P

    # y^2 = x^3 + ax + b (mod p)
    return (y * y - (x * x * x + a * x + b)) % p == 0


# Point addition: P + Q
def add(P, Q, a, p):

    # Point at infinity
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

        m = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p

    # Normal point addition
    else:

        m = ((y2 - y1) * pow(x2 - x1, -1, p)) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


# Scalar multiplication: kP
def mul(k, P, a, p):

    R = None

    while k > 0:

        if k % 2 == 1:
            R = add(R, P, a, p)

        P = add(P, P, a, p)

        k = k // 2

    return R


def get_params():

    print("\nEnter ECC parameters")

    p = int(input("Enter prime p: "))
    a = int(input("Enter curve parameter a: "))
    b = int(input("Enter curve parameter b: "))

    print("Curve: y^2 = x^3 +", a, "x +", b, "mod", p)

    return p, a, b


def get_point(p, a, b):

    x = int(input("Enter base point x: "))
    y = int(input("Enter base point y: "))

    P = (x, y)

    if not valid_point(P, a, b, p):
        print("Invalid point. Point does not lie on the curve.")
        return None

    return P


def option1():

    # Default ECC parameters
    p = 17
    a = 2
    b = 2
    G = (5, 1)

    print("\nDefault ECC parameters:")
    print("p =", p)
    print("a =", a)
    print("b =", b)
    print("G =", G)

    d = int(input("Enter private key d: "))

    Q = mul(d, G, a, p)

    print("Public Key Q = dG:", Q)


def option2():

    p, a, b = get_params()

    G = get_point(p, a, b)

    if G is None:
        return

    print("Valid Base Point G:", G)

    d = int(input("Enter private key d: "))

    if d <= 0:
        print("Private key must be positive.")
        return

    Q = mul(d, G, a, p)

    print("Private Key d:", d)
    print("Public Key Q = dG:", Q)


def option3():

    p, a, b = get_params()

    G = get_point(p, a, b)

    if G is None:
        return

    print("Base Point G:", G)

    k = int(input("Enter scalar k: "))

    if k <= 0:
        print("Scalar must be positive.")
        return

    R = mul(k, G, a, p)

    print("Scalar k:", k)
    print("Result kG:", R)


def option4():

    p, a, b = get_params()

    P = get_point(p, a, b)

    if P is None:
        return

    Q = get_point(p, a, b)

    if Q is None:
        return

    print("P =", P)
    print("Q =", Q)

    R = add(P, Q, a, p)

    print("P + Q =", R)


def option5():

    p, a, b = get_params()

    P = get_point(p, a, b)

    if P is None:
        return

    R = add(P, P, a, p)

    print("P =", P)
    print("2P =", R)


def option6():

    p, a, b = get_params()

    G = get_point(p, a, b)

    if G is None:
        return

    d1 = int(input("Enter Alice private key dA: "))
    d2 = int(input("Enter Bob private key dB: "))

    if d1 <= 0 or d2 <= 0:
        print("Private keys must be positive.")
        return

    # Alice public key
    QA = mul(d1, G, a, p)

    # Bob public key
    QB = mul(d2, G, a, p)

    # Shared secret
    SA = mul(d1, QB, a, p)
    SB = mul(d2, QA, a, p)

    print("\nAlice Public Key QA:", QA)
    print("Bob Public Key QB:", QB)

    print("Alice Shared Secret:", SA)
    print("Bob Shared Secret:", SB)

    print("Shared Secret Same:", SA == SB)


def option7():

    p, a, b = get_params()

    G = get_point(p, a, b)

    if G is None:
        return

    print("\nTesting different private keys")

    n = int(input("How many private keys? "))

    for i in range(n):

        d = int(input("Enter private key d: "))

        if d <= 0:
            print("Invalid private key.")
            continue

        Q = mul(d, G, a, p)

        print("d =", d, "-> Q =", Q)


def main():

    while True:

        print("\n========== ECC PARAMETER VARIATIONS ==========")
        print("1. Default curve + private key")
        print("2. Change curve parameters + base point + private key")
        print("3. Change curve parameters + base point + scalar")
        print("4. Point addition with custom points")
        print("5. Point doubling with custom point")
        print("6. ECDH with custom curve, base point and private keys")
        print("7. Test multiple private keys")
        print("8. Exit")

        ch = int(input("Enter your choice: "))

        if ch == 1:
            option1()

        elif ch == 2:
            option2()

        elif ch == 3:
            option3()

        elif ch == 4:
            option4()

        elif ch == 5:
            option5()

        elif ch == 6:
            option6()

        elif ch == 7:
            option7()

        elif ch == 8:
            print("Exiting...")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()