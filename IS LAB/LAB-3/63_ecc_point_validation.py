"""
Question 63: Ecc point validation

Check whether a given point (x,y) lies on the selected elliptic curve before performing operations.
"""


def valid(P, a, b, p):
    # Get x and y coordinates
    x, y = P

    # Check y^2 = x^3 + ax + b mod p
    return (y * y) % p == (x * x * x + a * x + b) % p


def main():
    # Elliptic curve: y^2 = x^3 + ax + b mod p
    p = int(input("Enter prime p: "))
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))

    # Given point
    x = int(input("Enter x: "))
    y = int(input("Enter y: "))

    P = (x, y)

    # Validate point before performing operations
    if valid(P, a, b, p):
        print("\nPoint", P, "lies on the elliptic curve.")
    else:
        print("\nPoint", P, "does not lie on the elliptic curve.")


if __name__ == "__main__":
    main()