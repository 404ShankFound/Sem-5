"""
Question 64: ECC Master Point Operations and Validation

Implement an interactive ECC program that accepts an elliptic curve and supports point validation, point addition, point doubling, and scalar multiplication. The program must validate points before performing operations and display appropriate errors for invalid points.

Flow:
Curve Parameters
      ↓
Enter p, a, b
      ↓
Enter Point(s)
      ↓
Validate Point
      ↓
┌───────────────┬───────────────┬──────────────────┐
│ Point Add     │ Point Double  │ Scalar Multiply  │
│ P + Q         │ 2P            │ kP               │
└───────────────┴───────────────┴──────────────────┘
      ↓
Display Result

Requirements:
- Accept p, a, b
- Accept point coordinates
- Check whether points satisfy y² = x³ + ax + b mod p
- Handle invalid points
- Handle point at infinity
- Implement point addition
- Implement point doubling
- Implement scalar multiplication using repeated doubling/addition
- Display resulting coordinates
- Include suitable error messages

Absorbs: original Q59, Q60, Q61, Q63, Q64.

"""

def inv(a, p):
    return pow(a, -1, p)


def valid(P, a, b, p):
    if P is None:
        return True

    x, y = P

    return (y * y) % p == (x * x * x + a * x + b) % p


def add(P, Q, a, p):
    # Point at infinity cases
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
        # If y = 0, result is point at infinity
        if y1 % p == 0:
            return None

        m = ((3 * x1 * x1 + a) * inv(2 * y1, p)) % p

    # Normal point addition
    else:
        m = ((y2 - y1) * inv(x2 - x1, p)) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def mul(k, P, a, p):
    # Scalar multiplication using repeated doubling/addition
    R = None

    while k > 0:
        if k % 2 == 1:
            R = add(R, P, a, p)

        P = add(P, P, a, p)
        k //= 2

    return R


def get_point(name, a, b, p):
    x = int(input("Enter " + name + ".x: "))
    y = int(input("Enter " + name + ".y: "))

    P = (x, y)

    if not valid(P, a, b, p):
        print("Error: Point", P, "does not lie on the curve.")
        return None

    return P


def show(R):
    if R is None:
        print("Result: Point at Infinity")
    else:
        print("Result:", R)
        print("x =", R[0])
        print("y =", R[1])


def main():
    print("--- ECC Master Point Operations ---")

    # Curve: y² = x³ + ax + b mod p
    try:
        p = int(input("Enter prime p: "))
        a = int(input("Enter a: "))
        b = int(input("Enter b: "))

        if p <= 2:
            print("Error: p must be a prime greater than 2.")
            return

    except ValueError:
        print("Error: Enter valid numeric values.")
        return

    while True:
        print("\n--- Menu ---")
        print("1. Validate Point")
        print("2. Point Addition")
        print("3. Point Doubling")
        print("4. Scalar Multiplication")
        print("5. Exit")

        ch = input("Enter choice: ")

        try:
            if ch == "1":
                P = get_point("P", a, b, p)

                if P is not None:
                    print("Point is valid.")
                else:
                    print("Point is invalid.")

            elif ch == "2":
                P = get_point("P", a, b, p)

                if P is None:
                    continue

                Q = get_point("Q", a, b, p)

                if Q is None:
                    continue

                R = add(P, Q, a, p)

                print("\nP + Q:")
                show(R)

            elif ch == "3":
                P = get_point("P", a, b, p)

                if P is None:
                    continue

                R = add(P, P, a, p)

                print("\n2P:")
                show(R)

            elif ch == "4":
                P = get_point("P", a, b, p)

                if P is None:
                    continue

                k = int(input("Enter k: "))

                if k < 0:
                    print("Error: k must be non-negative.")
                    continue

                R = mul(k, P, a, p)

                print("\nkP:")
                show(R)

            elif ch == "5":
                print("Exiting...")
                break

            else:
                print("Error: Invalid menu choice.")

        except ValueError:
            print("Error: Enter valid numeric values.")
        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    main()