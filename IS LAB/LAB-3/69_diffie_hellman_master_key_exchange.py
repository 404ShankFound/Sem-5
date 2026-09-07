"""
Question 69: Diffie-Hellman Master Key Exchange

Implement an interactive Diffie-Hellman system supporting fixed/user-input private keys, random private keys, parameter validation, shared-secret verification, different valid generators, and multiple user/pair demonstrations.

Flow:
Input / Generate
p, g, a, b
      ↓
Validate Parameters
      ↓
Public Keys
A = g^a mod p
B = g^b mod p
      ↓
Shared Secret
      ↓
┌───────────────────────┐
│ Alice: B^a mod p      │
│ Bob:   A^b mod p      │
└────────────┬──────────┘
             ↓
       Verify Equal
             ↓
     SUCCESS / FAILURE

Menu should support:
1. Fixed/User Private Keys
2. Random Private Keys
3. Parameter Validation
4. Shared Secret Verification
5. Different Generator Values
6. Multiple Users/Pairs
7. Exit

Requirements:
- Input p,g,a,b
- Generate random private keys
- Validate parameters
- Calculate public keys
- Calculate shared secrets independently
- Verify equality
- Test different valid generators
- Demonstrate multiple users/pairs
- Handle invalid parameters and input

Absorbs: original Q73–79.

"""

import random


def valid(p, g):
    # Basic DH parameter validation
    if p <= 2:
        return False

    if g <= 1 or g >= p:
        return False

    return True


def exchange(p, g, a, b):
    # Calculate Alice and Bob public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Calculate shared secrets independently
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)

    return A, B, s1, s2


def show(p, g, a, b):
    A, B, s1, s2 = exchange(p, g, a, b)

    print("\n--- Diffie-Hellman Exchange ---")
    print("p:", p)
    print("g:", g)
    print("Alice Private Key:", a)
    print("Bob Private Key:", b)
    print("Alice Public Key:", A)
    print("Bob Public Key:", B)
    print("Alice Shared Secret:", s1)
    print("Bob Shared Secret:", s2)

    if s1 == s2:
        print("SUCCESS: Shared secrets are equal.")
    else:
        print("FAILURE: Shared secrets are different.")


def main():
    print("--- Diffie-Hellman Master System ---")

    try:
        p = int(input("Enter prime p: "))
        g = int(input("Enter generator g: "))

        if not valid(p, g):
            print("Error: Invalid DH parameters.")
            return

    except ValueError:
        print("Error: Enter valid numeric values.")
        return

    while True:
        print("\n--- Menu ---")
        print("1. Fixed/User Private Keys")
        print("2. Random Private Keys")
        print("3. Parameter Validation")
        print("4. Shared Secret Verification")
        print("5. Different Generator Values")
        print("6. Multiple Users/Pairs")
        print("7. Exit")

        ch = input("Enter choice: ")

        try:
            if ch == "1":
                # Accept Alice and Bob private keys
                a = int(input("Enter Alice private key a: "))
                b = int(input("Enter Bob private key b: "))

                if a <= 0 or b <= 0:
                    print("Error: Private keys must be positive.")
                    continue

                show(p, g, a, b)

            elif ch == "2":
                # Generate random private keys
                a = random.randint(2, p - 2)
                b = random.randint(2, p - 2)

                print("\nRandom private keys generated.")
                show(p, g, a, b)

            elif ch == "3":
                # Validate current DH parameters
                print("\n--- Parameter Validation ---")

                if valid(p, g):
                    print("p is valid.")
                    print("g is within the valid range.")
                    print("Parameters are valid.")
                else:
                    print("Invalid DH parameters.")

            elif ch == "4":
                # Calculate and explicitly verify both shared secrets
                a = int(input("Enter Alice private key a: "))
                b = int(input("Enter Bob private key b: "))

                if a <= 0 or b <= 0:
                    print("Error: Private keys must be positive.")
                    continue

                A = pow(g, a, p)
                B = pow(g, b, p)

                s1 = pow(B, a, p)
                s2 = pow(A, b, p)

                print("\nAlice Shared Secret:", s1)
                print("Bob Shared Secret:", s2)

                if s1 == s2:
                    print("SUCCESS")
                else:
                    print("FAILURE")

            elif ch == "5":
                # Test different generator values
                gs = list(map(int, input(
                    "Enter generator values separated by space: "
                ).split()))

                print("\n--- Generator Comparison ---")

                a = int(input("Enter Alice private key a: "))
                b = int(input("Enter Bob private key b: "))

                for g2 in gs:
                    if not valid(p, g2):
                        print("g =", g2, ": Invalid")
                        continue

                    A, B, s1, s2 = exchange(p, g2, a, b)

                    print("\ng =", g2)
                    print("Alice Public Key:", A)
                    print("Bob Public Key:", B)
                    print("Shared Secret:", s1)

                    if s1 == s2:
                        print("Verification: SUCCESS")
                    else:
                        print("Verification: FAILURE")

            elif ch == "6":
                # Demonstrate multiple independent user pairs
                n = int(input("Enter number of user pairs: "))

                if n <= 0:
                    print("Error: Number of pairs must be positive.")
                    continue

                print("\n--- Multiple User Pairs ---")

                for i in range(1, n + 1):
                    a = random.randint(2, p - 2)
                    b = random.randint(2, p - 2)

                    A, B, s1, s2 = exchange(p, g, a, b)

                    print("\nPair", i)
                    print("Alice Private:", a)
                    print("Bob Private:", b)
                    print("Alice Public:", A)
                    print("Bob Public:", B)
                    print("Shared Secret:", s1)

                    if s1 == s2:
                        print("Verification: SUCCESS")
                    else:
                        print("Verification: FAILURE")

            elif ch == "7":
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