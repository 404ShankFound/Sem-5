"""
Question 65: ECC Key Generation and Public Key Operations

Generate ECC key pairs using a selected/fixed curve and display the private key and public point coordinates separately. Allow multiple private keys to be used with the same curve/base point to demonstrate the corresponding public keys.

Flow:
Select Curve
     ↓
Generate / Enter Private Key
     ↓
Q = dG
     ↓
Display
 ┌───────────────┐
 │ Private key d │
 │ Public Q      │
 │ Q.x           │
 │ Q.y           │
 └───────────────┘
     ↓
Optional: Different d values
     ↓
Compare Public Keys

Requirements:
- Support secp256r1
- Display private key
- Display public point (x,y)
- Accept/use different private keys
- Calculate corresponding public keys
- Reuse the same curve/base point when comparing private keys

Absorbs: original Q54, Q56, Q57, Q58.

"""

from Crypto.PublicKey import ECC


def main():
    print("--- ECC Key Generation ---")

    # Use fixed secp256r1 curve
    curve = "secp256r1"

    while True:
        print("\n--- Menu ---")
        print("1. Generate ECC Key Pair")
        print("2. Use Different Private Keys")
        print("3. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            # Generate ECC key pair
            key = ECC.generate(curve=curve)

            # Get private key
            d = key.d

            # Get public point
            Q = key.pointQ

            print("\n--- ECC Key Pair ---")
            print("Curve:", curve)
            print("Private Key d:", d)
            print("Public Point Q:")
            print("x =", Q.x)
            print("y =", Q.y)

        elif ch == "2":
            print("\nUsing the same curve:", curve)

            try:
                ds = list(map(int, input(
                    "Enter private keys separated by space: "
                ).split()))

                for d in ds:
                    # Create ECC private key from supplied d
                    key = ECC.construct(curve=curve, d=d)

                    # Calculate corresponding public point Q = dG
                    Q = key.pointQ

                    print("\nPrivate Key d:", d)
                    print("Public Key Q = dG:")
                    print("x =", Q.x)
                    print("y =", Q.y)

            except ValueError:
                print("Error: Enter valid private key values.")
            except Exception as e:
                print("Error:", e)

        elif ch == "3":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")


if __name__ == "__main__":
    main()