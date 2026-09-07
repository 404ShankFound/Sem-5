"""
Question 66: ECC ECDH Key Agreement and Verification

Generate Alice and Bob ECC key pairs, exchange public keys and independently calculate their shared secrets. Verify that both parties obtain the same shared secret.

Allow the curve/key parameters to be selected or entered where applicable.

Flow:
        ECC Curve
            ↓
    ┌───────────────┐
    │ Alice Key Pair │
    │ dA , QA        │
    └───────┬───────┘
            │ QA
            ↓
       Public Exchange
            ↑
            │ QB
    ┌───────┴───────┐
    │  Bob Key Pair  │
    │ dB , QB        │
    └───────────────┘
            ↓
 ┌─────────────────────────┐
 │ Alice: SA = dA × QB     │
 │ Bob:   SB = dB × QA     │
 └────────────┬────────────┘
              ↓
         SA == SB ?
          /              YES         NO
        ↓           ↓
     SUCCESS      FAILURE

Requirements:
- Generate Alice and Bob ECC key pairs
- Exchange public keys
- Calculate shared secrets independently
- Display both shared secrets
- Verify equality
- Support user-selected/entered parameters where practical
- Display SUCCESS/FAILURE

Absorbs: original Q65, Q66, Q67.

"""

from Crypto.PublicKey import ECC


def main():
    print("--- ECC ECDH Key Agreement ---")

    # Use the same curve for Alice and Bob
    curve = "secp256r1"

    while True:
        print("\n--- Menu ---")
        print("1. Generate Random Keys")
        print("2. Enter Private Keys")
        print("3. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            # Generate Alice and Bob ECC key pairs
            alice = ECC.generate(curve=curve)
            bob = ECC.generate(curve=curve)

        elif ch == "2":
            try:
                # Accept Alice and Bob private keys
                da = int(input("Enter Alice private key dA: "))
                db = int(input("Enter Bob private key dB: "))

                # Construct ECC keys using supplied private keys
                alice = ECC.construct(curve=curve, d=da)
                bob = ECC.construct(curve=curve, d=db)

            except ValueError:
                print("Error: Enter valid private key values.")
                continue
            except Exception as e:
                print("Error:", e)
                continue

        elif ch == "3":
            print("Exiting...")
            break

        else:
            print("Error: Invalid menu choice.")
            continue

        # Get private keys
        da = alice.d
        db = bob.d

        # Get public keys
        QA = alice.public_key().pointQ
        QB = bob.public_key().pointQ

        print("\n--- Alice ---")
        print("Private Key dA:", da)
        print("Public Key QA:")
        print("x =", QA.x)
        print("y =", QA.y)

        print("\n--- Bob ---")
        print("Private Key dB:", db)
        print("Public Key QB:")
        print("x =", QB.x)
        print("y =", QB.y)

        # Alice calculates shared point: SA = dA * QB
        SA = QA * 0  # placeholder for point type
        SA = alice.d * QB

        # Bob calculates shared point: SB = dB * QA
        SB = bob.d * QA

        print("\n--- Shared Secrets ---")
        print("Alice Shared Secret:")
        print("x =", SA.x)
        print("y =", SA.y)

        print("\nBob Shared Secret:")
        print("x =", SB.x)
        print("y =", SB.y)

        # Verify both shared points are equal
        if SA == SB:
            print("\nSUCCESS: Alice and Bob shared secrets are equal.")
        else:
            print("\nFAILURE: Alice and Bob shared secrets are different.")


if __name__ == "__main__":
    main()