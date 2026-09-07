"""
Question 58: Ecc public key display

Generate an ECC key pair and display the public point coordinates x and y separately.
"""

from Crypto.PublicKey import ECC


def main():
    # Generate ECC key pair using secp256r1 curve
    key = ECC.generate(curve="secp256r1")

    # Get public point
    Q = key.pointQ

    # Get x and y coordinates separately
    x = Q.x
    y = Q.y

    print("\n--- ECC Public Key ---")
    print("Public Key X:", x)
    print("Public Key Y:", y)


if __name__ == "__main__":
    main()