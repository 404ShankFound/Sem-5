"""
Question 54: Ecc fixed curve

Generate an ECC key pair using the secp256r1 curve and display the private key and public point (x,y).
"""

from Crypto.PublicKey import ECC


def main():
    # Generate ECC key pair using fixed secp256r1 curve
    key = ECC.generate(curve="secp256r1")

    # Get private key
    d = key.d

    # Get public point
    x = key.pointQ.x
    y = key.pointQ.y

    print("\n--- ECC Key Pair ---")
    print("Curve: secp256r1")
    print("Private Key:", d)
    print("Public Point:")
    print("x =", x)
    print("y =", y)


if __name__ == "__main__":
    main()