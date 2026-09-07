"""
12. ecc_key_generation

Given elliptic-curve parameters, base point G and private key d, calculate the
public key Q=dG and display both keys.
"""

from Crypto.PublicKey import ECC

def main():
    # Select the elliptic curve.
    curve = input("Enter curve name (secp256r1/secp384r1/secp521r1): ")

    # Generate a private key using the selected curve.
    key = ECC.generate(curve=curve)

    # Get the private/secret key d.
    d = key.d

    # Get the base point G from the curve.
    G = key._curve.G

    # Calculate the public key Q.
    # Q = dG
    Q = d * G

    # Display the private key.
    print("Private Key d:", d)

    # Display the base point G.
    print("Base Point G:")
    print("x =", G.x)
    print("y =", G.y)

    # Display the public key Q.
    print("Public Key Q:")
    print("x =", Q.x)
    print("y =", Q.y)


if __name__ == "__main__":
    main()