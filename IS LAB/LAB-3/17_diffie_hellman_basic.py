"""
17. diffie_hellman_basic

Implement DH with public parameters p,g; generate Alice/Bob private keys,
public keys and common shared secret; verify both secrets are equal.
"""

def main():

    # Public parameters
    p = int(input("Enter prime p: "))
    g = int(input("Enter generator g: "))

    # Alice private key
    a = int(input("Enter Alice private key: "))

    # Bob private key
    b = int(input("Enter Bob private key: "))

    # Alice public key
    A = pow(g, a, p)

    # Bob public key
    B = pow(g, b, p)

    # Alice calculates shared secret using Bob's public key
    s1 = pow(B, a, p)

    # Bob calculates shared secret using Alice's public key
    s2 = pow(A, b, p)

    print("\nPublic Parameters:")
    print("p =", p)
    print("g =", g)

    print("\nAlice:")
    print("Private Key:", a)
    print("Public Key:", A)

    print("\nBob:")
    print("Private Key:", b)
    print("Public Key:", B)

    print("\nShared Secret by Alice:", s1)
    print("Shared Secret by Bob:", s2)

    # Verify both shared secrets
    print("Shared Secret Same:", s1 == s2)


if __name__ == "__main__":
    main()