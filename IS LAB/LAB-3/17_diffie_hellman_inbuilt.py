"""
17. diffie_hellman_basic

Implement DH with public parameters p,g; generate Alice/Bob private keys,
public keys and common shared secret; verify both secrets are equal.
"""

from cryptography.hazmat.primitives.asymmetric import dh


def main():

    # Generate DH parameters
    params = dh.generate_parameters(generator=2, key_size=2048)

    # Get public parameters
    pn = params.parameter_numbers()

    p = pn.p
    g = pn.g

    print("Public Parameter p:", p)
    print("Public Parameter g:", g)

    # Generate Alice private and public keys
    alice_private = params.generate_private_key()
    alice_public = alice_private.public_key()

    # Generate Bob private and public keys
    bob_private = params.generate_private_key()
    bob_public = bob_private.public_key()

    # Calculate shared secrets
    s1 = alice_private.exchange(bob_public)
    s2 = bob_private.exchange(alice_public)

    print("\nAlice Private Key:", alice_private.private_numbers().x)
    print("Alice Public Key:", alice_public.public_numbers().y)

    print("\nBob Private Key:", bob_private.private_numbers().x)
    print("Bob Public Key:", bob_public.public_numbers().y)

    print("\nAlice Shared Secret:", s1.hex())
    print("Bob Shared Secret:", s2.hex())

    # Verify both shared secrets
    print("Shared Secret Same:", s1 == s2)


if __name__ == "__main__":
    main()