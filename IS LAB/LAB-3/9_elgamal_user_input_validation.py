"""
9. elgamal_user_input_validation

Accept p, g, d, k and plaintext from the user; validate parameter ranges and
generate the ciphertext (c1,c2).
"""

from Crypto.Util.number import bytes_to_long, isPrime, getPrime


def main():
    # Choose how to obtain prime p.
    print("1. Enter p manually")
    print("2. Generate p using getPrime()")

    ch = int(input("Enter choice: "))

    if ch == 1:
        # Enter prime p manually.
        p = int(input("Enter prime p: "))

    elif ch == 2:
        # Enter the bit size for generating prime p.
        size = int(input("Enter bit size for p: "))

        # Generate a random prime p of the given bit size.
        p = getPrime(size)

        print("Generated prime p:", p)

    else:
        print("Invalid choice.")
        return

    # Validate that p is a prime number greater than 2.
    if p <= 2 or not isPrime(p):
        print("Invalid p. p must be a prime number greater than 2.")
        return

    # Enter primitive root g.
    g = int(input("Enter primitive root g: "))

    # Validate range of g.
    # g must lie between 2 and p-1.
    if g < 2 or g >= p:
        print("Invalid g. g must satisfy 2 <= g < p.")
        return

    # Check whether g is a primitive root modulo p.
    # A primitive root must generate all p-1 non-zero values modulo p.
    s = set()

    for i in range(1, p):
        s.add(pow(g, i, p))

    # If the number of unique powers is p-1,
    # then g is a primitive root modulo p.
    if len(s) != p - 1:
        print("Invalid g. g is not a primitive root modulo p.")
        return

    '''
    Reason of len(s)== p-1 instead of len(s)==p:
    Because, modulo a prime p, there are only p-1 possible NON-ZERO values,
    remaining one value is ZERO.

    For a primitive root g, we want its powers to generate every
    non-zero value modulo p exactly once.

    Example: p = 7

    The possible values modulo 7 are:
    0, 1, 2, 3, 4, 5, 6 => That's 7 values total.

    But primitive roots only need to generate the non-zero values:
    1, 2, 3, 4, 5, 6 => That's 7 - 1 = 6 = p-1
    '''

    print("Valid Primitive root g:", g)

    # Enter private/secret key d.
    d = int(input("Enter private key d: "))

    # Validate range of d.
    # d must satisfy 1 <= d <= p-2.
    if d < 1 or d > p - 2:
        print("Invalid d. d must satisfy 1 <= d <= p-2.")
        return

    # Enter encryption key k.
    k = int(input("Enter random k: "))

    # Validate range of k.
    # k must satisfy 1 <= k <= p-2.
    if k < 1 or k > p - 2:
        print("Invalid k. k must satisfy 1 <= k <= p-2.")
        return

    # Generate public key parameters.
    # e1 = g
    # e2 = e1^d mod p
    e1 = g
    e2 = pow(e1, d, p)

    print("Public Key:", (e1, e2, p))
    print("Private Key:", d)

    # Enter plaintext.
    pt = input("Enter plaintext: ")

    # Convert plaintext into an integer.
    m = bytes_to_long(pt.encode())

    # ElGamal requires the message integer to be smaller than p.
    if m >= p:
        print("Plaintext is too large for p.")
        return

    # ElGamal encryption:
    # c1 = e1^k mod p
    c1 = pow(e1, k, p)

    # c2 = m * e2^k mod p
    c2 = (m * pow(e2, k, p)) % p

    # Display ciphertext.
    print("Ciphertext:", (c1, c2))


if __name__ == "__main__":
    main()