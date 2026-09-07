"""
18. diffie_hellman_user_input_performance

Accept p,g,a,b from the user; calculate public values and shared secret;
verify equality and measure key-generation/key-exchange time.
"""

import time


def main():

    # Accept DH parameters from user
    p = int(input("Enter prime p: "))
    g = int(input("Enter generator g: "))

    # Accept private keys
    a = int(input("Enter Alice private key a: "))
    b = int(input("Enter Bob private key b: "))

    # Measure public-key generation time
    t = time.perf_counter()

    A = pow(g, a, p)
    B = pow(g, b, p)

    key_time = time.perf_counter() - t

    # Measure shared-secret calculation time
    t = time.perf_counter()

    s1 = pow(B, a, p)
    s2 = pow(A, b, p)

    exchange_time = time.perf_counter() - t

    print("\nAlice Public Key:", A)
    print("Bob Public Key:", B)

    print("\nAlice Shared Secret:", s1)
    print("Bob Shared Secret:", s2)

    print("Shared Secret Same:", s1 == s2)

    print("\nKey Generation Time:", key_time, "seconds")
    print("Key Exchange Time:", exchange_time, "seconds")


if __name__ == "__main__":
    main()