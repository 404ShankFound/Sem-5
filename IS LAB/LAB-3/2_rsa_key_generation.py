# %%
"""2. rsa_key_generation

Given p and q, calculate n, phi(n), choose valid e, calculate d,
and display public/private keys.
"""

# %%
from math import gcd
from Crypto.Util.number import inverse

def main():

    # Take the two prime numbers p and q from the user
    # Modification:
    # If the question gives fixed p and q, simply write:
    # p = 17
    # q = 19
    p = int(input("Enter p: "))
    q = int(input("Enter q: "))

    # Calculate RSA modulus
    # Formula: n = p * q
    n = p * q

    # Calculate Euler's Totient function
    # Formula: phi(n) = (p - 1) * (q - 1)
    phi = (p - 1) * (q - 1)

    print("n =", n)
    print("phi(n) =", phi)

    # Choose the public exponent e
    # e must satisfy:
    # 1 < e < phi(n)
    # gcd(e, phi(n)) = 1
    while True:
        e = int(input("Enter e: "))

        # Check whether e is valid
        if e > 1 and e < phi and gcd(e, phi) == 1:
            break

        print("Invalid e. Choose another value.")

    '''
    If question says "choose a valid e automatically"
    Instead of user input, we could:

    for e in range(2, phi):
        if gcd(e, phi) == 1:
            break
        
    '''

    # Calculate private exponent d
    # d is the modular inverse of e modulo phi(n)
    # Formula: d = e^(-1) mod phi(n)
    d = inverse(e, phi)

    # Display RSA keys
    # Public key contains (n, e)
    # Private key contains (n, d)
    print("\nPublic Key:", (n, e))
    print("Private Key:", (n, d))


# %%
if __name__ == "__main__":
    main()