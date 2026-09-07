# %%
"""8. elgamal_key_generation

Generate ElGamal parameters/keys by choosing p, g, private key d, and
calculating e1 = g and e2 = e1^d mod p; display public/private keys.
"""

# %%
from Crypto.Util.number import getPrime
import random


def primitive_root(p):
    # Find the smallest primitive root modulo p.
    for g in range(2, p):
        s = set()

        # Generate all powers of g modulo p.
        for i in range(1, p):
            s.add(pow(g, i, p))

        # A primitive root generates all p-1 non-zero values.
        if len(s) == p - 1:
            return g

    return None


def main():
    # Generate a large random prime p.
    # 2048 bits is a suitable RSA/DH-sized prime for demonstration.
    p = getPrime(8)

    print("Large Prime p:", p)

    # HERE WE DONT USE FUNCTION AS PRIME IS OF 20248 BITS NOT 20248 DECIMAL DIGITS, COMPUTATIONALLY INFEASIBLE
    # Find the smallest primitive root g of p.
    # g = primitive_root(p)

    #if(g == None):
        #print("Primitive root does not exist for", p)
        #return None

    #print("Smallest Primitive root g:", g)

    g = int(input("Enter primitive root g: "))
    
    # Generate private/secret key d.
    # d must satisfy 1 <= d <= p-2.

    d = random.randint(1, p - 2)

    # Generate public key parameters.
    # e1 = g
    # e2 = e1^d mod p
    e1 = g
    e2 = pow(e1, d, p)

    # Display the keys.
    print("Public Key:", (e1, e2, p))
    print("Private Key:", d)


if __name__ == "__main__":
    main()