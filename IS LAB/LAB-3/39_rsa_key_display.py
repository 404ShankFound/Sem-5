"""Question 39: Rsa key display

Generate RSA keys and display p, q, n, φ(n), e, and d separately as public and private parameters.

RSA.generate(2048)
       ↓
   Private key object
   p, q, n, e, d
       ↓
key.publickey()
       ↓
   Public key object
      n, e

Inside RSA.generate(2048):

RSA.generate(2048)
       ↓
Randomly generate large prime p
       ↓
Randomly generate large prime q
       ↓
n = p × q
       ↓
φ(n) = (p-1)(q-1)
       ↓
choose e
       ↓
calculate d
       ↓
RSA key pair

If you run:
key = RSA.generate(2048)
multiple times, you will get a different RSA key pair every time 
because RSA generates new random prime numbers p and q.

"""

from Crypto.PublicKey import RSA


def main():

    # Generate a 2048-bit RSA key pair
    key = RSA.generate(2048)

    # Extract RSA parameters
    p = key.p
    q = key.q
    n = key.n
    e = key.e
    d = key.d

    # Calculate Euler's phi(n)
    phi = (p - 1) * (q - 1)

    # Display all parameters
    print("RSA Parameters:\n")

    print("p =", p)
    print("q =", q)
    print("n =", n)
    print("phi(n) =", phi)
    print("e =", e)
    print("d =", d)

    # Public parameters
    print("\nPublic Parameters:")
    print("n =", n)
    print("e =", e)

    # Private parameters
    print("\nPrivate Parameters:")
    print("p =", p)
    print("q =", q)
    print("d =", d)


if __name__ == "__main__":
    main()    
