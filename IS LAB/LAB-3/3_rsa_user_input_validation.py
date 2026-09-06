# %%
"""3. rsa_user_input_validation

Modify RSA to accept p, q, e and plaintext from the user; validate primes,
gcd(e,φ(n))=1, and message < n.
"""

# %%
from math import gcd
from Crypto.Util.number import inverse, isPrime, bytes_to_long, long_to_bytes


def main():
    # Take p and q from the user
    p = int(input("Enter p: "))
    q = int(input("Enter q: "))

    # Check whether p and q are prime numbers
    if not isPrime(p) or not isPrime(q):
        print("Invalid input: p and q must be prime.")
        return

    # p and q should be different
    if p == q:
        print("Invalid input: p and q must be different.")
        return

    # Calculate n = p * q
    n = p * q

    # Calculate Euler's phi
    phi = (p - 1) * (q - 1)

    print("n =", n)
    print("phi(n) =", phi)

    # Take e from the user
    e = int(input("Enter e: "))

    # Check:
    # 1 < e < phi(n)
    # gcd(e, phi(n)) must be 1
    if e <= 1 or e >= phi or gcd(e, phi) != 1:
        print("Invalid e.")
        return

    # Calculate private exponent d
    d = inverse(e, phi)

    print("Public Key:", (n, e))
    print("Private Key:", (n, d))

    # Take plaintext from user
    msg = input("Enter plaintext: ")

        #Numeric plaintext
        #don't use encode()/bytes_to_long()

    # Convert plaintext string to bytes
    data = msg.encode()

    # Convert bytes to integer
    m = bytes_to_long(data)

    # RSA requires plaintext integer m < n
    if m >= n:
        print("Message is too large. Message must be smaller than n.")
        return

    # RSA encryption:
    # c = m^e mod n
    c = pow(m, e, n)

    print("Ciphertext:", c)

    # RSA decryption:
    # m = c^d mod n
    md = pow(c, d, n)

    # Convert decrypted integer back to bytes
    dec = long_to_bytes(md)

    # Convert bytes back to string
    dec = dec.decode()

    print("Decrypted message:", dec)

    # Verify original and decrypted messages
    if dec == msg:
        print("SUCCESS: Messages match")
    else:
        print("FAILURE: Messages do not match")


if __name__ == "__main__":
    main()