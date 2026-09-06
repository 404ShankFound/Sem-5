# %%
"""Question 37: Rsa change plaintext

Modify the RSA program to accept different plaintexts without regenerating the key pair.
"""
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
from math import gcd

def encrypt(msg, n, e):
    # Convert message to integer
    m = bytes_to_long(msg.encode())

    # RSA requires m < n
    if m >= n:
        return None

    # c = m^e mod n
    c = pow(m, e, n)

    return c


def decrypt(c, n, d):
    # m = c^d mod n
    m = pow(c, d, n)

    # Convert integer back to text
    msg = long_to_bytes(m).decode()

    return msg

def main():

    p = int(input("Enter p: "))
    q = int(input("Enter q: "))

    n = p * q

    phi = (p - 1) * (q - 1)

    print("n =", n)
    print("phi(n) =", phi)

    while True:

        e = int(input("Enter e: "))
        # Check whether e is valid
        if e > 1 and e < phi and gcd(e, phi) == 1:
            break
        print("Invalid e. Choose another value.")

    d = inverse(e,phi)
    print("\nPublic Key:", (n, e))
    print("Private Key:", (n, d))

    while(True):

        msg = input("Enter message: ")
        if(msg=="exit"):
            break
        ct = encrypt(msg,n,e)

        if ct is None:
            print("Message is too large.")
            continue

        pt = decrypt(ct,n,d)
        if msg == pt:
            print("SUCCESS")
        else:
            print("FAILED")
        

if __name__ == "__main__":
    main()
