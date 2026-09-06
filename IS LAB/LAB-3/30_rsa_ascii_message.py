"""Question 30: Rsa ascii message
Convert each character of a plaintext into its ASCII and integer representation, 
perform RSA encryption/decryption and reconstruct the original message.
"""

from Crypto.Util.number import inverse
from math import gcd

def main():

    # Take RSA values from user
    p = int(input("Enter p: "))
    q = int(input("Enter q: "))
    e = int(input("Enter e: "))

    # Calculate n
    n = p * q

    # Calculate phi(n)
    phi = (p - 1) * (q - 1)

    # Check whether e is valid
    if e <= 1 or e >= phi or gcd(e, phi) != 1:
        print("Invalid e")
        return

    # Calculate private exponent
    d = inverse(e, phi)

    print("Public Key:", (n, e))
    print("Private Key:", (n, d))

    # Take plaintext
    msg = input("Enter plaintext: ")

    enc = []
    dec = ""

    # Encrypt each character separately
    for ch in msg:

        # Character -> ASCII integer
        # Example: 'A' -> 65
        m = ord(ch)

        print("\nCharacter:", ch)
        print("ASCII value:", m)

        # RSA requires m < n
        if m >= n:
            print("Character value is greater than n.")
            return

        # RSA encryption
        # c = m^e mod n
        c = pow(m, e, n)

        enc.append(c)

        print("Encrypted:", c)

    print("\nCiphertext:", enc)

    # Decrypt each ciphertext
    for c in enc:

        # RSA decryption
        # m = c^d mod n
        m = pow(c, d, n)

        # ASCII integer -> character
        # Example: 65 -> 'A'
        ch = chr(m)

        dec += ch

    print("Decrypted message:", dec)

    # Verify
    if msg == dec:
        print("SUCCESS")
    else:
        print("FAILED")


if __name__ == "__main__":
    main()
# %%
