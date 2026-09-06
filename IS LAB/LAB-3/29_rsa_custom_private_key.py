# %%
"""Question 29: Rsa custom private key

Accept (n,d) and ciphertext from the user, decrypt the ciphertext and display the recovered plaintext.
"""

from Crypto.Util.number import long_to_bytes


def decrypt(c, n, d):
    # RSA decryption: m = c^d mod n
    msg = pow(c, d, n)

    # Convert integer back to bytes
    msg = long_to_bytes(msg)

    # Convert bytes to string
    return msg.decode()


def main():

    # Take private key from user
    n = int(input("Enter n: "))
    d = int(input("Enter d: "))

    # Take ciphertext as an integer
    c = int(input("Enter ciphertext: "))

    # Decrypt ciphertext
    pt = decrypt(c, n, d)

    print("Recovered plaintext:", pt)


if __name__ == "__main__":
    main()