# %%
"""Question 28: Rsa custom public key

Accept (n,e) as the public key and plaintext from the user, encrypt the message, and display the ciphertext.
"""
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes

def encrypt(data,n,e):
    msg = data.encode()
    msg = bytes_to_long(msg)
    return pow(msg,e,n)

def main():
    n = int(input("Enter n: "))
    e = int(input("Enter e: "))
    data = input("Enter plaintext: ")
    ct = encrypt(data,n,e)
    ct = long_to_bytes(ct)
    print("Ciphertext:(hex) ",ct.hex())

if __name__ == "__main__":
    main()
