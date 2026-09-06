"""Question 38: Rsa hex conversion

Encrypt a plaintext and represent the ciphertext in hexadecimal; convert it back during decryption.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def main():

    # Generate RSA key pair
    key = RSA.generate(2048)

    # Generate public key from private key
    pub = key.publickey()

    # Take plaintext from user
    msg = input("Enter plaintext: ")

    # Convert string to bytes
    data = msg.encode()

    # Encrypt using public key
    cipher = PKCS1_OAEP.new(pub)
    ct = cipher.encrypt(data)

    # Convert ciphertext bytes to hexadecimal string
    h = ct.hex()

    print("Ciphertext (hex):", h)

    # Convert hexadecimal string back to ciphertext bytes
    ct = bytes.fromhex(h)

    # Decrypt using private key
    cipher = PKCS1_OAEP.new(key)
    pt = cipher.decrypt(ct)

    # Convert plaintext bytes back to string
    dec = pt.decode()

    print("Decrypted message:", dec)

    # Verify
    if msg == dec:
        print("SUCCESS")
    else:
        print("FAILED")


if __name__ == "__main__":
    main()