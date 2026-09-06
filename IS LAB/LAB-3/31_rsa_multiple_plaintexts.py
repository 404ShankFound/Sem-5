# %%
"""Question 31: Rsa multiple plaintexts

Use the same RSA key pair to encrypt and decrypt multiple plaintext messages and verify every result.
"""

# %%
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def main():
    # Generate one RSA key pair
    key = RSA.generate(1024)

    # Get the public key
    pub = key.publickey()

    # Multiple plaintext messages

    # internally msgs = ["Hello", "Hello123", "RSA Lab", "Python"]
    msgs = input("Enter the sentence:")
    msgs = msgs.split(" ")

    # Encrypt and decrypt every message
    flag = 0
    for msg in msgs:

        # Convert message to bytes
        data = msg.encode()

        # Encrypt using the SAME public key
        cipher = PKCS1_OAEP.new(pub)
        ct = cipher.encrypt(data)

        # Decrypt using the SAME private key
        cipher = PKCS1_OAEP.new(key)
        pt = cipher.decrypt(ct)

        # Convert decrypted bytes back to string
        dec = pt.decode()

        print("\nOriginal:", msg)
        print("Ciphertext:", ct.hex())
        print("Decrypted:", dec)

        # Verify the result
        if msg == dec:
            print("SUCCESS: Messages match")
        else:
            print("FAILURE: Messages do not match")
            flag = 1
    if(flag==1):
        print("RECHECK NEEDED")
    else:
        print("All PT\'s encrypted CORRECTLY")


if __name__ == "__main__":
    main()