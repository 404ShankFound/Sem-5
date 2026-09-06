# %%
"""1. rsa_basic_encryption_decryption

Generate/use RSA public and private keys; encrypt a plaintext and decrypt the
ciphertext; verify the original message.

RSA.generate(2048)
       ↓
   private key
       ↓
  publickey()
       ↓
   public key

plaintext
    ↓
 encode()
    ↓
 bytes
    ↓
PUBLIC KEY
    ↓
 encrypt()
    ↓
ciphertext
    ↓
PRIVATE KEY
    ↓
 decrypt()
    ↓
 plaintext
    ↓
 compare
    ↓
SUCCESS

"ABC123"
    │
    │ encode()
    ↓
b'ABC123'
    │
    │ bytes_to_long()
    ↓
71859371082291
    │
    │ RSA
    │ c = m^e mod n
    ↓
ciphertext INTEGER
    │
    │ RSA decryption
    ↓
71859371082291
    │
    │ long_to_bytes()
    ↓
b'ABC123'
    │
    │ decode()
    ↓
"ABC123"

For RSA-OAEP:

"ABC123"
    │
    │ encode()
    ↓
b'ABC123'
    │
    │ OAEP + RSA library
    ↓
ciphertext BYTES
    │
    │ .hex()       ← ONLY for displaying it
    ↓
"8a24f1......"

"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def main():
    pvt_key = RSA.generate(2048) # key contains the private RSA key information
    pub_key = pvt_key.publickey()

    data = input("Enter message: ")
    msg = data.encode()
    # from Crypto.Cipher import PKCS1_OAEP
    cipher = PKCS1_OAEP.new(pub_key) # ENCRYPT using PUBLIC KEY
    ct = cipher.encrypt(msg)
    print("Ciphertext:", ct.hex())

    #Display ciphertext in bytes as hex: ct.hex()
    #Convert hex ciphertext back to bytes: bytes.fromhex(ct)

    cipher = PKCS1_OAEP.new(pvt_key) # DECRYPT using PRIVATE KEY
    pt = cipher.decrypt(ct) # PT is in bytes so we need to decode
    pt = pt.decode()

    if pt == data:
        print("SUCCESS\n")
    else:
        print("FAILED")

if __name__ == "__main__":
    main()

