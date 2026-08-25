from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_keys():
    private_key = ECC.generate(curve="P-256")
    public_key = private_key.public_key()

    return private_key, public_key


def derive_key(private_key, public_key):
    shared_point = private_key.d * public_key.pointQ

    shared_secret = int(shared_point.x).to_bytes(32, 'big')

    key = HKDF(
        master=shared_secret,
        key_len=32,
        salt=None,
        hashmod=SHA256,
        context=b"ECC Encryption"
    )

    return key


def encrypt(message, public_key):
    # Generate temporary ECC key
    temp_private_key, temp_public_key = generate_keys()

    # Derive AES key
    key = derive_key(temp_private_key, public_key)

    # AES-GCM encryption
    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode()
    )

    return temp_public_key, cipher.nonce, ciphertext, tag


def decrypt(temp_public_key, private_key, nonce, ciphertext, tag):
    # Derive same AES key
    key = derive_key(private_key, temp_public_key)

    # AES-GCM decryption
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext.decode()


def main():
    message = input("Enter message: ")

    # Generate ECC key pair
    private_key, public_key = generate_keys()

    print("\nECC Curve: P-256 (secp256r1)")
    print("Public Key generated.")
    print("Private Key generated.")

    # Encryption
    temp_public_key, nonce, ciphertext, tag = encrypt(
        message,
        public_key
    )

    print("\nCiphertext:")
    print(ciphertext.hex().upper())

    # Decryption
    decrypted_message = decrypt(
        temp_public_key,
        private_key,
        nonce,
        ciphertext,
        tag
    )

    print("\nDecrypted Message:")
    print(decrypted_message)

    print(
        "\nVerification:",
        "SUCCESS" if message == decrypted_message else "FAILED"
    )


if __name__ == "__main__":
    main()