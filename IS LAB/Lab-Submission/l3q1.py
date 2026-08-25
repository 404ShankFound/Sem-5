from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_keys():
    key = RSA.generate(2048)

    public_key = key.publickey()
    private_key = key

    return public_key, private_key


def encrypt(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())

    return ciphertext


def decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext.decode()


def main():
    message = input("Enter message: ")

    public_key, private_key = generate_keys()

    n = public_key.n
    e = public_key.e
    d = private_key.d

    print("\nPublic Key (n, e):")
    print("n =", n)
    print("e =", e)

    print("\nPrivate Key (n, d):")
    print("n =", n)
    print("d =", d)

    ciphertext = encrypt(message, public_key)

    print("\nCiphertext:")
    print(ciphertext.hex())

    decrypted_message = decrypt(ciphertext, private_key)

    print("\nDecrypted Message:")
    print(decrypted_message)


if __name__ == "__main__":
    main()