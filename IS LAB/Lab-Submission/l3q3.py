import secrets

def encrypt(message, p, g, h):
    ciphertext = []

    for char in message:
        m = ord(char)

        k = secrets.randbelow(p - 2) + 1

        c1 = pow(g, k, p)
        c2 = (m * pow(h, k, p)) % p

        ciphertext.append((c1, c2))

    return ciphertext


def decrypt(ciphertext, p, x):
    message = ""

    for c1, c2 in ciphertext:
        s = pow(c1, x, p)
        s_inv = pow(s, -1, p)

        m = (c2 * s_inv) % p

        message += chr(m)

    return message


def main():
    message = input("Enter message: ")

    p = int(input("Enter prime p: "))
    g = int(input("Enter generator g: "))
    x = int(input("Enter private key x: "))

    h = pow(g, x, p)

    print("\nPublic Key (p, g, h):")
    print("p =", p)
    print("g =", g)
    print("h =", h)

    print("\nPrivate Key:")
    print("x =", x)

    ciphertext = encrypt(message, p, g, h)

    print("\nCiphertext:")
    print(ciphertext)

    decrypted_message = decrypt(ciphertext, p, x)

    print("\nDecrypted Message:")
    print(decrypted_message)

    print(
        "\nVerification:",
        "SUCCESS" if message == decrypted_message else "FAILED"
    )


if __name__ == "__main__":
    main()