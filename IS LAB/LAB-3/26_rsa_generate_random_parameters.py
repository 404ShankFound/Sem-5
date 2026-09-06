"""Question 26: Rsa generate random parameters
Generate suitable prime numbers p and q randomly, calculate RSA parameters,
generate keys, and perform encryption/decryption.
"""
from Crypto.Util.number import getPrime, inverse
from math import gcd

def main():
    # Generate two random prime numbers.
    # 1024-bit primes give an approximately 2048-bit RSA modulus.
    p = getPrime(1024)
    q = getPrime(1024)

    # Calculate n = p * q.
    # n is part of both the public and private key.
    n = p * q

    # Calculate Euler's totient:
    # phi(n) = (p - 1) * (q - 1)
    phi = (p - 1) * (q - 1)

    # Find e by hit-and-trial.
    # e must satisfy:
    # 1 < e < phi
    # gcd(e, phi) = 1
    e = 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1

    # Calculate private exponent d.
    # d is the modular inverse of e modulo phi.
    # This means (d * e) % phi = 1
    d = inverse(e, phi)

    # Public key = (n, e)
    # Private key = (n, d)
    print("Public Key:", (n, e))
    print("Private Key:", (n, d))

    # Take plaintext from the user.
    msg = input("Enter message: ")

    # Convert the string into bytes.
    data = msg.encode()

    # RSA can only directly encrypt a message whose size is
    # smaller than the modulus n.
    # Convert bytes into one large integer.
    from Crypto.Util.number import bytes_to_long, long_to_bytes

    m = bytes_to_long(data)

    if m >= n:
        print("Message is too large for this RSA key.")
        return

    # Encryption:
    # c = m^e mod n
    c = pow(m, e, n)

    print("Ciphertext:", c)

    # Decryption:
    # m = c^d mod n
    md = pow(c, d, n)

    # Convert the decrypted integer back into bytes.
    data = long_to_bytes(md)

    # Convert bytes back into a normal string.
    dec = data.decode()

    print("Decrypted message:", dec)

    # Verify that original and decrypted messages are the same.
    if msg == dec:
        print("SUCCESS: Messages match")
    else:
        print("FAILURE: Messages do not match")


if __name__ == "__main__":
    main()