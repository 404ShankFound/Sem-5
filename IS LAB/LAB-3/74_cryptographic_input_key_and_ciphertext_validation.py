"""
Question 74: Cryptographic Input, Key and Ciphertext Validation

Implement a reusable validation/error-handling layer for the cryptographic programs. Detect invalid numeric input, empty messages, invalid cryptographic parameters, invalid keys, corrupted ciphertext, wrong private keys and tampered ciphertext.

Test cases:
Invalid numeric input
Empty message
Invalid p/g
Invalid key
Invalid ciphertext
Wrong private key
Tampered ciphertext
Correct ciphertext/key

Requirements:
- Never crash on expected invalid input
- Display appropriate error
- Validate before cryptographic operation
- Catch decryption/authentication failures
- Explicit SUCCESS / FAILURE
- Demonstrate wrong-key failure
- Demonstrate tampered-ciphertext failure

Absorbs: original Q97–102.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os


def get_int(msg):
    # Safely read an integer
    try:
        return int(input(msg))
    except ValueError:
        print("FAILURE: Invalid numeric input.")
        return None


def valid_msg(msg):
    # Check for empty message
    if not msg:
        print("FAILURE: Message cannot be empty.")
        return False

    return True


def valid_pg(p, g):
    # Basic Diffie-Hellman/ElGamal parameter validation
    if p is None or g is None:
        return False

    if p <= 2:
        print("FAILURE: p must be greater than 2.")
        return False

    if g <= 1 or g >= p:
        print("FAILURE: g must satisfy 1 < g < p.")
        return False

    print("SUCCESS: p and g are valid.")
    return True


def valid_key(key):
    # Check whether a key object exists
    if key is None:
        print("FAILURE: Invalid key.")
        return False

    return True


def encrypt(data, pub):
    # Generate AES session key
    key = os.urandom(32)

    # Protect AES key using RSA-OAEP
    ek = PKCS1_OAEP.new(pub).encrypt(key)

    # Encrypt data using AES-EAX
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(data)

    return ek, ct, c.nonce, tag


def decrypt(ek, ct, nonce, tag, pri):
    # Recover AES key
    key = PKCS1_OAEP.new(pri).decrypt(ek)

    # Decrypt and authenticate ciphertext
    c = AES.new(key, AES.MODE_EAX, nonce=nonce)

    pt = c.decrypt(ct)

    c.verify(tag)

    return pt


def correct_test(data, enc, pri):
    # Correct ciphertext and correct private key
    try:
        pt = decrypt(*enc, pri)

        if pt == data:
            print("SUCCESS: Correct ciphertext/key decrypted successfully.")
        else:
            print("FAILURE: Plaintext verification failed.")

    except Exception:
        print("FAILURE: Decryption failed.")


def wrong_key_test(enc, wrong_pri):
    # Test decryption with wrong private key
    try:
        decrypt(*enc, wrong_pri)
        print("FAILURE: Wrong private key was accepted.")

    except Exception:
        print("SUCCESS: Wrong private key rejected.")


def tamper_test(data, enc, pri):
    # Copy ciphertext so original data is not modified
    ek, ct, nonce, tag = enc

    ct = bytearray(ct)

    if len(ct) > 0:
        # Modify one ciphertext byte
        ct[0] ^= 1

    ct = bytes(ct)

    try:
        pt = decrypt(ek, ct, nonce, tag, pri)

        if pt == data:
            print("FAILURE: Tampered ciphertext was accepted.")
        else:
            print("SUCCESS: Tampered ciphertext detected.")

    except Exception:
        print("SUCCESS: Tampered ciphertext detected.")


def invalid_ciphertext_test(enc, pri):
    # Test corrupted/invalid ciphertext
    ek, ct, nonce, tag = enc

    bad = b"invalid ciphertext"

    try:
        decrypt(ek, bad, nonce, tag, pri)
        print("FAILURE: Invalid ciphertext was accepted.")

    except Exception:
        print("SUCCESS: Invalid ciphertext rejected.")


def input_test():
    print("\n--- Invalid Numeric Input Test ---")

    x = get_int("Enter an integer: ")

    if x is not None:
        print("SUCCESS: Numeric input is valid.")


def empty_message_test():
    print("\n--- Empty Message Test ---")

    msg = input("Enter message: ")

    valid_msg(msg)


def parameter_test():
    print("\n--- Invalid p/g Test ---")

    p = get_int("Enter p: ")
    g = get_int("Enter g: ")

    valid_pg(p, g)


def invalid_key_test():
    print("\n--- Invalid Key Test ---")

    key = None

    if not valid_key(key):
        print("Invalid key handled correctly.")


def complete_validation_test():
    print("\n--- Complete Cryptographic Validation Test ---")

    msg = input("Enter message: ")

    if not valid_msg(msg):
        return

    data = msg.encode()

    print("\nGenerating valid RSA keys...")

    try:
        pri = RSA.generate(2048)
        pub = pri.publickey()

    except Exception:
        print("FAILURE: RSA key generation failed.")
        return

    if not valid_key(pri) or not valid_key(pub):
        return

    print("SUCCESS: RSA keys are valid.")

    try:
        enc = encrypt(data, pub)
        print("SUCCESS: Encryption completed.")

    except Exception as e:
        print("FAILURE: Encryption failed:", e)
        return

    # Correct ciphertext and key
    print("\n1. Correct Ciphertext / Correct Key")
    correct_test(data, enc, pri)

    # Wrong private key
    print("\n2. Wrong Private Key")

    try:
        wrong_pri = RSA.generate(2048)
        wrong_key_test(enc, wrong_pri)

    except Exception:
        print("SUCCESS: Wrong private key rejected.")

    # Invalid ciphertext
    print("\n3. Invalid Ciphertext")
    invalid_ciphertext_test(enc, pri)

    # Tampered ciphertext
    print("\n4. Tampered Ciphertext")
    tamper_test(data, enc, pri)


def menu():
    while True:
        print("\n--- Validation Menu ---")
        print("1. Invalid Numeric Input")
        print("2. Empty Message")
        print("3. Invalid p/g")
        print("4. Invalid Key")
        print("5. Complete Cryptographic Validation")
        print("6. Exit")

        ch = input("Enter choice: ")

        if ch == "1":
            input_test()

        elif ch == "2":
            empty_message_test()

        elif ch == "3":
            parameter_test()

        elif ch == "4":
            invalid_key_test()

        elif ch == "5":
            complete_validation_test()

        elif ch == "6":
            print("Exiting...")
            break

        else:
            print("FAILURE: Invalid menu choice.")


def main():
    print("--- Cryptographic Input, Key and Ciphertext Validation ---")
    menu()


if __name__ == "__main__":
    main()