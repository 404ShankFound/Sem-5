
"""RSA message conversion step-by-step
String → Bytes → ASCII → Hex → Decimal integer → RSA
"""

from Crypto.Util.number import inverse, long_to_bytes
from math import gcd

def main():

    # ---------------------------------------------------------
    # STEP 1: Take plaintext as a normal Python STRING
    # ---------------------------------------------------------

    msg = input("Enter plaintext: ")

    print("\nSTEP 1 - String:")
    print(msg)


    # ---------------------------------------------------------
    # STEP 2: Convert STRING to BYTES using encode()
    #
    # "ABC"
    #   ↓ encode()
    # b'ABC'
    # ---------------------------------------------------------

    data = msg.encode()

    print("\nSTEP 2 - Bytes:")
    print(data)


    # ---------------------------------------------------------
    # STEP 3: See ASCII DECIMAL values of every character
    #
    # A → 65
    # B → 66
    # C → 67
    # ---------------------------------------------------------

    print("\nSTEP 3 - ASCII decimal:")

    for ch in msg:
        print(ch, "->", ord(ch))


    # ---------------------------------------------------------
    # STEP 4: Convert ASCII values to HEX
    #
    # A → 65 → 41
    # B → 66 → 42
    # C → 67 → 43
    # ---------------------------------------------------------

    print("\nSTEP 4 - ASCII hexadecimal:")

    for ch in msg:
        print(ch, "->", hex(ord(ch)))


    # ---------------------------------------------------------
    # STEP 5: Combine all hexadecimal bytes i.e. bytes to hex
    #
    # b'ABC'
    #    ↓ .hex()
    # "414243"
    # ---------------------------------------------------------

    h = data.hex()

    print("\nSTEP 5 - Combined hexadecimal:")
    print(h)


    # ---------------------------------------------------------
    # STEP 6: Convert HEX string to ONE DECIMAL INTEGER
    #
    # "414243"
    #     ↓
    # 0x414243
    #     ↓
    # 4276803
    # ---------------------------------------------------------

    m = int(h, 16)

    print("\nSTEP 6 - Decimal integer:")
    print(m)


    # ---------------------------------------------------------
    # STEP 7: Generate/define RSA parameters
    # ---------------------------------------------------------

    p = int(input("\nEnter p: "))
    q = int(input("Enter q: "))
    e = int(input("Enter e: "))

    # Calculate n
    n = p * q

    # Calculate phi(n)
    phi = (p - 1) * (q - 1)

    # Check whether e is valid
    if e <= 1 or e >= phi or gcd(e, phi) != 1:
        print("Invalid e.")
        return

    # Calculate private key d
    d = inverse(e, phi)

    print("\nn =", n)
    print("phi(n) =", phi)
    print("d =", d)


    # ---------------------------------------------------------
    # STEP 8: Check m < n
    #
    # RSA requires:
    #
    #       m < n
    #
    # If m is greater than or equal to n,
    # we CANNOT encrypt this whole message as one RSA block.
    # ---------------------------------------------------------

    if m >= n:
        print("\nMessage is too large!")
        print("m =", m)
        print("n =", n)
        print("Requirement: m < n")
        return


    # ---------------------------------------------------------
    # STEP 9: RSA ENCRYPTION
    #
    # c = m^e mod n
    # ---------------------------------------------------------

    c = pow(m, e, n)

    print("\nSTEP 9 - Ciphertext:")
    print(c)


    # ---------------------------------------------------------
    # STEP 10: RSA DECRYPTION
    #
    # m = c^d mod n
    # ---------------------------------------------------------

    m2 = pow(c, d, n)

    print("\nSTEP 10 - Decrypted integer:")
    print(m2)


    # ---------------------------------------------------------
    # STEP 11: INTEGER → BYTES
    #
    # long_to_bytes()
    #
    # 4276803
    #    ↓
    # b'ABC'
    # ---------------------------------------------------------

    data2 = long_to_bytes(m2)
    #WE IMPLEMENTED bytes_to_long(m) step by step instead of directly using the function bytes_to_long

    print("\nSTEP 11 - Decrypted bytes:")
    print(data2)

    # ---------------------------------------------------------
    # STEP 12: BYTES → STRING
    #
    # b'ABC'
    #    ↓ decode()
    # "ABC"
    # ---------------------------------------------------------

    msg2 = data2.decode()

    print("\nSTEP 12 - Recovered plaintext:")
    print(msg2)


if __name__ == "__main__":
    main()