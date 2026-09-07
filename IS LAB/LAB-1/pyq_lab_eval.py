"""
Combined Encryption System

Plaintext
   |
   v
Affine Encryption
   |
   v
Selected Cipher
   |
   v
Final Ciphertext

Decryption:
Final Ciphertext
   |
   v
Selected Cipher Decryption
   |
   v
Affine Decryption
   |
   v
Original Plaintext
"""

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from math import gcd


# ==================== AFFINE CIPHER ====================

def affine_encrypt(pt, a, b):
    ct = ""

    for c in pt:
        if c.isupper():
            x = ord(c) - ord('A')
            ct += chr((a * x + b) % 26 + ord('A'))
        elif c.islower():
            x = ord(c) - ord('a')
            ct += chr((a * x + b) % 26 + ord('a'))
        else:
            ct += c

    return ct


def affine_decrypt(ct, a, b):
    pt = ""
    a_inv = pow(a, -1, 26)

    for c in ct:
        if c.isupper():
            x = ord(c) - ord('A')
            pt += chr((a_inv * (x - b)) % 26 + ord('A'))
        elif c.islower():
            x = ord(c) - ord('a')
            pt += chr((a_inv * (x - b)) % 26 + ord('a'))
        else:
            pt += c

    return pt


# ==================== VIGENERE ====================

def vigenere_encrypt(pt, key):
    ct = ""
    j = 0

    for c in pt:
        if c.isalpha():
            k = ord(key[j % len(key)].lower()) - ord('a')

            if c.isupper():
                ct += chr((ord(c) - ord('A') + k) % 26 + ord('A'))
            else:
                ct += chr((ord(c) - ord('a') + k) % 26 + ord('a'))

            j += 1
        else:
            ct += c

    return ct


def vigenere_decrypt(ct, key):
    pt = ""
    j = 0

    for c in ct:
        if c.isalpha():
            k = ord(key[j % len(key)].lower()) - ord('a')

            if c.isupper():
                pt += chr((ord(c) - ord('A') - k) % 26 + ord('A'))
            else:
                pt += chr((ord(c) - ord('a') - k) % 26 + ord('a'))

            j += 1
        else:
            pt += c

    return pt


# ==================== AUTOKEY NUMERIC ====================

def autokey_num_encrypt(pt, k):
    ct = ""
    cur = k

    for c in pt:
        if c.isalpha():
            x = ord(c.upper()) - ord('A')
            y = (x + cur) % 26
            ct += chr(y + ord('A'))
            cur = x
        else:
            ct += c

    return ct


def autokey_num_decrypt(ct, k):
    pt = ""
    cur = k

    for c in ct:
        if c.isalpha():
            y = ord(c.upper()) - ord('A')
            x = (y - cur) % 26
            pt += chr(x + ord('A'))
            cur = x
        else:
            pt += c

    return pt


# ==================== AUTOKEY TEXT ====================

def autokey_text_encrypt(pt, key):
    ct = ""
    ks = [ord(c.lower()) - ord('a') for c in key]
    i = 0

    for c in pt:
        if c.isalpha():
            x = ord(c.upper()) - ord('A')
            k = ks[i]
            y = (x + k) % 26

            ct += chr(y + ord('A'))
            ks.append(x)
            i += 1
        else:
            ct += c

    return ct


def autokey_text_decrypt(ct, key):
    pt = ""
    ks = [ord(c.lower()) - ord('a') for c in key]
    i = 0

    for c in ct:
        if c.isalpha():
            y = ord(c.upper()) - ord('A')
            k = ks[i]
            x = (y - k) % 26

            pt += chr(x + ord('A'))
            ks.append(x)
            i += 1
        else:
            pt += c

    return pt


# ==================== PLAYFAIR ====================

def make_matrix(key):
    key = key.upper().replace('J', 'I')
    s = ""

    for c in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c.isalpha() and c not in s:
            s += c

    return [s[i:i + 5] for i in range(0, 25, 5)]


def playfair_encrypt(pt, key):
    mat = make_matrix(key)
    pt = ''.join(c for c in pt.upper() if c.isalpha()).replace('J', 'I')

    pairs = []
    i = 0

    while i < len(pt):
        a = pt[i]

        if i + 1 == len(pt):
            b = 'X'
            i += 1
        elif pt[i] == pt[i + 1]:
            b = 'X'
            i += 1
        else:
            b = pt[i + 1]
            i += 2

        pairs.append(a + b)

    ct = ""

    for pair in pairs:
        a, b = pair
        r1 = c1 = r2 = c2 = 0

        for r in range(5):
            for c in range(5):
                if mat[r][c] == a:
                    r1, c1 = r, c
                if mat[r][c] == b:
                    r2, c2 = r, c

        if r1 == r2:
            ct += mat[r1][(c1 + 1) % 5]
            ct += mat[r2][(c2 + 1) % 5]
        elif c1 == c2:
            ct += mat[(r1 + 1) % 5][c1]
            ct += mat[(r2 + 1) % 5][c2]
        else:
            ct += mat[r1][c2]
            ct += mat[r2][c1]

    return ct


def playfair_decrypt(ct, key):
    mat = make_matrix(key)
    pt = ""

    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i + 1]
        r1 = c1 = r2 = c2 = 0

        for r in range(5):
            for c in range(5):
                if mat[r][c] == a:
                    r1, c1 = r, c
                if mat[r][c] == b:
                    r2, c2 = r, c

        if r1 == r2:
            pt += mat[r1][(c1 - 1) % 5]
            pt += mat[r2][(c2 - 1) % 5]
        elif c1 == c2:
            pt += mat[(r1 - 1) % 5][c1]
            pt += mat[(r2 - 1) % 5][c2]
        else:
            pt += mat[r1][c2]
            pt += mat[r2][c1]

    return pt


# ==================== HILL ====================

def matrix_inverse(K):
    n = len(K)
    A = [[K[i][j] % 26 for j in range(n)] +
         [1 if i == j else 0 for j in range(n)] for i in range(n)]

    for i in range(n):
        p = -1

        for r in range(i, n):
            if gcd(A[r][i], 26) == 1:
                p = r
                break

        if p == -1:
            return None

        A[i], A[p] = A[p], A[i]

        inv = pow(A[i][i], -1, 26)

        for j in range(2 * n):
            A[i][j] = (A[i][j] * inv) % 26

        for r in range(n):
            if r != i:
                x = A[r][i]

                for j in range(2 * n):
                    A[r][j] = (A[r][j] - x * A[i][j]) % 26

    return [row[n:] for row in A]


def hill_encrypt(pt, K):
    n = len(K)
    s = ''.join(c for c in pt.upper() if c.isalpha())

    while len(s) % n != 0:
        s += 'X'

    ct = ""

    for i in range(0, len(s), n):
        p = [ord(c) - ord('A') for c in s[i:i + n]]

        for r in range(n):
            x = sum(K[r][j] * p[j] for j in range(n)) % 26
            ct += chr(x + ord('A'))

    return ct


def hill_decrypt(ct, K):
    K = matrix_inverse(K)

    if K is None:
        return ""

    n = len(K)
    pt = ""

    for i in range(0, len(ct), n):
        p = [ord(c) - ord('A') for c in ct[i:i + n]]

        for r in range(n):
            x = sum(K[r][j] * p[j] for j in range(n)) % 26
            pt += chr(x + ord('A'))

    return pt


# ==================== RAIL FENCE ====================

def rail_encrypt(pt, n):
    if n <= 1:
        return pt

    rail = ['' for _ in range(n)]
    r = 0
    d = 1

    for c in pt:
        rail[r] += c

        if r == 0:
            d = 1
        elif r == n - 1:
            d = -1

        r += d

    return ''.join(rail)


def rail_decrypt(ct, n):
    if n <= 1:
        return ct

    pattern = []
    r = 0
    d = 1

    for _ in ct:
        pattern.append(r)

        if r == 0:
            d = 1
        elif r == n - 1:
            d = -1

        r += d

    rail = ['' for _ in range(n)]
    i = 0

    for r in range(n):
        for j in range(len(ct)):
            if pattern[j] == r:
                rail[r] += ct[i]
                i += 1

    pos = [0] * n
    pt = ""

    for r in pattern:
        pt += rail[r][pos[r]]
        pos[r] += 1

    return pt


# ==================== KEYLESS TRANSPOSITION ====================

def keyless_encrypt(pt, n):
    while len(pt) % n != 0:
        pt += 'X'

    ct = ""

    for c in range(n):
        for i in range(c, len(pt), n):
            ct += pt[i]

    return ct


def keyless_decrypt(ct, n):
    rows = len(ct) // n
    mat = [''] * n
    k = 0

    for c in range(n):
        mat[c] = ct[k:k + rows]
        k += rows

    pt = ""

    for r in range(rows):
        for c in range(n):
            pt += mat[c][r]

    return pt


# ==================== KEYED TRANSPOSITION ====================

def keyed_encrypt(pt, key):
    n = len(key)

    while len(pt) % n != 0:
        pt += 'X'

    order = sorted(range(n), key=lambda x: key[x])
    ct = ""

    for c in order:
        for i in range(c, len(pt), n):
            ct += pt[i]

    return ct


def keyed_decrypt(ct, key):
    n = len(key)
    rows = len(ct) // n
    order = sorted(range(n), key=lambda x: key[x])

    mat = [''] * n
    k = 0

    for c in order:
        mat[c] = ct[k:k + rows]
        k += rows

    pt = ""

    for r in range(rows):
        for c in range(n):
            pt += mat[c][r]

    return pt


# ==================== COLUMNAR TRANSPOSITION ====================

def columnar_encrypt(pt, key):
    n = len(key)

    while len(pt) % n != 0:
        pt += 'X'

    rows = len(pt) // n
    order = sorted(range(n), key=lambda x: (key[x], x))
    ct = ""

    for c in order:
        for r in range(rows):
            ct += pt[r * n + c]

    return ct


def columnar_decrypt(ct, key):
    n = len(key)
    rows = len(ct) // n
    order = sorted(range(n), key=lambda x: (key[x], x))

    mat = [[''] * n for _ in range(rows)]
    k = 0

    for c in order:
        for r in range(rows):
            mat[r][c] = ct[k]
            k += 1

    return ''.join(''.join(row) for row in mat)


# ==================== COMBINED COLUMNAR ====================

def combined_encrypt(pt, key1, key2):
    ct = columnar_encrypt(pt, key1)
    ct = columnar_encrypt(ct, key2)
    return ct


def combined_decrypt(ct, key1, key2):
    pt = columnar_decrypt(ct, key2)
    pt = columnar_decrypt(pt, key1)
    return pt


# ==================== AES ====================

def aes_encrypt(pt, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(pt, AES.block_size))


def aes_decrypt(ct, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ct), AES.block_size)


# ==================== DES ====================

def des_encrypt(pt, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(pt, DES.block_size))


def des_decrypt(ct, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ct), DES.block_size)


# ==================== 2-DES ====================

def two_des_encrypt(pt, key1, key2):
    ct = des_encrypt(pt, key1)
    ct = des_encrypt(ct, key2)
    return ct


def two_des_decrypt(ct, key1, key2):
    pt = des_decrypt(ct, key2)
    pt = des_decrypt(pt, key1)
    return pt


# ==================== MAIN ====================

def main():

    print("========== COMBINED CIPHER SYSTEM ==========")

    pt = input("Enter plaintext: ")

    print("\n========== AFFINE CIPHER ==========")

    a = int(input("Enter affine key a: "))
    b = int(input("Enter affine key b: "))

    a = a % 26
    b = b % 26

    if gcd(a, 26) != 1:
        print("Invalid affine key. gcd(a,26) must be 1.")
        return

    aft = affine_encrypt(pt, a, b)

    print("After Affine Encryption:", aft)

    print("\n========== MENU ==========")
    print("1. Vigenere Cipher")
    print("2. Autokey Cipher")
    print("3. Playfair Cipher")
    print("4. Hill Cipher")
    print("5. Rail Fence Cipher")
    print("6. Keyless Transposition Cipher")
    print("7. Keyed Transposition Cipher")
    print("8. Columnar Transposition Cipher")
    print("9. Combined Columnar Transposition Cipher")
    print("10. AES")
    print("11. DES")
    print("12. 2-DES")

    choice = input("Enter choice: ")

    # Store all required information for decryption
    data = None

    # Vigenere
    if choice == '1':
        key = input("Enter Vigenere text key: ")
        ct = vigenere_encrypt(aft, key)
        data = ("vigenere", key)

    # Autokey
    elif choice == '2':
        print("\n1. Numeric-key Autokey")
        print("2. Text-key Autokey")

        x = input("Enter choice: ")

        if x == '1':
            key = int(input("Enter numeric key: "))
            ct = autokey_num_encrypt(aft, key)
            data = ("autokey_num", key)

        elif x == '2':
            key = input("Enter text key: ")
            ct = autokey_text_encrypt(aft, key)
            data = ("autokey_text", key)

        else:
            print("Invalid choice.")
            return

    # Playfair
    elif choice == '3':
        key = input("Enter Playfair key: ")
        ct = playfair_encrypt(aft, key)
        data = ("playfair", key)

    # Hill
    elif choice == '4':
        n = int(input("Enter matrix size: "))
        K = []

        print("Enter matrix:")
        for i in range(n):
            K.append(list(map(int, input().split())))

        if matrix_inverse(K) is None:
            print("Matrix is not invertible in Z-26.")
            return

        ct = hill_encrypt(aft, K)
        data = ("hill", K)

    # Rail Fence
    elif choice == '5':
        n = int(input("Enter number of rails: "))
        ct = rail_encrypt(aft, n)
        data = ("rail", n)

    # Keyless
    elif choice == '6':
        n = int(input("Enter number of columns: "))
        ct = keyless_encrypt(aft, n)
        data = ("keyless", n)

    # Keyed
    elif choice == '7':
        key = input("Enter permutation key: ")

        if len(set(key)) != len(key):
            print("Key must contain unique characters.")
            return

        ct = keyed_encrypt(aft, key)
        data = ("keyed", key)

    # Columnar
    elif choice == '8':
        key = input("Enter columnar key: ")

        ct = columnar_encrypt(aft, key)
        data = ("columnar", key)

    # Combined Columnar
    elif choice == '9':
        key1 = input("Enter first columnar key: ")
        key2 = input("Enter second columnar key: ")

        ct = combined_encrypt(aft, key1, key2)
        data = ("combined", key1, key2)

    # AES
    elif choice == '10':
        print("\n========== AES KEY SIZE ==========")
        print("1. AES-128")
        print("2. AES-192")
        print("3. AES-256")

        x = input("Enter key size: ")

        if x == '1':
            key = input("Enter 16-character key: ")
            if len(key) != 16:
                print("Invalid AES-128 key.")
                return

        elif x == '2':
            key = input("Enter 24-character key: ")
            if len(key) != 24:
                print("Invalid AES-192 key.")
                return

        elif x == '3':
            key = input("Enter 32-character key: ")
            if len(key) != 32:
                print("Invalid AES-256 key.")
                return

        else:
            print("Invalid choice.")
            return

        ct = aes_encrypt(aft.encode(), key.encode())
        data = ("aes", key.encode())

    # DES
    elif choice == '11':
        key = input("Enter DES key (8 characters): ")

        if len(key) != 8:
            print("Invalid DES key.")
            return

        ct = des_encrypt(aft.encode(), key.encode())
        data = ("des", key.encode())

    # 2-DES
    elif choice == '12':
        key1 = input("Enter first DES key (8 characters): ")
        key2 = input("Enter second DES key (8 characters): ")

        if len(key1) != 8 or len(key2) != 8:
            print("Invalid DES key.")
            return

        ct = two_des_encrypt(aft.encode(), key1.encode(), key2.encode())
        data = ("2des", key1.encode(), key2.encode())

    else:
        print("Invalid choice.")
        return

    print("\n========== RESULT ==========")

    if choice in ['10', '11', '12']:
        print("Final Ciphertext:", ct.hex())
    else:
        print("Final Ciphertext:", ct)

    # ==================== DECRYPTION ====================

    x = input("\nDo you want to decrypt? (y/n): ")

    if x.lower() != 'y':
        return

    print("\n========== DECRYPTION ==========")

    typ = data[0]

    if typ == "vigenere":
        aft2 = vigenere_decrypt(ct, data[1])

    elif typ == "autokey_num":
        aft2 = autokey_num_decrypt(ct, data[1])

    elif typ == "autokey_text":
        aft2 = autokey_text_decrypt(ct, data[1])

    elif typ == "playfair":
        aft2 = playfair_decrypt(ct, data[1])

    elif typ == "hill":
        aft2 = hill_decrypt(ct, data[1])

    elif typ == "rail":
        aft2 = rail_decrypt(ct, data[1])

    elif typ == "keyless":
        aft2 = keyless_decrypt(ct, data[1])

    elif typ == "keyed":
        aft2 = keyed_decrypt(ct, data[1])

    elif typ == "columnar":
        aft2 = columnar_decrypt(ct, data[1])

    elif typ == "combined":
        aft2 = combined_decrypt(ct, data[1], data[2])

    elif typ == "aes":
        aft2 = aes_decrypt(ct, data[1]).decode()

    elif typ == "des":
        aft2 = des_decrypt(ct, data[1]).decode()

    elif typ == "2des":
        aft2 = two_des_decrypt(ct, data[1], data[2]).decode()

    print("After Selected Cipher Decryption:", aft2)

    original = affine_decrypt(aft2, a, b)

    # Remove padding X added by transposition/Hill if present
    if choice in ['4', '6', '7', '8', '9']:
        original = original.rstrip('X')

    print("After Affine Decryption:", original)

    if original == pt:
        print("Verification: Success")
    else:
        print("Verification: Check padding/format")


if __name__ == "__main__":
    main()