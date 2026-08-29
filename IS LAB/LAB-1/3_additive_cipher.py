'''
| Check             | Detects                 | Example             | Result |
| ----------------- | ----------------------- | ------------------- | ------ |
| `c.isalpha()`     | Alphabet (`A-Z`, `a-z`) | `"A".isalpha()`     | `True` |
| `c.isdigit()`     | Digit (`0-9`)           | `"5".isdigit()`     | `True` |
| `c.isalnum()`     | Alphabet **or** digit   | `"A".isalnum()`     | `True` |
| `c.isspace()`     | Space / tab / newline   | `" ".isspace()`     | `True` |
| `c.isupper()`     | Uppercase letter        | `"A".isupper()`     | `True` |
| `c.islower()`     | Lowercase letter        | `"a".islower()`     | `True` |
| `c.isprintable()` | Printable character     | `"@".isprintable()` | `True` |

"\n" is not printable thus "\n".isprintable() return false
'''
a_base = ord('a')
A_BASE = ord('A')

def inputct():
    return input("Enter ciphertext: "), int(input("Enter the key: "))

def inputpt():
    return input("Enter plaintext: "), int(input("Enter the key: "))

A_BASE = ord('A')
a_base = ord('a')

def encrypt_additive(pt, key):
    ct = ""

    for c in pt:

        # Encrypt alphabets
        if c.isalpha():
            if c.islower():
                ct += chr((key + ord(c) - a_base) % 26 + a_base)
            else:
                ct += chr((key + ord(c) - A_BASE) % 26 + A_BASE)

        # Handle non-alphabet characters
        else:
            # Shift digits by 1
            if c.isdigit():
                ct += str((int(c) + key) % 10)
            # Keep spaces unchanged
            elif c.isspace():
                ct += c
            else:
                ct += c #We dont want to encrypt symbols, thus if we dont write this symbols would've been disappeared

    print("CipherText:", ct)

# Note: When shifting digits, 9 becomes 10 if we simply add 1. Example:
# str(int('9') + 1) gives "10"

# This causes one input character ('9') to become two characters ('1','0').
# Therefore, use modulo 10 to keep the result as a single digit:

# (int('9') + 1) % 10 = 0
# 0 -> 1, 1 -> 2, ..., 8 -> 9, 9 -> 0

def decrypt_additive(ct, key):
    pt = ""

    for c in ct:

        # Encrypt alphabets
        if c.isalpha():
            if c.islower():
                pt += chr((ord(c) - a_base - key) % 26 + a_base)
            else:
                pt += chr((ord(c) - A_BASE - key) % 26 + A_BASE)

        # Handle non-alphabet characters
        else:
            # Shift digits by 1
            if c.isdigit():
                pt += str((int(c) - key) % 10)
            # Keep spaces unchanged
            elif c.isspace():
                pt += c
            else:
                pt += c #We dont want to encrypt symbols, thus if we dont write this symbols would've been disappeared

    print("PlainText:", pt)

def main():

    while(True):

        choice = int(input("Enter 1 for Encryption and 2 for Decryption: "))

        if(choice==1):
            pt,key1=inputpt()
            print("Plaintext: ", pt)
            print("Key: ", key1)
            encrypt_additive(pt,key1)

        elif(choice==2):
            ct,key2=inputct()
            print("Ciphertext: ", ct)
            print("Key: ", key2)
            decrypt_additive(ct,key2)

        else:
            exit()

    

if __name__ == "__main__":
    main()
