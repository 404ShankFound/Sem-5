"""1. Check if a number/key is invertible in Z-26 or not.
    GCD(k, 26) = 1. Handle k < 0.
"""

import math

def gcd(k):
    return math.gcd(k,26)

def inputct():
    return input("Enter ciphertext: "), int(input("Enter the key: "))

def inputpt():
    return input("Enter plaintext: "), int(input("Enter the key: "))

def main():
    pt,key1=inputpt()
    ct,key2=inputct()
    print("Plaintext: ", pt)
    print("Key: ", key1)
    print("Ciphertext: ", ct)
    

if __name__ == "__main__":
    main()

# import math

# # Check whether a number is invertible in Z-26
# k = int(input("Enter the key: "))

# # Handle negative key
# k = abs(k)

# # A number is invertible modulo 26 if GCD(k, 26) = 1
# if math.gcd(k, 26) == 1:
#     print("The key is invertible in Z-26.")
# else:
#     print("The key is NOT invertible in Z-26.")