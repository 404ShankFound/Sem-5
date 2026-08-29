"""1. Check if a number/key is invertible in Z-26 or not.
    GCD(k, 26) = 1. Handle k < 0.
"""
# Python's % works with negative numbers and gives you the positive modular remainder.
#-15 % 26 = 11
#-26 % 26 = 0

'''
NORMAL POWER
pow(a,b) = a^b

MODULAR EXPONENTIATION:
pow(a, b, m) = (a^b mod m)
'''

import math

def gcd(k):
    return math.gcd(k,26)

def inputk():
    return int(input("Enter the key: "))

def main():
    key = inputk() % 26
    if gcd(key)!=1:
        print("Key not invertible")
        return
    print("Invertible Key: ", key)

    #First check if inverse exists and then find out the inverse using modular exponentiation
    print("Inverse of the key in Z26: ", pow(key,-1,26))



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