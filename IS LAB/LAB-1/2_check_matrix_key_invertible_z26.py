
"""2. Check if a matrix/key is invertible or not.
GCD(det(K), 26) = 1. Handle det(K) < 0.
"""
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

