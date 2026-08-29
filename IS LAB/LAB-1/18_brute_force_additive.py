"""18. Brute force for additive."""

def main():
    pass


if __name__ == "__main__":
    main()

'''Use a brute-force attack to decipher the following message enciphered by Alice using an 
additive cipher. Suppose that Alice always uses a key that is close to her birthday, which is on 
the 13th of the month: 
NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY 
(Considering range to be +3 and -3 from the B'Day)
'''
'''
def decrypt_additive(ciphertext, key):
    plaintext = []
    for char in ciphertext:
        if char.isalpha():
            # Calculate the shifted position for uppercase letters (A=0, B=1, ..., Z=25)
            shifted_ord = (ord(char) - ord('A') - key) % 26
            plaintext.append(chr(shifted_ord + ord('A')))
        else:
            # Leave special characters like '/' and '&' unchanged
            plaintext.append(char)
    return "".join(plaintext)

# The encrypted message from Alice
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

print("--- Brute-Force Results Around Key 13 ---")
# Testing keys close to her birthday on the 13th
for possible_key in range(8, 16):
    decrypted_message = decrypt_additive(ciphertext, possible_key)
    
    # Highlight the correct key
    if possible_key == 11:
        print(f"Key {possible_key:02d}: {decrypted_message} <-- CORRECT KEY")
    else:
        print(f"Key {possible_key:02d}: {decrypted_message}")
'''