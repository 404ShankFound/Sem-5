# %%
"""
Question 73: Multiple Message, File, Binary and Large-Data Hybrid Encryption

Create a hybrid asymmetric encryption system capable of handling multiple messages, different message sizes, repeated encryption of the same message, text-file input, binary data and large data.

Asymmetric cryptography should be used for key exchange/key protection, while AES should encrypt the actual data.

Flow:
              Input Data
                  ↓
      ┌───────────┼────────────┐
      ↓           ↓            ↓
   Message      Text File    Binary Data
      └───────────┼────────────┘
                  ↓
            Generate AES Key
                  ↓
       RSA / ECC Key Protection
                  ↓
             AES Encryption
                  ↓
              Ciphertext
                  ↓
             AES Decryption
                  ↓
            Original Data
                  ↓
             Verification

Menu:
1. Multiple Messages
2. Different Message Sizes
3. Same Message Multiple Times
4. Text File
5. Binary Data
6. Large Data
7. Exit

Requirements:
- Same key for multiple messages
- Different message sizes
- Same message encrypted multiple times
- Text file support
- Binary data support
- Large data support
- RSA/ECC + AES hybrid approach
- Decryption
- Verification
- Authentication/tampering detection where supported

Absorbs: original Q91–96.

This is intentionally a support/master program, because these checks should also be integrated into the RSA/ECC/ElGamal/DH programs rather than duplicated blindly.

"""

def main():
    # TODO: Implement the experiment described above.
    pass


if __name__ == "__main__":
    main()
