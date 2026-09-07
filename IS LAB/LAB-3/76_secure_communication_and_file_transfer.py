# %%
"""
Question 76: Secure Communication and File Transfer

Build a secure communication/file-transfer system supporting RSA-based, ECC-based and DH-based secure communication. Use asymmetric cryptography for key exchange/key protection and AES for actual message/file encryption.

Flow:
                   Secure System
                        ↓
        ┌───────────────┼────────────────┐
        ↓               ↓                ↓
       RSA             ECC               DH
        ↓               ↓                ↓
   RSA + AES        ECDH + AES        DH + AES
        └───────────────┼────────────────┘
                        ↓
               Message / File
                        ↓
                    Encrypt
                        ↓
                    Transfer
                        ↓
                    Decrypt
                        ↓
                   Verify

Menu:
1. RSA Secure Message
2. RSA Secure File
3. ECC Secure File
4. DH Secure Communication
5. Multiple Users
6. Different File Sizes
7. RSA vs ECC Transfer
8. Exit

Requirements:
- Recipient public key encryption
- Private-key decryption
- RSA + AES file transfer
- ECC/ECDH + AES file transfer
- DH + AES secure communication
- Multiple users
- Different file sizes
- Verification
- Performance comparison
- Hybrid encryption for large data

Absorbs: original Q109–115.

"""

def main():
    # TODO: Implement the experiment described above.
    pass


if __name__ == "__main__":
    main()
