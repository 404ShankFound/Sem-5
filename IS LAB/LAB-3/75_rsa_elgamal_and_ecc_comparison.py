# %%
"""
Question 75: RSA, ElGamal and ECC Comparison

Implement RSA, ElGamal and ECC-based encryption/decryption for common input data and compare their key-generation, encryption and decryption performance. Support pairwise comparisons as well as a complete three-algorithm comparison.

Flow:
                    Same Input
                        ↓
          ┌─────────────┼─────────────┐
          ↓             ↓             ↓
         RSA         ElGamal         ECC
          ↓             ↓             ↓
       Encrypt       Encrypt       Hybrid
          ↓             ↓             ↓
       Decrypt       Decrypt       Decrypt
          ↓             ↓             ↓
       Verify        Verify        Verify
          └─────────────┼─────────────┘
                        ↓
                  Performance
                        ↓
              Algorithm Comparison

Requirements:
- RSA
- ElGamal
- ECC hybrid encryption
- Same input message
- Multiple messages
- Different message sizes
- Key-generation timing
- Encryption timing
- Decryption timing
- Key/storage-size comparison
- Pairwise comparison
- Three-way comparison
- Determine suitable algorithm for different message sizes

Absorbs: original Q103–108.

"""

def main():
    # TODO: Implement the experiment described above.
    pass


if __name__ == "__main__":
    main()
