# %%
"""
Question 78: Complete RSA, ElGamal and ECC Analysis

Using the implementations from the cryptographic system, perform a comprehensive comparison of RSA, ElGamal and ECC based on key size/storage overhead, key-generation time, encryption time and decryption time.

Flow:
RSA ───────┐
ElGamal ──┼──→ Generate Keys
ECC ───────┘          ↓
                 Measure Parameters
                       ↓
              ┌────────┼────────┐
              ↓        ↓        ↓
            KeyGen   Encrypt  Decrypt
              └────────┼────────┘
                       ↓
                Comparison Table
                       ↓
                 Analysis/Result

Requirements:
- RSA
- ElGamal
- ECC
- Key-size comparison
- Storage overhead
- Key generation time
- Encryption time
- Decryption time
- Comparison table
- Identify relative strengths/performance

Absorbs: original Q121.

"""

def main():
    # TODO: Implement the experiment described above.
    pass


if __name__ == "__main__":
    main()
