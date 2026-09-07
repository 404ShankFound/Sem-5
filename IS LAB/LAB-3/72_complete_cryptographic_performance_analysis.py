# %%
"""
Question 72: Complete Cryptographic Performance Analysis

Create an interactive performance-analysis system that compares RSA, ElGamal and ECC based on key generation, encryption and decryption time. Support key-size comparisons, repeated measurements, average execution time, time overhead and identification of the fastest algorithm.

Flow:
                 Performance System
                        ↓
          ┌─────────────┴─────────────┐
          ↓                           ↓
     Algorithm Test              Key Size Test
          ↓                           ↓
 Message Size Test              Key Generation
          ↓
   Repeat Measurements
          ↓
   Average Execution Time
          ↓
 ┌────────┬────────┬────────┐
 │ RSA    │ ElGamal│ ECC    │
 └────────┴────────┴────────┘
          ↓
 Comparison / Difference
          ↓
 Fastest Algorithm

Requirements:
- RSA/ElGamal/ECC
- Key-generation timing
- Encryption timing
- Decryption timing
- Different message sizes
- Different key sizes
- Repeated tests
- Average timing
- Time overhead/difference
- Fastest algorithm
- Final comparison table

Absorbs: original Q86–90.

"""

def main():
    # TODO: Implement the experiment described above.
    pass


if __name__ == "__main__":
    main()
