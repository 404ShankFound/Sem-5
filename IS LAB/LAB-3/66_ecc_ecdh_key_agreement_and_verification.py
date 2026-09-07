# %%
"""
Question 66: ECC ECDH Key Agreement and Verification

Generate Alice and Bob ECC key pairs, exchange public keys and independently calculate their shared secrets. Verify that both parties obtain the same shared secret.

Allow the curve/key parameters to be selected or entered where applicable.

Flow:
        ECC Curve
            ↓
    ┌───────────────┐
    │ Alice Key Pair │
    │ dA , QA        │
    └───────┬───────┘
            │ QA
            ↓
       Public Exchange
            ↑
            │ QB
    ┌───────┴───────┐
    │  Bob Key Pair  │
    │ dB , QB        │
    └───────────────┘
            ↓
 ┌─────────────────────────┐
 │ Alice: SA = dA × QB     │
 │ Bob:   SB = dB × QA     │
 └────────────┬────────────┘
              ↓
         SA == SB ?
          /              YES         NO
        ↓           ↓
     SUCCESS      FAILURE

Requirements:
- Generate Alice and Bob ECC key pairs
- Exchange public keys
- Calculate shared secrets independently
- Display both shared secrets
- Verify equality
- Support user-selected/entered parameters where practical
- Display SUCCESS/FAILURE

Absorbs: original Q65, Q66, Q67.

"""

def main():
    # TODO: Implement the experiment described above.
    pass


if __name__ == "__main__":
    main()
