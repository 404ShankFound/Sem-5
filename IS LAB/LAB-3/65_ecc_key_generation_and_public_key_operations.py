# %%
"""
Question 65: ECC Key Generation and Public Key Operations

Generate ECC key pairs using a selected/fixed curve and display the private key and public point coordinates separately. Allow multiple private keys to be used with the same curve/base point to demonstrate the corresponding public keys.

Flow:
Select Curve
     ↓
Generate / Enter Private Key
     ↓
Q = dG
     ↓
Display
 ┌───────────────┐
 │ Private key d │
 │ Public Q      │
 │ Q.x           │
 │ Q.y           │
 └───────────────┘
     ↓
Optional: Different d values
     ↓
Compare Public Keys

Requirements:
- Support secp256r1
- Display private key
- Display public point (x,y)
- Accept/use different private keys
- Calculate corresponding public keys
- Reuse the same curve/base point when comparing private keys

Absorbs: original Q54, Q56, Q57, Q58.

"""

def main():
    # TODO: Implement the experiment described above.
    pass


if __name__ == "__main__":
    main()
