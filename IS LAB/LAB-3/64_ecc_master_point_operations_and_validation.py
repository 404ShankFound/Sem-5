# %%
"""
Question 64: ECC Master Point Operations and Validation

Implement an interactive ECC program that accepts an elliptic curve and supports point validation, point addition, point doubling, and scalar multiplication. The program must validate points before performing operations and display appropriate errors for invalid points.

Flow:
Curve Parameters
      ↓
Enter p, a, b
      ↓
Enter Point(s)
      ↓
Validate Point
      ↓
┌───────────────┬───────────────┬──────────────────┐
│ Point Add     │ Point Double  │ Scalar Multiply  │
│ P + Q         │ 2P            │ kP               │
└───────────────┴───────────────┴──────────────────┘
      ↓
Display Result

Requirements:
- Accept p, a, b
- Accept point coordinates
- Check whether points satisfy y² = x³ + ax + b mod p
- Handle invalid points
- Handle point at infinity
- Implement point addition
- Implement point doubling
- Implement scalar multiplication using repeated doubling/addition
- Display resulting coordinates
- Include suitable error messages

Absorbs: original Q59, Q60, Q61, Q63, Q64.

"""

def main():
    # TODO: Implement the experiment described above.
    pass


if __name__ == "__main__":
    main()
