"""
2. Check if a matrix/key is invertible or not.
GCD(det(K), 26) = 1. Handle det(K) < 0.
"""

import numpy as np
import math


# Find GCD of determinant and 26
def gcd(k):
    return math.gcd(k, 26)


# Take matrix input dynamically
def inputkey():
    size = int(input("Enter matrix dimension: "))

    expected_numbers = size * size

    key_input = input(
        f"Enter {expected_numbers} key numbers: "
    ).split()

    key_numbers = list(map(int, key_input))

    # Convert into N x N matrix
    matrix = [
        key_numbers[i:i + size]
        for i in range(0, expected_numbers, size)
    ]

    return matrix


# Find inverse of matrix modulo 26
def get_matrix_inverse(m, mod=26):
    n = len(m)

    # Create [Matrix | Identity]
    aug = [
        row[:] + [1 if i == j else 0 for j in range(n)]
        for i, row in enumerate(m)
    ]

    for i in range(n):

        # Find a pivot which is invertible modulo 26 instead of just finding non-zero pivot
        pivot = i

        while pivot < n:
            if math.gcd(aug[pivot][i] % mod, mod) == 1:
                break
            pivot += 1

        if pivot == n:
            return None

        # Swap rows if required
        if pivot != i:
            aug[i], aug[pivot] = aug[pivot], aug[i]

        # Find modular inverse of pivot
        inv_pivot = pow(aug[i][i] % mod, -1, mod)

        # Make pivot = 1
        for j in range(2 * n):
            aug[i][j] = (aug[i][j] * inv_pivot) % mod

        # Make other elements in this column = 0
        for j in range(n):
            if j != i:
                factor = aug[j][i]

                for k in range(2 * n):
                    aug[j][k] = (
                        aug[j][k] - factor * aug[i][k]
                    ) % mod

    # Extract right half
    return [
        row[n:]
        for row in aug
    ]


def main():

    # Input key matrix
    A = inputkey()

    print("Key:")
    for row in A:
        print(row)

    # Find determinant:
    # NumPy stores the result of np.linalg.det() as a floating-point number, 
    # even when the actual determinant is an integer.
    det = round(np.linalg.det(A)) % 26

    print("Determinant mod 26:", det)

    # Check if invertible:
    if gcd(det) != 1:
        print("Matrix is NOT invertible")
    else:
        print("Matrix is invertible")

        # Find inverse modulo 26
        inv_mat = get_matrix_inverse(A)

        print("Inverse:")
        for row in inv_mat:
            print(row)

# np.linalg.det() returns the determinant as a float.

# NumPy uses floating-point arithmetic internally, so even if the
# actual determinant is exactly 5, it may sometimes return a value
# like 4.999999999999999 or 5.000000000000001.

# Example:
# Actual determinant = 5
# NumPy may return = 4.999999999999999
#
# int(4.999999999999999) gives 4, which is WRONG.
# round(4.999999999999999) gives 5, which is CORRECT.
# Therefore, use round() before converting to mod 26.
# det = round(np.linalg.det(A)) % 26

if __name__ == "__main__":
    main()