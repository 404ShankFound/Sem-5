"""
Question 55: Ecc different curves

Generate ECC keys using different supported curves and compare their key-generation times.
"""

from Crypto.PublicKey import ECC
import time


def main():
    # Different ECC curves to compare
    curves = ["P-192", "P-224", "P-256", "P-384", "P-521"]

    print("\n--- ECC Key Generation Performance ---")

    for curve in curves:
        # Start timer
        st = time.perf_counter()

        # Generate ECC key pair
        key = ECC.generate(curve=curve)

        # Stop timer
        et = time.perf_counter()

        # Calculate time taken
        t = et - st

        print(curve, ":", t, "seconds")


if __name__ == "__main__":
    main()