"""Keyed Transposition Attack.
a. Type of attack: Known Plaintext Attack (KPA)
b. Size of permutation key: 9
Because the plaintext has 9 characters and the ciphertext reveals 
the permutation of those 9 positions, the permutation key has 9 elements.
"""

def main():
    pt = "abcdefghi"
    ct = "CABDEHFGL"

    # Find the permutation
    p = []
    for c in ct:
        p.append(pt.index(c.lower()) + 1)

    print("Permutation:", p)
    print("Key size:", len(p))
    print("Attack: Known Plaintext Attack (KPA)")


if __name__ == "__main__":
    main()