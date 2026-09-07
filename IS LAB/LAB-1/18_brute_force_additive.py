"""18. Brute force for additive."""

def decrypt_additive(ct, k):
    pt = ""

    for c in ct:
        if c.isalpha():
            x = (ord(c) - ord('A') - k) % 26
            pt += chr(x + ord('A'))
        else:
            pt += c

    return pt


def main():
    ct = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

    print("Brute-Force Results Around Key 13:")

    # Birthday = 13, range = +3 and -3
    for k in range(10, 17):
        pt = decrypt_additive(ct, k)
        print("Key", k, ":", pt)


if __name__ == "__main__":
    main()