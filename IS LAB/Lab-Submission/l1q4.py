import math
import sys
def get_matrix_determinant(m, mod=26):
    n = len(m)
    mat = [[val % mod for val in row] for row in m]
    det = 1
    for i in range(n):
        pivot = i
        while pivot < n and mat[pivot][i] == 0:
            pivot += 1
        if pivot == n:
            return 0
        if pivot != i:
            mat[i], mat[pivot] = mat[pivot], mat[i]
            det = -det
        det = (det * mat[i][i]) % mod
        try:
            inv_pivot = pow(mat[i][i], -1, mod)
        except ValueError:
            return 0
        for j in range(i + 1, n):
            factor = (mat[j][i] * inv_pivot) % mod
            for k in range(i, n):
                mat[j][k] = (mat[j][k] - factor * mat[i][k]) % mod

    return det % mod


def get_matrix_inverse(m, mod=26):
    n = len(m)
    aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(m)]

    for i in range(n):
        pivot = i
        while pivot < n and aug[pivot][i] % mod == 0:
            pivot += 1

        if pivot == n:
            return None

        if pivot != i:
            aug[i], aug[pivot] = aug[pivot], aug[i]

        try:
            inv_pivot = pow(aug[i][i] % mod, -1, mod)
        except ValueError:
            return None

        for j in range(2 * n):
            aug[i][j] = (aug[i][j] * inv_pivot) % mod

        for j in range(n):
            if j != i:
                factor = aug[j][i]
                for k in range(2 * n):
                    aug[j][k] = (aug[j][k] - factor * aug[i][k]) % mod
    inv = [[aug[i][j + n] % mod for j in range(n)] for i in range(n)]
    return inv


def multiply_matrix_vector(matrix, vector, mod=26):
    result = []
    for row in matrix:
        sum_val = sum(row[i] * vector[i] for i in range(len(vector)))
        result.append(sum_val % mod)
    return result


def hill_cipher():
    action = input("Choose action - (E)ncrypt or (D)ecrypt: ").strip().upper()
    if action not in ["E", "D"]:
        print("Invalid action selected.")
        return

    try:
        size = int(input("Enter matrix dimension N (e.g., 2, 3, 5, etc.): ").strip())
    except ValueError:
        print("Error: Please enter a valid integer for the dimension.")
        return

    if size < 2:
        print("Error: Dimension must be at least 2.")
        return

    expected_numbers = size * size
    text = input("Enter the message: ")
    key_input = input(f"Enter the {expected_numbers} key numbers (space-separated): ").strip()

    try:
        key_numbers = list(map(int, key_input.split()))
    except ValueError:
        print("Error: Please enter valid integers separated by spaces.")
        return

    if len(key_numbers) != expected_numbers:
        print(f"Error: You must enter exactly {expected_numbers} numbers for a {size}x{size} matrix.")
        return

    matrix = [key_numbers[i: i + size] for i in range(0, expected_numbers, size)]

    det = get_matrix_determinant(matrix, 26)
    if det == 0 or math.gcd(det, 26) != 1:
        print(f"Error: Matrix determinant ({det}) is not coprime with 26. This key cannot be used!")
        return

    print("\nKey Matrix:")
    for row in matrix:
        print(" ".join(f"{num:02d}" for num in row))
    print("\n")

    clean_chars = [c for c in text if c.isalpha()]

    pad_char = 'X' if (clean_chars and clean_chars[-1].isupper()) else 'x'
    while len(clean_chars) % size != 0:
        clean_chars.append(pad_char)

    vectors = []
    for i in range(0, len(clean_chars), size):
        block = clean_chars[i: i + size]
        vectors.append([ord(char.lower()) - ord("a") for char in block])

    result_chars = []

    if action == "E":
        for idx, vec in enumerate(vectors):
            res_vec = multiply_matrix_vector(matrix, vec)
            for j, num in enumerate(res_vec):
                orig_char = clean_chars[idx * size + j]
                res_char = chr(num + ord("a"))
                if orig_char.isupper():
                    res_char = res_char.upper()
                result_chars.append(res_char)
        print("Result (Encrypted):", "".join(result_chars))

    elif action == "D":
        inv_matrix = get_matrix_inverse(matrix)
        if inv_matrix is None:
            print("Error: Inverse matrix could not be computed.")
            return
        for idx, vec in enumerate(vectors):
            res_vec = multiply_matrix_vector(inv_matrix, vec)
            for j, num in enumerate(res_vec):
                orig_char = clean_chars[idx * size + j]
                res_char = chr(num + ord("a"))
                if orig_char.isupper():
                    res_char = res_char.upper()
                result_chars.append(res_char)
        print("Result (Decrypted):", "".join(result_chars))


while True:
    print("\nHill Cipher Menu:")
    print("1. Run Hill Cipher")
    print("2. Exit")
    choice = input("Enter choice (1 or 2): ").strip()
    if choice == "1":
        hill_cipher()
    elif choice == "2":
        sys.exit()
    else:
        print("Invalid selection")