import sys


def playfair_cipher():
    action = input("Choose action - (E)ncrypt or (D)ecrypt: ").strip().upper()
    text = input("Enter the message: ")
    keyword = input("Enter the keyword: ")

    keyword_clean = "".join(dict.fromkeys(keyword.lower().replace('j', 'i')))
    alphabet = "abcdefghiklmnopqrstuvwxyz"

    matrix_chars = []
    for char in keyword_clean + alphabet:
        if char not in matrix_chars and char.isalpha():
            matrix_chars.append(char)

    matrix = [matrix_chars[i:i + 5] for i in range(0, 25, 5)]

    print("\nMatrix:")
    for row in matrix:
        print(" ".join(row).upper())
    print("\n")

    def find_pos(char):
        for r, row in enumerate(matrix):
            if char in row:
                return r, row.index(char)
        return 0, 0

    if action == 'E':
        clean_text = "".join([c.lower().replace('j', 'i') for c in text if c.isalpha()])
        prepared_text = []
        i = 0
        while i < len(clean_text):
            char1 = clean_text[i]
            if i + 1 < len(clean_text):
                char2 = clean_text[i + 1]
                if char1 == char2:
                    prepared_text.append(char1 + 'x')
                    i += 1
                else:
                    prepared_text.append(char1 + char2)
                    i += 2
            else:
                prepared_text.append(char1 + 'x')
                i += 1

        ciphertext = []
        for pair in prepared_text:
            r1, c1 = find_pos(pair[0])
            r2, c2 = find_pos(pair[1])
            if r1 == r2:
                ciphertext.append(matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5])
            elif c1 == c2:
                ciphertext.append(matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2])
            else:
                ciphertext.append(matrix[r1][c2] + matrix[r2][c1])
        print("Result:", "".join(ciphertext))

    elif action == 'D':
        clean_text = "".join([c.lower().replace('j', 'i') for c in text if c.isalpha()])
        plaintext = []
        i = 0
        while i < len(clean_text):
            if i + 1 < len(clean_text):
                pair = clean_text[i:i + 2]
                r1, c1 = find_pos(pair[0])
                r2, c2 = find_pos(pair[1])
                if r1 == r2:
                    plaintext.append(matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5])
                elif c1 == c2:
                    plaintext.append(matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2])
                else:
                    plaintext.append(matrix[r1][c2] + matrix[r2][c1])
                i += 2
            else:
                break
        print("Result:", "".join(plaintext))
    else:
        print("PLz do a valid selection")


while True:
    print("\nPlayfair Cipher Menu:")
    print("1. Run Playfair Cipher")
    print("2. Exit")
    choice = input("Enter choice (1 or 2): ").strip()
    if choice == '1':
        playfair_cipher()
    elif choice == '2':
        sys.exit()
    else:
        print("Invalid selection.")
