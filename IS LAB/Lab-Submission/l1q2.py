import sys

def vigenere_cipher():
    action = input("Choose action - (E)ncrypt or (D)ecrypt: ").strip().upper()
    text = input("Enter the message: ")
    key = input("Enter the text key: ").strip().lower()
    
    if not key:
        print("Key cannot be empty.")
        return

    result = []
    key_len = len(key)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % key_len]) - ord('a')
            is_upper = char.isupper()
            base = ord('A') if is_upper else ord('a')
            
            if action == 'E':
                new_char_code = (ord(char) - base + shift) % 26 + base
            else:
                new_char_code = (ord(char) - base - shift) % 26 + base
                
            result.append(chr(new_char_code))
            key_index += 1
        else:
            result.append(char)
            
    print("Result:", "".join(result))

def autokey_cipher():
    action = input("Choose action - (E)ncrypt or (D)ecrypt: ").strip().upper()
    text = input("Enter the message: ")
    key_input = input("Enter the numeric key: ").strip()
    
    try:
        numeric_key = int(key_input)
        result = []
        
        if action == 'E':
            current_key = numeric_key
            for char in text:
                if char.isalpha():
                    is_upper = char.isupper()
                    base = ord('A') if is_upper else ord('a')
                    p = ord(char) - base
                    c = (p + current_key) % 26
                    result.append(chr(c + base))
                    current_key = p
                else:
                    result.append(char)
        else:
            current_key = numeric_key
            for char in text:
                if char.isalpha():
                    is_upper = char.isupper()
                    base = ord('A') if is_upper else ord('a')
                    c = ord(char) - base
                    p = (c - current_key) % 26
                    result.append(chr(p + base))
                    current_key = p
                else:
                    result.append(char)
                    
        print("Result:", "".join(result))
    except ValueError:
        print("Invalid numeric key.")

while True:
    print("\nChoose the Cipher:")
    print("1. Vigenere Cipher")
    print("2. Autokey Cipher")
    print("3. Exit")
    choice = input("Enter choice (1, 2, or 3): ").strip()

    if choice == '1':
        vigenere_cipher()
    elif choice == '2':
        autokey_cipher()
    elif choice == '3':
        sys.exit()
    else:
        print("Invalid selection.")