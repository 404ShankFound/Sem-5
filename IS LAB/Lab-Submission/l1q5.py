def shift_encrypt(plaintext, shift):
    encrypted_text = []
    for char in plaintext:
        if char.isalpha():
            ascii_offset = ord("A") if char.isupper() else ord("a")
            shifted_num = (ord(char) - ascii_offset + shift) % 26
            encrypted_text.append(chr(shifted_num + ascii_offset))
        else:
            encrypted_text.append(char)
    return "".join(encrypted_text)


def shift_decrypt(ciphertext, shift):
    decrypted_text = []
    for char in ciphertext:
        if char.isalpha():
            ascii_offset = ord("A") if char.isupper() else ord("a")
            orig_num = (ord(char) - ascii_offset - shift) % 26
            decrypted_text.append(chr(orig_num + ascii_offset))
        else:
            decrypted_text.append(char)
    return "".join(decrypted_text)


def known_plaintext_attack(known_cipher, known_plain):
    c_char, p_char = None, None
    for cc, pc in zip(known_cipher, known_plain):
        if cc.isalpha() and pc.isalpha():
            c_char = cc
            p_char = pc
            break

    if not c_char or not p_char:
        raise ValueError("No valid alphabetic characters found in the samples.")

    shift = (ord(c_char.lower()) - ord(p_char.lower())) % 26
    return shift


sample_cipher = input("Enter sample ciphertext (default 'CIW'): ").strip() or "CIW"
sample_plain = input("Enter sample plaintext (default 'yes'): ").strip() or "yes"
target_ciphertext = input("Enter target ciphertext to decrypt (default 'XVIEWYWI'): ").strip() or "XVIEWYWI"

derived_shift = known_plaintext_attack(sample_cipher, sample_plain)
print(f"\nDerived Shift Key: {derived_shift}")

decrypted_result = shift_decrypt(target_ciphertext, derived_shift)
print(f"Target Ciphertext: {target_ciphertext}")
print(f"Decrypted Plaintext: {decrypted_result}")