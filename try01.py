def encryption_caeser_cipher():
    def encrypt(text, shift):
    encrypted_text = ""
        for char in text:
    if char.isalpha():
    ascii_offset = 65 if char.isupper() else 97
    encrypted_text += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)



