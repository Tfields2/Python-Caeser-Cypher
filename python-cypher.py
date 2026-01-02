import string

def caesar_encrypt(message, key):
    shift = key % 26
    cipher = str.maketrans(string.ascii_lowercase, string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift])
    ciphertext = message.lower().translate(cipher)
    return ciphertext

def caesar_decrypt(ciphertext, key):
    shift = (-key) % 26
    cipher = str.maketrans(string.ascii_lowercase, string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift])
    message = ciphertext.translate(cipher)
    return message


message = input("Enter a message to encrypt: ")

while True:
    try:
        key = int(input("Enter shift value (1-25): "))
        if 1 <= key <= 25:
            break
        else:
            key = int(input("Invalid key. Please enter a shift value between 1 and 25: "))
    except ValueError:
        key = int(input("Invalid input. Please enter a valid integer: "))

encrypted_message = caesar_encrypt(message, key)
print("Encrypted message:", encrypted_message)

decrypted_message = caesar_decrypt(encrypted_message, key)
print("Decrypted message:", decrypted_message)