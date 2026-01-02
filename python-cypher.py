import string

def make_cypher(key: int):
    shift = key %26
    lower_src = string.ascii_lowercase
    lower_dst = lower_src[shift:] + lower_src[:shift]
    upper_src = string.ascii_uppercase
    upper_dst = upper_src[shift:] + upper_src[:shift]
    return str.maketrans(lower_src + upper_src, lower_dst + upper_dst)

def caesar_encrypt(message, key):
    return message.translate(make_cypher(key))

def caesar_decrypt(ciphertext, key):
    return ciphertext.translate(make_cypher(-key))

def brute_force(cipheertext: str):
    for key in range(1, 26):
        print(f"Key {key:2}: {caesar_decrypt(cipheertext, key)}")
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