import string
from pathlib import Path
import json
import os

def valid_key() -> int:
    while True:
        try:
            key = int(input("Enter shift value (1-25): "))
            if 1 <= key <= 25:
                return key
            print("Key must be between 1 and 25.")
        except ValueError:
            print("Invalid input. Please enter an integer between 1 and 25.")

def make_cipher(key: int):
    shift = key % 26
    lower_src = string.ascii_lowercase
    lower_dst = lower_src[shift:] + lower_src[:shift]
    upper_src = string.ascii_uppercase
    upper_dst = upper_src[shift:] + upper_src[:shift]
    return str.maketrans(lower_src + upper_src, lower_dst + upper_dst)

def dedupe_key(cipher_message: str) -> str:
    # Case-insensitive + trims ends + collapses internal whitespace
    return " ".join(cipher_message.split()).casefold()

def caesar_encrypt(message: str, key: int) -> str:
    encrypted = message.translate(make_cipher(key))
    file_path = "cipher_log.jsonl"

    seen = set()
    last_id = 0

    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                last_id = record.get("id", last_id)

                seen.add(dedupe_key(record.get("cipher_message", "")))

                if dedupe_key(encrypted) in seen:
                    return encrypted
        
        new_id = last_id + 1

    with open(file_path, "a", encoding="utf-8") as f:
        json.dump(
            {
                "id": new_id,
                "cipher_message": encrypted,
                "key": key
            },
            f,
            ensure_ascii=False
        )
        f.write("\n")
    
    return encrypted

def caesar_decrypt(ciphertext: str, key: int) -> str:
    return ciphertext.translate(make_cipher(-key))

def brute_force(ciphertext: str):
    for key in range(1, 26):
        print(f"Key {key:2}: {caesar_decrypt(ciphertext, key)}")

def read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")

def write_file(path: str, text: str):
    Path(path).write_text(text, encoding="utf-8")

def menu():
    print("\nMenu:")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Brute-force decrypt a message")
    print("4. Encrypt a file")
    print("5. Decrypt a file")
    print("6. Exit")

while True:
    menu()
    choice = input("Choose an option (1-6): ").strip()

    if choice == "1":
        message = input("Enter message to encrypt: ")
        key = valid_key()
        print("Encrypted message:", caesar_encrypt(message, key))

    elif choice == "2":
        ciphertext = input("Enter ciphertext to decrypt: ")
        key = valid_key()
        print("Decrypted message:", caesar_decrypt(ciphertext, key))

    elif choice == "3":
        ciphertext = input("Enter ciphertext to brute-force decrypt: ")
        brute_force(ciphertext)

    elif choice == "4":
        inp = input("Enter input file path: ")
        out = input("Enter output file path: ")
        key = valid_key()
        write_file(out, caesar_encrypt(read_file(inp), key))
        print("Saved to:", out)

    elif choice == "5":
        inp = input("Enter input file path: ")
        out = input("Enter output file path: ")
        key = valid_key()
        write_file(out, caesar_decrypt(read_file(inp), key))
        print("Saved to:", out)

    elif choice == "6":
        break

    else:
        print("Invalid choice. Please select a valid option.")
