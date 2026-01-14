import string
from pathlib import Path
import json
import os
from typing import Optional, Dict, Any, Iterator

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
# JSONL = "JSON Lines": one JSON object per line.
# This format is ideal for append-only logs because you can add new
# records without rewriting the entire file.
LOG_PATH = "cipher_log.jsonl"


# -------------------------------------------------------------------
# Input helpers
# -------------------------------------------------------------------
def valid_key() -> int:
    """
    Prompt the user until they enter a valid Caesar shift key (1-25).
    Returns:
        int: a valid key value between 1 and 25 (inclusive)
    """
    while True:
        try:
            key = int(input("Enter shift value (1-25): "))
            if 1 <= key <= 25:
                return key
            print("Key must be between 1 and 25.")
        except ValueError:
            print("Invalid input. Please enter an integer between 1 and 25.")


# -------------------------------------------------------------------
# Cipher construction
# -------------------------------------------------------------------
def make_cipher(key: int):
    """
    Build a translation table for Caesar shifting.

    We create a mapping for:
      - lowercase letters a-z
      - uppercase letters A-Z

    str.maketrans() returns a translation table usable by .translate().
    """
    shift = key % 26

    # Lowercase mapping: abc... -> shifted version
    lower_src = string.ascii_lowercase
    lower_dst = lower_src[shift:] + lower_src[:shift]

    # Uppercase mapping: ABC... -> shifted version
    upper_src = string.ascii_uppercase
    upper_dst = upper_src[shift:] + upper_src[:shift]

    # Combine both mappings into one translation table
    return str.maketrans(lower_src + upper_src, lower_dst + upper_dst)


# -------------------------------------------------------------------
# Dedupe helpers
# -------------------------------------------------------------------
def dedupe_key(cipher_message: str) -> str:
    """
    Normalize a ciphertext for deduplication:
      - collapse internal whitespace
      - trim leading/trailing whitespace
      - case-insensitive comparison (casefold is stronger than lower)

    This ensures that:
      "LIPPS   ASVPH" and "lipps asvph" are treated as the same message.
    """
    return " ".join(cipher_message.split()).casefold()


# -------------------------------------------------------------------
# JSONL helpers
# -------------------------------------------------------------------
def iter_jsonl(file_path: str) -> Iterator[Dict[str, Any]]:
    """
    Iterate over a JSONL file safely.
    - Skips blank lines
    - Skips malformed/corrupted JSON lines
    - Yields dictionaries only
    """
    if not os.path.exists(file_path):
        return

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # If the log file ever gets a bad line, we don't crash
                continue

            if isinstance(obj, dict):
                yield obj


def get_next_id(file_path: str) -> int:
    """
    Compute the next record ID by scanning for the maximum existing 'id'.
    This is more reliable than assuming the last line has the highest id.
    """
    max_id = 0

    for record in iter_jsonl(file_path):
        rid = record.get("id")
        if isinstance(rid, int) and rid > max_id:
            max_id = rid

    return max_id + 1


def get_record_by_id(file_path: str, record_id: int) -> Optional[Dict[str, Any]]:
    """
    Look up a record by its numeric ID inside the JSONL log.
    Returns:
        dict if found, otherwise None
    """
    for record in iter_jsonl(file_path):
        if record.get("id") == record_id:
            # Basic shape check
            if "cipher_message" in record:
                return record
            return None
    return None


# -------------------------------------------------------------------
# Core crypto operations
# -------------------------------------------------------------------
def caesar_encrypt(message: str, key: int) -> str:
    """
    Encrypt the message using a Caesar cipher and log the result.

    Logging behavior:
      - Each encryption is appended as a single JSON object in LOG_PATH
      - We prevent duplicates by checking:
            (normalized_cipher_message, key)
    """
    # Encrypt using the translation table
    encrypted = message.translate(make_cipher(key))
    file_path = LOG_PATH

    # Build a set of signatures from existing log records so we can avoid duplicates
    # Signature chosen: (normalized_ciphertext, key)
    seen = set()

    for record in iter_jsonl(file_path):
        cm = record.get("cipher_message", "")
        rk = record.get("key")

        # Only accept keys that are integers for a valid signature
        if isinstance(rk, int):
            seen.add((dedupe_key(str(cm)), rk))

    # If this exact encryption already exists (case-insensitive ciphertext + same key),
    # return the ciphertext and do NOT write a duplicate record.
    if (dedupe_key(encrypted), key) in seen:
        return encrypted

    # Assign the next unique ID
    new_id = get_next_id(file_path)

    # Append to JSONL log
    with open(file_path, "a", encoding="utf-8") as f:
        json.dump(
            {"id": new_id, "cipher_message": encrypted, "key": key},
            f,
            ensure_ascii=False
        )
        f.write("\n")

    return encrypted


def caesar_decrypt(ciphertext: str, key: int) -> str:
    """
    Decrypt a Caesar ciphertext by applying the negative shift.
    """
    return ciphertext.translate(make_cipher(-key))


def brute_force(ciphertext: str):
    """
    Try all possible Caesar keys (1-25) and print the results.
    """
    for key in range(1, 26):
        print(f"Key {key:2}: {caesar_decrypt(ciphertext, key)}")


# -------------------------------------------------------------------
# File I/O helpers
# -------------------------------------------------------------------
def read_file(path: str) -> str:
    """
    Read a text file and return its contents.
    Raises FileNotFoundError if the file doesn't exist.
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    return p.read_text(encoding="utf-8")


def write_file(path: str, text: str, overwrite: bool = False):
    """
    Write text to a file.
    By default, prevents accidental overwrites unless overwrite=True.
    """
    p = Path(path)
    if p.exists() and not overwrite:
        raise FileExistsError(f"Output file already exists: {path}")
    p.write_text(text, encoding="utf-8")


# -------------------------------------------------------------------
# CLI menu
# -------------------------------------------------------------------
def menu():
    """
    Display the CLI options.
    """
    print("\nMenu:")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Brute-force decrypt from log ID")
    print("4. Encrypt a file")
    print("5. Decrypt a file")
    print("6. Exit")


def main():
    """
    Main program loop:
    - show menu
    - handle user selection
    - repeat until exit
    """
    while True:
        menu()
        choice = input("Choose an option (1-6): ").strip()

        # 1) Encrypt a message typed by the user
        if choice == "1":
            message = input("Enter message to encrypt: ")
            key = valid_key()
            print("Encrypted message:", caesar_encrypt(message, key))

        # 2) Decrypt a ciphertext typed by the user
        elif choice == "2":
            ciphertext = input("Enter ciphertext to decrypt: ")
            key = valid_key()
            print("Decrypted message:", caesar_decrypt(ciphertext, key))

        # 3) Brute-force decrypt using an ID from the JSONL log
        elif choice == "3":
            try:
                record_id = int(input("Enter log ID to brute-force decrypt: ").strip())
            except ValueError:
                print("Invalid ID. Please enter a number.")
                continue

            record = get_record_by_id(LOG_PATH, record_id)
            if record is None:
                print(f"No record found with id {record_id}.")
                continue

            ciphertext = record.get("cipher_message", "")
            if not ciphertext:
                print(f"Record {record_id} has no cipher_message.")
                continue

            print(f"Brute-forcing log id {record_id} (stored key: {record.get('key')}): {ciphertext}")
            brute_force(ciphertext)

        # 4) Encrypt a text file and write the encrypted output to another file
        elif choice == "4":
            inp = input("Enter input file path: ")
            out = input("Enter output file path: ")
            key = valid_key()
            try:
                plaintext = read_file(inp)
                encrypted = caesar_encrypt(plaintext, key)
                write_file(out, encrypted, overwrite=False)
                print("Saved to:", out)
            except (FileNotFoundError, FileExistsError, UnicodeDecodeError) as e:
                print(e)

        # 5) Decrypt a text file and write the decrypted output to another file
        elif choice == "5":
            inp = input("Enter input file path: ")
            out = input("Enter output file path: ")
            key = valid_key()
            try:
                ciphertext = read_file(inp)
                decrypted = caesar_decrypt(ciphertext, key)
                write_file(out, decrypted, overwrite=False)
                print("Saved to:", out)
            except (FileNotFoundError, FileExistsError, UnicodeDecodeError) as e:
                print(e)

        # 6) Exit the program
        elif choice == "6":
            break

        else:
            print("Invalid choice. Please select a valid option.")


# -------------------------------------------------------------------
# Entry point
# -------------------------------------------------------------------
if __name__ == "__main__":
    # Catch Ctrl+C so the program exits cleanly without a stack trace.
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
