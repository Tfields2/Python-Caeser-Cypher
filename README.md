# Caesar Cipher Encryption Tool (Python)

This project implements a Caesar cipher utility in Python with an emphasis on **secure design, data integrity, and usability** rather than just encryption logic.

The application supports encrypting and decrypting messages and files, brute-forcing ciphertext, and maintaining an append-only **JSONL encryption log** with unique IDs. Each encryption event is recorded with safeguards to prevent duplicate entries, enabling log-driven workflows such as retrieving and brute-forcing ciphertext by ID.

### Key Features
- Caesar cipher encryption and decryption (upper- and lowercase safe)
- Interactive CLI menu for ease of use
- Append-only JSONL logging with unique, monotonic IDs
- Case-insensitive and whitespace-normalized deduplication
- Brute-force decryption by log entry ID
- Safe file encryption and decryption
- Defensive file I/O and input validation
- Fault-tolerant JSONL parsing (skips corrupted log entries)

### Why This Project
Rather than focusing solely on cryptography, this project demonstrates **how security tools are designed in practice**:
- Logging instead of transient output
- Defensive parsing and input handling
- Workflow design using persisted artifacts
- Explicit tradeoffs between usability and security

The code is heavily documented to emphasize clarity, maintainability, and real-world software design principles.

### Technologies Used
- Python 3
- JSON Lines (JSONL) logging
- Standard library only (no third-party dependencies)

---

📌 **Portfolio Note**  
This project is intentionally terminal-based to highlight encryption logic, logging workflows, and defensive programming rather than UI complexity. The same architecture could be adapted to a backend service, REST API, or security training tool.
