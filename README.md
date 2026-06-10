# AES Encryption Project

A pure Java implementation of the **Advanced Encryption Standard (AES)** built from scratch — no external cryptography libraries. Supports AES-128 and AES-192 key sizes with ECB, CBC, and CFB block cipher modes, featuring an interactive console interface and a step-by-step visualization mode for learning the internals of AES.

---

## Features

- **AES-128 and AES-192** key schedule and block cipher implemented by hand
- **Three cipher modes:** ECB, CBC, CFB
- **Key input options:** HEX string, UTF-8 text, random generation, or file
- **IV management:** manual HEX input or random generation (for CBC/CFB)
- **Flexible I/O:** plaintext or HEX input from the console or a file; output to console or file
- **Round key expansion viewer** — inspect all derived round keys
- **Verbose visualization mode** — prints the full AES state matrix after every operation (SubBytes, ShiftRows, MixColumns, AddRoundKey) for each round, great for learning and debugging

---

## Project Structure

```
AESproject/
├── src/
│   ├── module-info.java
│   └── pckg/
│       ├── AesCipher.java      # Core AES block cipher (key expansion, encrypt/decrypt block)
│       ├── CryptoModes.java    # ECB, CBC, CFB modes + utilities (padding, hex, XOR)
│       └── Main.java           # Interactive console menu
└── bin/                        # Compiled .class files
```

---

## Getting Started

### Prerequisites

- Java 11 or higher (uses `module-info.java` and text blocks)

### Compile

```bash
javac -d bin src/module-info.java src/pckg/*.java
```

### Run

```bash
java -cp bin pckg.Main
```

---

## Usage

When you run the program, an interactive menu is displayed:

```
================ AES Project =================
AES Key Size  : 128
Mode          : ECB
Visualization : OFF
Key is set    : false
=============================================

1) Choose AES Key Size (128 / 192)
2) Set Key (HEX / TEXT) or Generate Random
3) Expand Key and Display Round Keys
4) Choose Mode (ECB / CBC / CFB)
5) Set IV (HEX) or Generate Random (CBC/CFB only)
6) Encrypt (input TEXT or HEX)  -> output HEX
7) Decrypt (input HEX)          -> output TEXT or HEX
8) Exit
9) Toggle Visualization Mode
```

### Quick Example

1. Choose key size: `1` → `128`
2. Set key: `2` → option `3` (generate random) — note the printed HEX key
3. Encrypt: `6` → input `1` (TEXT) → type `Hello World`
4. Copy the output HEX ciphertext
5. Decrypt: `7` → input `1` (HEX) → paste ciphertext → output as TEXT

### Visualization Mode

Toggle option `9` to enable verbose output. With visualization ON, encrypting a block will print the 4×4 AES state matrix at every intermediate step:

```
>>> START ENCRYPT BLOCK <<<
   [ Input State ]
     32 88 31 E0
     ...

--- Round 1 ---
   [ After SubBytes ]
     ...
   [ After ShiftRows ]
     ...
```

This is useful for understanding or verifying the AES algorithm step by step.

---

## Implementation Notes

- **Key expansion** follows the AES-192 schedule (Nk=6, 13 round keys). AES-128 uses 10 rounds over the same expanded key array.
- **Padding** uses zero-padding to the nearest 16-byte boundary. Note: this means plaintexts that naturally end with null bytes may be trimmed on decryption.
- **CFB mode** is implemented in 16-byte (128-bit) segment size.
- The S-Box, inverse S-Box, and RCON constants are hardcoded as lookup tables per the AES specification.

---

## Cipher Modes

| Mode | IV Required | Notes |
|------|------------|-------|
| ECB  | No         | Each block encrypted independently. Not recommended for most use cases. |
| CBC  | Yes        | Each plaintext block is XORed with the previous ciphertext block before encryption. |
| CFB  | Yes        | Turns AES into a stream cipher; no padding needed. |

---

## License

This project is for educational purposes.
