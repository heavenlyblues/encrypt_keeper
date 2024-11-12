
# Encrypt Keeper

**Encrypt Keeper** is a symmetric+key encryption and decryption tool designed to securely manage files and keys. The tool offers both basic encryption using a randomly generated key and password-based encryption using Scrypt for added security. Encrypt Keeper is built using Python and leverages the `cryptography` library, making it suitable for secure file handling with easy-to-use command-line options.

## Features

- **Key Generation**: Generate and save encryption keys with or without password protection.
- **Password-Based Key Derivation**: Generate a key using Scrypt, a memory-hard key derivation function.
- **File Encryption and Decryption**: Encrypt and decrypt files using the Fernet encryption algorithm.
- **Secure Key Storage**: Save keys securely in a specified directory with optional password protection.

## Installation

### Prerequisites

- Python 3.6 or newer
- The following Python packages (install via `pip` if not already installed):

```bash
pip install cryptography argon2-cffi
```

### Directory Setup

Ensure the following directories are set up in the project root:

- `keys`: Used to store generated encryption keys.
- `data`: Used to store files to be encrypted or decrypted.

## Usage

Encrypt Keeper provides various commands for key management, encryption, and decryption, accessible through command-line arguments.

### Command-Line Arguments

```plaintext
usage: Encrypt Keeper [-h] [-k] [-s] [-e] [-d] key_file [input_file] [output_file]

WELCOME TO THE CRYPT... Encrypt, decrypt, and manage keys with optional password protection.

positional arguments:
  key_file             Specify your key file name
  input_file           File to be processed. Required for encrypting or decrypting.
  output_file          Specify output file name. If omitted, input file will be overwritten.

optional arguments:
  -h, --help           Show this help message and exit
  -k, --key            Generate an encryption key.
  -s, --secure_key     Generate a password-based encryption key.
  -e, --encrypt        Encrypt a file using the specified key.
  -d, --decrypt        Decrypt a file using the specified key.
```

### Examples

#### 1. Generate a Random Encryption Key

Generate a random Fernet encryption key and save it to the `keys` directory.

```bash
python main.py -k my_encryption_key
```

#### 2. Generate a Password-Based Encryption Key

Generate a password-based key using Scrypt, a memory-hard key derivation function.

```bash
python main.py -s my_password_key
```

You’ll be prompted to create a password, which will be used to derive the encryption key.

#### 3. Encrypt a File

Encrypt a file using an existing key file.

```bash
python main.py -e my_encryption_key example.txt example.enc
```

If `output_file` (here, `encrypted_example.enc`) is omitted, the input file (`example.txt`) will be overwritten with the encrypted content.

#### 4. Decrypt a File

Decrypt a file using the specified key file.

```bash
python main.py -d my_encryption_key example.enc example.txt
```

If `output_file` (here, `example.txt`) is omitted, the encrypted file (`example.enc`) will be overwritten with the decrypted content and vice-versa for encryption and decryption in place.