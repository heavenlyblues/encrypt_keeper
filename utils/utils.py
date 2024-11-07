import argparse
import os

# Helper function to check and set a unique filename
# Add .key extension if missing and ensure the directory exists
def unique_filename(keyname):
    if not keyname.endswith(".key"):
        keyname += ".key"
    
    os.makedirs("keys", exist_ok=True)

    while os.path.exists(f"./keys/{keyname}"):
        keyname = input("File already exists. Enter a new file name: ")
        if not keyname.endswith(".key"):
            keyname += ".key"
            
    return keyname

# Parse command-line arguments for key generation, encryption, and decryption.
def get_command_line_args():
    parser = argparse.ArgumentParser(
        description="WELCOME TO THE CRYPT..."
        "Encrypt, decrypt, and manage keys with optional password protection."
    )
    parser.add_argument(
        "-k", "--key", 
        help="Generate an encryption key.", 
        action="store_true"
    )
    parser.add_argument(
        "-s", "--secure_key", 
        help="Generate a password-based encryption key.", 
        action="store_true"
    )
    parser.add_argument(
        "-e", "--encrypt", 
        help="Encrypt a file using the specified key.", 
        action="store_true"
    )
    parser.add_argument(
        "-d", "--decrypt", 
        help="Decrypt a file using the specified key.", 
        action="store_true"
    )
    parser.add_argument(
        "key_file", 
        type=str, 
        help="Specify your key file name"
    )
    parser.add_argument(
        "input_file", 
        nargs="?", 
        type=str, 
        help="File to be processed. Required for encrypting or decrypting."
    )
    parser.add_argument(
        "output_file", 
        nargs="?", 
        type=str, 
        help="Specify output file name. If omitted, input file will be overwritten."
    )

    args = parser.parse_args()
    
    if not (args.key or args.secure_key or args.encrypt or args.decrypt):
        parser.error("At least one action is required: --key, --encrypt, or --decrypt.")

    if (args.encrypt or args.decrypt) and not args.input_file:
        parser.error("Encrypt and decrypt require an input file.")

    return args