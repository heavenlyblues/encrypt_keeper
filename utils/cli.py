import argparse

COLOR, RESET = "\033[0;35m", "\033[0m"


# Parse command-line arguments for key generation, encryption, and decryption.
def get_command_line_args():
    parser = argparse.ArgumentParser(
        description=f"{COLOR}WELCOME TO THE CRYPT...{RESET}\n"
                    f"Encrypt, decrypt, and manage keys with optional password protection.",
        formatter_class=argparse.RawTextHelpFormatter  # This formatter preserves line breaks
    )
    parser.add_argument("-k", "--key", 
        help="Generate an encryption key", 
        action="store_true"
    )
    parser.add_argument("-s", "--secure_key", 
        help="Generate a password-based encryption key", 
        action="store_true"
    )
    parser.add_argument("-e", "--encrypt", 
        help="Encrypt a file using specified 'key_file'", 
        action="store_true"
    )
    parser.add_argument("-d", "--decrypt", 
        help="Decrypt a file using specified 'key_file'", 
        action="store_true"
    )
    parser.add_argument("key_file", type=str, 
        help=f"{COLOR}Your key filename (e.g., 'secure_key').\n{RESET}"
             "  For generating a new key, encrypting, decrypting.\n"
             "  No file extension needed."
    )
    parser.add_argument("input_file", nargs="?", type=str, 
        help=f"{COLOR}Specify input filename to encrypt/decrypt.\n{RESET}"
             "  File extension required for encryption (e.g., 'file.ext')."
    )
    parser.add_argument("output_file", nargs="?", type=str, 
        help=f"{COLOR}Optional output filename to save separately.\n{RESET}"
             "  If omitted, will encrypt/decrypt in place.\n"    
             "  Encrypt by default adds '.enc' file extension.\n"
    )

    args = parser.parse_args()
    
    if not (args.key or args.secure_key or args.encrypt or args.decrypt):
        parser.error("At least one action is required: "
                     "--key, --secure_key, --encrypt, or --decrypt.")

    if (args.encrypt or args.decrypt) and not args.input_file:
        parser.error("Encrypt and decrypt require an input file.")

    return args