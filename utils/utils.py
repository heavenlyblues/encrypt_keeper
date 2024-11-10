import argparse
import os
import time

COLOR, RESET = "\033[0;35m", "\033[0m"


# Helper function to check and set a unique filename
# Add .key extension if missing and ensure the directory exists
def unique_key_filename(keyname):
    if not keyname.endswith(".key"):
        keyname += ".key"
    
    os.makedirs("keys", exist_ok=True)

    while os.path.exists(f"./keys/{keyname}"):
        keyname = input("File already exists. Enter a new file name: ")
        if not keyname.endswith(".key"):
            keyname += ".key"
            
    return keyname


def get_filenames(action, input_file, output_file=None):
    # Handle encryption
    if action == "encrypt":
        # For encryption: check if the file has an extension and set metadata accordingly
        if "." in input_file:
            original_extension = input_file.rsplit(".", 1)[-1]
            base_name = input_file.rsplit(".", 1)[0]
        else:
            original_extension = ""  # No extension
            base_name = input_file

        metadata = f"EXT:{original_extension}|".encode()
        temp_path = f"./data/{base_name}_temp_{int(time.time())}.enc"
        final_path = f"./data/{base_name}.enc" if output_file is None else f"./data/{output_file}.enc"

    # Handle decryption
    elif action == "decrypt":
            input_file += ".enc" if not input_file.endswith(".enc") else ""
        
            # Temporary file for decryption
            base_name = input_file.rsplit(".", 1)[0]
            temp_path = f"./data/{base_name}_temp_{int(time.time())}"  # Extension will be updated after reading metadata
            
            # Set final output file based on provided or detected extension
            final_path = f"./data/{base_name}" if output_file is None else f"./data/{output_file}"
            metadata = None  # Metadata read on file open in crypt_keeper
    
    else:
        raise ValueError("Invalid action or file extension.")

    return metadata, temp_path, final_path


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