import argparse
from cryptography.fernet import Fernet

# Define argument-based function mapping
def gen_encryption_key(key):
    # Define the logic for generating an encryption key
    pass

def gen_password_based_encryption_key(key):
    # Define the logic for generating a password-based encryption key
    pass

def encrypt_item(key, input_file, output_file):
    # Define the logic for encrypting the file
    pass

def decrypt_item(key, input_file, output_file):
    # Define the logic for decrypting the file
    pass

def get_command_line_args():
    parser = argparse.ArgumentParser(
        description="Welcome to the crypt... generating keys, encrypting/decrypting files.")
    
    parser.add_argument(
        "-g", "--generate", 
        help="generate encryption key", 
        action="store_true")
    parser.add_argument(
        "-p", "--password", 
        help="generate password based encryption key", 
        action="store_true")
    parser.add_argument(
        "-e", "--encrypt", 
        help="encrypt file", 
        action="store_true")
    parser.add_argument(
        "-d", "--decrypt", 
        help="decrypt file", 
        action="store_true")

    parser.add_argument(
        "keyname", 
        type=str, 
        help="Specify your key file name to generate or to use for encrypt/decrypt")
    parser.add_argument(
        "--input_file", 
        type=str, 
        help="File to be processed (required for encrypt/decrypt)")
    parser.add_argument(
        "--output_file", 
        type=str, 
        help="Output file for returned data (required for encrypt/decrypt)")

    args = parser.parse_args()
    return args, parser

def main():
    args, parser = get_command_line_args()
    
    arguments = {
    "generate": lambda: gen_encryption_key(args.keyname), 
    "password": lambda: gen_password_based_encryption_key(args.keyname), 
    "encrypt": lambda: (
        encrypt_item(args.keyname, args.input_file, args.output_file)
        if args.input_file and args.output_file
        else parser.error("--encrypt requires --input_file and --output_file")
        ),
    "decrypt": lambda: (
        decrypt_item(args.keyname, args.input_file, args.output_file)
        if args.input_file and args.output_file
        else parser.error("--decrypt requires --input_file and --output_file")
        )
    }
    
    for argument, function in arguments.items(): 
        if getattr(args, argument):
            function()

    """key = Fernet.generate_key() # creates a byte string that meets Fernet’s encryption requirements
    f = Fernet(key) # creates an instance of the Fernet class from the cryptography.fernet module. 
    
    token = f.encrypt(b"my deep dark secret")
    print(token)
    
    token = f.decrypt(token)
    print(token)"""


if __name__ == "__main__":
    main()