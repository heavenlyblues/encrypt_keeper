import argparse
import base64
import getpass
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Helper function to check and set a unique filename
def unique_filename(filename):
    while os.path.exists(filename):
        filename = input("File already exists. Enter a new file name: ")
    return filename

# Generate a Fernet key and save it to a file with 'FERNET' marker.
def gen_encryption_key(keyname):
    keyname = unique_filename(keyname)
    key = Fernet.generate_key()    
    try:
        with open(keyname, "wb") as file:
            file.write(b"FERNET")
            file.write(key)
            print(f"Key created successfully and saved to '{keyname}'.")
    except OSError as e:
        print(f"Error: Could not write to '{keyname}'. {e}")

# Generate a password-based Scrypt key, save salt and keys to file 
# as byte strings in base64 with 'PWDKEY' marker.
def gen_password_based_encryption_key(keyname):
    print("Please create a password for your encryption key.")
    password = getpass.getpass("Password: ")
    salt = os.urandom(16)
    salt_b64, key_b64 = derive_key(salt, password)

    keyname = unique_filename(keyname)
    try:
        with open(keyname, "wb") as file:
            file.write(b"PWDKEY")
            file.write(salt_b64 + b'\n')
            file.write(key_b64 + b'\n')
        print("Key file saved successfully.")
    except OSError as e:
        print(f"Error: Could not write to '{keyname}'. {e}")

# Derive a key using Scrypt with the provided salt 
# and password, return salt and key as base64.
def derive_key(salt, password):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    derived_key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(salt), base64.urlsafe_b64encode(derived_key)

# Verify the password by matching the stored key.
def check_password(salt, stored_key):
    password = getpass.getpass("Password: ")
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    try:
        kdf.verify(password.encode(), stored_key)
        print("Password verified succesfully.")
        return True
    except Exception:
        print("Password verification failed.")
        return False
    

# Load Fernet instance from a key file based on its type (FERNET or PWDKEY).
def load_fernet_instance(keyname):
    try:
        with open(keyname, "rb") as key_file:
            marker = key_file.read(6)
            
            if marker == b"PWDKEY":
                # For password-based keys, read salt and stored key
                salt_b64 = key_file.readline().strip()
                stored_key_b64 = key_file.readline().strip()

                # Decode from base64 for password check
                salt = base64.urlsafe_b64decode(salt_b64)
                stored_key = base64.urlsafe_b64decode(stored_key_b64)
                
                if check_password(salt, stored_key):
                    return Fernet(base64.urlsafe_b64encode(stored_key))
                else:
                    print("Incorrect password")
                    return None

            elif marker == b"FERNET":
                # For direct Fernet keys
                stored_key = key_file.read()
                return Fernet(stored_key)
            else:
                print("File format not recognized.")
                return None

    except FileNotFoundError:
        print(f"Error: The key '{keyname}' was not found.")
    except OSError as e:
        print(f"Error reading '{keyname}': {e}")

# Take "action" – encrypt or decrypt a file using the specified key file
def crypt_keeper(action, keyname, *args):
    input_file = args[0]
    output_file = args[1] if args[1] is not None else input_file 

    f = load_fernet_instance(keyname)
    if f is None:
        print("Error: Failed to load encryption key.")
        return
    
    try:
        with open(input_file, "rb") as file:
            data = file.read()

        token = f.encrypt(data) if action == "encrypt" else f.decrypt(data)
        print(f"Data {action}ed successfully...")
        
        with open(output_file, "wb") as file:
            file.write(token)
        print(f"File saved as {output_file}.")

    except FileNotFoundError as e:
        print(f"Error: '{e.filename}' not found.")
    except OSError as e:
        print(f"Error with file '{e.filename}': {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

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

def main():
    args = get_command_line_args()
    
    # Dictionary with 'keys' as tuples and 'values' as lambda functions
    commands = {
        "key": lambda: gen_encryption_key(args.key_file),
        "secure_key": lambda: gen_password_based_encryption_key(args.key_file),
        "encrypt": lambda: crypt_keeper("encrypt", args.key_file, args.input_file, args.output_file),
        "decrypt": lambda: crypt_keeper("decrypt", args.key_file, args.input_file, args.output_file)
    }
    
    # Iterate over actions and execute the first matching condition
    for key, command in commands.items():
        if getattr(args, key):
            command()
            break

if __name__ == "__main__":
    main()