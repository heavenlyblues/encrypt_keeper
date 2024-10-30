import argparse
from cryptography.fernet import Fernet

def gen_encryption_key(keyname):
    key = Fernet.generate_key()    
    try:
        with open(keyname, "wb") as file:
            file.write(key)
            print("Key created successfully.")
    except PermissionError:
        print(f"Error: Permission denied when trying to write to '{keyname}'. Try a different location.")
    except IOError as e:
        print(f"An unexpected I/O error occurred: {e}")

def gen_password_based_encryption_key(keyname):
    # Define the logic for generating a password-based encryption key
    pass

def crypt_keeper(action, keyname, input_file, output_file):
    try:
        with open(keyname, "rb") as key_file:
            key = key_file.read()
        f = Fernet(key) # creates an instance of the Fernet class from the cryptography.fernet module. 

        with open(input_file, "rb") as file:
            data = file.read()

        if action == "encrypt":
            token = f.encrypt(data)
            print("File encrypted successfully.")
        elif action == "decrypt":
            token = f.decrypt(data)
            print("File decrypted successfully.")
        else:
            raise ValueError("Invalid action. Use 'encrypt' or 'decrypt'.")
        
        with open(output_file, "wb") as file:
            file.write(token)

    except FileNotFoundError as e:
        print(f"Error: The file '{e.filename}' was not found. Please check the path and try again.")
    except PermissionError as e:
        print(f"Error: Permission denied when trying to access '{e.filename}'. Try a different location or check permissions.")
    except IOError as e:
        print(f"An unexpected I/O error occurred: {e}")
    except ValueError as e:
        print(e)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def get_command_line_args():
    parser = argparse.ArgumentParser(
        description="Generate keys, encrypt, and decrypt files. WELCOME TO THE CRYPT... ")
    
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
        "input_file", 
        nargs="?",
        type=str, 
        help="File to be processed (required for encrypt/decrypt)")
    parser.add_argument(
        "output_file", 
        nargs="?",
        type=str, 
        help="Output file for returned data (required for encrypt/decrypt)")

    args = parser.parse_args()

    if args.encrypt or args.decrypt:
            if not args.input_file or not args.output_file:
                parser.error("Encrypt and decrypt require both input_file and output_file")

    return args


def main():
    args = get_command_line_args()
    
    arguments = {
    "generate": lambda: gen_encryption_key(args.keyname), 
    "password": lambda: gen_password_based_encryption_key(args.keyname), 
    "encrypt": lambda: crypt_keeper("encrypt", args.keyname, args.input_file, args.output_file),
    "decrypt": lambda: crypt_keeper("decrypt", args.keyname, args.input_file, args.output_file)
    }
    
    for arg_name, function in arguments.items(): 
        if getattr(args, arg_name):
            function()


if __name__ == "__main__":
    main()