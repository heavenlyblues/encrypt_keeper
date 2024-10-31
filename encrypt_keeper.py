import argparse
import base64
import os
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def gen_encryption_key(keyname):
    key = Fernet.generate_key()    
    while os.path.exists(keyname):
        keyname = input("File already exists. Enter a new file name: ")
    try:
        with open(keyname, "wb") as file:
            file.write(b"FERNET")
            file.write(key)
            print(f"Key created successfully and saved to '{keyname}'.")
    except PermissionError:
        print(f"Error: Permission denied when trying to write to '{keyname}'. Try a different location.")
    except IOError as e:
        print(f"An unexpected I/O error occurred: {e}")


def gen_password_based_encryption_key(keyname):
    print("Please create a password for your encryption key.")

    password = getpass.getpass("Password: ")
    salt = os.urandom(16)
    salt_b64, key_b64 = derive_key(salt, password)

    while os.path.exists(keyname):
        keyname = input("File already exists. Enter a new file name: ")

    try:
        with open(keyname, "wb") as file:
            file.write(b"PWDKEY")
            file.write(salt_b64 + b'\n')
            file.write(key_b64 + b'\n')
        print("Password hash saved successfully.")
    except PermissionError:
        print(f"Error: Permission denied when trying to write to '{keyname}'.")
    except IOError as e:
        print(f"An unexpected I/O error occurred: {e}")
    return 0


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


def check_password(salt, stored_key, password):
    # Checks user inputted password to enable use of password-based encryption/decryption
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
        print("Password verification failed in check_password.")
        return False
    

def load_fernet_instance(keyname):
    try:
        with open(keyname, "rb") as key_file:
            marker = key_file.read(6)
            
            if marker == b"PWDKEY":
                salt_b64 = key_file.readline().strip()
                stored_key_b64 = key_file.readline().strip()
                print(f"Salt (base64): {salt_b64}") # Debugging prints
                print(f"Stored Key (base64): {stored_key_b64}") # Debugging prints

                salt = base64.urlsafe_b64decode(salt_b64)
                stored_key = base64.urlsafe_b64decode(stored_key_b64)
                
                password = getpass.getpass("Password: ")
                if check_password(salt, stored_key, password):
                    return Fernet(base64.urlsafe_b64encode(stored_key))
                else:
                    print("Incorrect password")

            elif marker == b"FERNET":
                stored_key = key_file.read()
                print(f"Direct Fernet Key: {stored_key}")
                return Fernet(stored_key)
            else:
                print("File not recognized.")

    except FileNotFoundError as e:
        print(f"Error: The key '{e.filename}' was not found. Please check the path and try again.")


def crypt_keeper(action, keyname, input_file, output_file):
    f = load_fernet_instance(keyname)
    if f is None:
        print("Error: Failed to load encryption key. Please check the key file and password.")
        return
    
    try:
        with open(input_file, "rb") as file:
            data = file.read()

        if action == "encrypt": 
            token = f.encrypt(data)
        elif action == "decrypt":
            token = f.decrypt(data)
        else:
            raise ValueError("Invalid action. Use 'encrypt' or 'decrypt'.")
        
        print(f"File {action}ed successfully.")

        with open(output_file, "wb") as file:
            file.write(token)
        print(f"File saved {action}ed as {output_file}.")

    except FileNotFoundError as e:
        print(f"Error: The file '{e.filename}' was not found. Please check the path and try again.")
    except PermissionError as e:
        print(f"Error: Permission denied when trying to access '{e.filename}'. Try a different location or check permissions.")
    except IOError as e:
        print(f"An unexpected I/O error occurred: {e}")
    except ValueError as e:
        print(f"Invalid value provided: {e}")  # More specific message for ValueError
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