import base64
import getpass
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from utils.utils import unique_key_filename, get_filenames, get_command_line_args

# Derive a key using Scrypt with the provided salt 
# and password, return salt and key as base64.
def derive_key(password):
    salt = os.urandom(16)    
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    derived_key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(salt), base64.urlsafe_b64encode(derived_key)

# Generate a Fernet key and save it to a file with 'FERNET' marker.
def gen_encryption_key(keyname):
    unique_keyname = unique_key_filename(keyname)
    key = Fernet.generate_key()    
    try:
        with open(f"keys/{unique_keyname}", "wb") as key_file:
            key_file.write(b"FERNET")
            key_file.write(key)
            print(f"Key created successfully and saved to 'keys/{unique_keyname}'.")
    except OSError as e:
        print(f"Error: Could not write to 'keys/{unique_keyname}'. {e}")

# Generate a password-based Scrypt key, save salt and keys to file 
# as byte strings in base64 with 'PWDKEY' marker.
def gen_password_based_encryption_key(keyname):
    print("Please create a password for your encryption key.")
    password = getpass.getpass("Password: ")
    salt_b64, key_b64 = derive_key(password)

    unique_keyname = unique_key_filename(keyname)
    try:
        with open(f"keys/{unique_keyname}", "wb") as key_file:
            key_file.write(b"PWDKEY")
            key_file.write(salt_b64 + b'\n')
            key_file.write(key_b64 + b'\n')
        print(f"Key created successfully and saved to 'keys/{unique_keyname}'.")
    except OSError as e:
        print(f"Error: Could not write to 'keys/{unique_keyname}'. {e}")


# Verify the password by matching the stored key.
def check_password(salt, key):
    password = getpass.getpass("Password: ")
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    try:
        kdf.verify(password.encode(), key)
        print("Password verified succesfully.")
        return True
    except Exception:
        print("Password verification failed.")
        return False
    

# Load Fernet instance from a key file based on its type (FERNET or PWDKEY).
def load_fernet_instance(stored_key):
    if not stored_key.endswith(".key"):
        stored_key += ".key"
    try:
        with open(f"keys/{stored_key}", "rb") as key_file:
            marker = key_file.read(6)
            
            if marker == b"PWDKEY":
                # For password-based keys, read salt and stored key
                salt_b64 = key_file.readline().strip()
                key_b64 = key_file.readline().strip()

                # Decode from base64 for password check
                salt = base64.urlsafe_b64decode(salt_b64)
                key = base64.urlsafe_b64decode(key_b64)
                
                if check_password(salt, key):
                    return Fernet(base64.urlsafe_b64encode(key))
                else:
                    print("Incorrect password")
                    return None

            elif marker == b"FERNET":
                # For direct Fernet keys
                key = key_file.read()
                return Fernet(key)
            else:
                print("File format not recognized.")
                return None

    except FileNotFoundError:
        print(f"Error: The key '{stored_key}' was not found.")
    except OSError as e:
        print(f"Error reading '{stored_key}': {e}")

# Take "action" – encrypt or decrypt a file using the specified key file
def crypt_keeper(action, stored_key, input_file, output_file=None):
    f = load_fernet_instance(stored_key)
    if f is None:
        print("Error: Failed to load encryption key.")
        return
    
    try:
        # Use helper to get filenames and metadata
        metadata, temp_path, final_path = get_filenames(action, input_file, output_file)

        if action == "encrypt":
            # Read original file content and encrypt with metadata
            with open(f"data/{input_file}", "rb") as file:
                plaintext = file.read()
            ciphertext = f.encrypt(metadata + plaintext)
            print("Data encrypted successfully.")

        elif action == "decrypt":
            input_file += ".enc" if not input_file.endswith(".enc") else ""

            # Read encrypted data and decrypt it
            with open(f"data/{input_file}", "rb") as file:
                encrypted_data = file.read()
            decrypted_data = f.decrypt(encrypted_data)
            print("Data decrypted successfully.")

            # Extract metadata for original extension
            metadata, plaintext = decrypted_data.split(b'|', 1)
            original_extension = metadata.decode().split("EXT:", 1)[-1]

            # Update final output filenames based on the original extension
            temp_path += f".{original_extension}"
            final_path += f".{original_extension}"

        # Write to the temporary file
        with open(temp_path, "wb") as file:
            file.write(ciphertext if action == "encrypt" else plaintext)
        print(f"Temporary file created: {temp_path}")

        # Remove the original file only after successful processing
        if output_file is None:
            os.remove(f"data/{input_file}")  # Delete the original file
        os.rename(temp_path, final_path)  # Rename temp file to final output file

        print(f"File saved as {final_path}")

    except FileNotFoundError as e:
        print(f"Error: '{e.filename}' not found.")
    except OSError as e:
        print(f"Error with file '{e.filename}': {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

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