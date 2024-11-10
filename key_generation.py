import base64
import getpass
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from utils.utils import unique_key_filename


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