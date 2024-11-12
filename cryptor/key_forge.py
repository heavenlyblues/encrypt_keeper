import base64
import getpass
import os
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptor.base_cipher import BaseCipher


class KeyForge(BaseCipher):
    def __init__(self, key_name):
        self.key_name = key_name
        self.final_key_path = None
        self.key = None
        self.salt = None


    def _unique_key_filename(self):
        # Ensure the filename has a ".key" extension
        filename = f"{self.key_name}.key" if not self.key_name.endswith(".key") else self.key_name

        unique_keypath = Path("keys") / filename
        unique_keypath.parent.mkdir(parents=True, exist_ok=True)

        while unique_keypath.exists():
            new_name = input("Key filename already exists. Enter a new file name: ")
            filename = f"{new_name}.key" if not new_name.endswith(".key") else new_name
            unique_keypath = unique_keypath.with_name(filename)

        self.final_key_path = unique_keypath
                

    # Generate a Fernet key and save it to a file with 'FERNET' marker.
    def forge_key(self):
        self._unique_key_filename()
        derived_key = Fernet.generate_key()    
        try:
            with open(self.final_key_path, "wb") as file:
                file.write(b"FERNET")
                file.write(derived_key)
                print(f"Key created successfully and saved to '{self.final_key_path}'.")
        except OSError as e:
            print(f"Error: Could not write to '{self.final_key_path}'. {e}")


    # Generate a password-based Scrypt key, save salt and keys to file 
    # as byte strings in base64 with 'PWDKEY' marker.
    def forge_secure_key(self):
        self._unique_key_filename()

        print("Please create a password for your encryption key.")
        password = getpass.getpass("Password: ")
        
        scrypt_kdf = self._scrypt_creator()
        derived_key = scrypt_kdf.derive(password.encode())
        salt_b64 = base64.urlsafe_b64encode(self.salt)
        key_b64 = base64.urlsafe_b64encode(derived_key)

        try:
            with open(self.final_key_path, "wb") as file:
                file.write(b"PWDKEY")
                file.write(salt_b64 + b'\n')
                file.write(key_b64 + b'\n')
            print(f"Key created successfully and saved to '{self.final_key_path}'.")
        except OSError as e:
            print(f"Error: Could not write to '{self.final_key_path}'. {e}")


    # Instance method using class constants creates and instance of 
    # the Scrypt key derivation function for the password based key
    def _scrypt_creator(self):
        self.salt = os.urandom(self.SALT_SIZE)
        scrypt_kdf = Scrypt(
            salt=self.salt,
            length=self.SCRYPT_LENGTH,
            n=self.SCRYPT_N,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P,
        )
        return scrypt_kdf
    

# Potential "high security" subclass for later development
class HighSecurityKeyForge(KeyForge):
    SCRYPT_N = 2**18  # Higher CPU/memory cost for enhanced security
    SCRYPT_R = 16     # Increased block size for higher security