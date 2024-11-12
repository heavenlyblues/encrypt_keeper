import base64
import getpass
from pathlib import Path
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from utils.file_utils import get_filenames, rename_with_prompt
from cryptor.base_cipher import BaseCipher


class CryptKeeper(BaseCipher):
    def __init__(self, key_name, input_file, output_file=None):
        self.key_name = key_name
        self.input_file = input_file
        self.output_file = output_file
        self.mode = None


    def _save_to_file(self, temp_path, data_to_write, final_path):
        # Write to the temporary file
        with temp_path.open(mode="wb") as file:
            file.write(data_to_write)
        print(f"Temporary file created: {temp_path}")

        if self.output_file is None: # Encrypt/decrypt in place
            input_path = Path("data") / self.input_file
            input_path.unlink()  # This removes the file at input_path
        rename_with_prompt(temp_path, final_path)


    # Load Fernet instance from a key file based on its type (FERNET or PWDKEY).
    def get_fernet_cipher(self):
        filename = f"{self.key_name}.key" if not self.key_name.endswith(".key") else self.key_name
        keypath = Path("keys") / filename

        try:
            with open(keypath, "rb") as key_file:
                marker = key_file.read(6)
                
                if marker == b"PWDKEY":
                    # For password-based keys, read salt and stored key
                    stored_salt_b64 = key_file.readline().strip()
                    stored_key_b64 = key_file.readline().strip()
                    salt = base64.urlsafe_b64decode(stored_salt_b64)
                    key = base64.urlsafe_b64decode(stored_key_b64)
                    
                    if self.check_password(salt, key):
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
            print(f"Error: The key '{keypath}' was not found.")
        except OSError as e:
            print(f"Error reading '{keypath}': {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")


    # Take "action" – encrypt or decrypt a file using the specified key file
    def crypt_keeper(self, mode):
        self.mode = mode

        fernet_cipher = self.get_fernet_cipher()
        if fernet_cipher is None:
            print("Error: Failed to load encryption key.")

        try:
            # Use helper to get filenames and metadata
            metadata, temp_path, final_path = get_filenames(self.mode, self.input_file, self.output_file)
            file_to_process = Path ("data") / self.input_file

            if self.mode == "encrypt":
                # Read original file content and encrypt with metadata
                with file_to_process.open(mode="rb") as file:
                    plaintext = file.read()
                ciphertext = fernet_cipher.encrypt(metadata + plaintext)
                print("Data encrypted successfully.")
                data_to_write = ciphertext

            elif self.mode == "decrypt":
                # Read encrypted data and decrypt and extract metadata
                with file_to_process.open(mode="rb") as file:
                    encrypted_data = file.read()
                decrypted_data = fernet_cipher.decrypt(encrypted_data)
                print("Data decrypted successfully.")

                # Extract metadata for original extension
                metadata, plaintext = decrypted_data.split(b'|', 1)
                original_extension = metadata.decode().split("EXT:", 1)[-1]

                # Determine final output path for decryption
                if self.output_file:  # If user provided a custom output file
                    temp_path = Path("data") / f"{self.output_file}_temp_{int(time.time())}.{original_extension}"
                    final_path = Path("data") / f"{self.output_file}.{original_extension}"
                else:  # Default to original extension from metadata
                    final_path = final_path.with_suffix(f".{original_extension}")
                    temp_path = temp_path.with_suffix(f".{original_extension}")
                data_to_write = plaintext

            self._save_to_file(temp_path, data_to_write, final_path)

        except FileNotFoundError as e:
            print(f"Error: '{e.filename}' not found.")
        except OSError as e:
            print(f"Error with file '{e.filename}': {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")


    # Verify the password by matching the stored key.
    def check_password(self, salt, key):
        password = getpass.getpass("Password: ")
        scrypt_kdf = Scrypt(
            salt=salt,
            length=self.SCRYPT_LENGTH,
            n=self.SCRYPT_N,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P,
        )
        try:
            scrypt_kdf.verify(password.encode(), key)
            print("Password verified succesfully.")
            return True
        except Exception:
            print("Password verification failed.")
            return False