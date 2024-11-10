import sys
from key_generation import gen_encryption_key, gen_password_based_encryption_key
from encryption import crypt_keeper
from utils.utils import get_command_line_args


def main():
    args = get_command_line_args()
    
    # Dictionary with 'keys' as command line arguments and 'values' as lambda functions
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
            return 0
    
    print("No valid command was executed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())