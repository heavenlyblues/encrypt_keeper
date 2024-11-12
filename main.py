import sys
from cryptor.key_forge import KeyForge
from cryptor.crypt_keeper import CryptKeeper
from utils.cli import get_command_line_args


def main():
    args = get_command_line_args()

    key_maker = KeyForge(args.key_file)
    cryptor = CryptKeeper(args.key_file, args.input_file, args.output_file)

    # Dictionary with 'keys' as command line arguments and 'values' as lambda functions
    commands = {
        "key": lambda: key_maker.forge_key(),
        "secure_key": lambda: key_maker.forge_secure_key(),
        "encrypt": lambda: cryptor.crypt_keeper("encrypt"),
        "decrypt": lambda: cryptor.crypt_keeper("decrypt")
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