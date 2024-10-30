import argparse
from cryptography.fernet import Fernet



def main():
    
    # parser = argparse.ArgumentParser()
    # parser.add_argument("echo", help="echo the string you use here")
    # args = parser.parse_args()

    key = Fernet.generate_key() # creates a byte string that meets Fernet’s encryption requirements
    f = Fernet(key) # creates an instance of the Fernet class from the cryptography.fernet module. 
    
    token = f.encrypt(b"my deep dark secret")
    print(token)
    
    token = f.decrypt(token)
    print(token)


if __name__ == "__main__":
    main()