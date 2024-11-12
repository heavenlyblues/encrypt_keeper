class BaseCipher:
    SCRYPT_LENGTH = 32      # Derived key length in bytes
    SCRYPT_N = 2**14        # CPU/memory cost factor
    SCRYPT_R = 8            # Block size factor
    SCRYPT_P = 1            # Parallelization factor
    SALT_SIZE = 16          # Salt size in bytes