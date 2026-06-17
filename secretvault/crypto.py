from cryptography.fernet import Fernet


def generate_kek() -> bytes:
    """Generate a brand new Key Encryption Key (the master key)."""
    return Fernet.generate_key()


def generate_dek() -> bytes:
    """Generate a brand new Data Encryption Key (one per secret)."""
    return Fernet.generate_key()

def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    """Encrypt a DEK using the KEK. This is what gets stored in the database."""
    f = Fernet(kek)
    return f.encrypt(dek)


def unwrap_dek(wrapped_dek: bytes, kek: bytes) -> bytes:
    """Decrypt a wrapped DEK back into a usable DEK, using the KEK."""
    f = Fernet(kek)
    return f.decrypt(wrapped_dek)