from cryptography.fernet import Fernet

#Key generators
def generate_kek() -> bytes:
    """Generate a brand new Key Encryption Key (the master key)."""
    return Fernet.generate_key()


def generate_dek() -> bytes:
    """Generate a brand new Data Encryption Key (one per secret)."""
    return Fernet.generate_key()
#Encryption of DEK with KEK
def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    """Encrypt a DEK using the KEK. This is what gets stored in the database."""
    f = Fernet(kek)
    return f.encrypt(dek)

# Decryption of DEK with KEK
def unwrap_dek(wrapped_dek: bytes, kek: bytes) -> bytes:
    """Decrypt a wrapped DEK back into a usable DEK, using the KEK."""
    f = Fernet(kek)
    return f.decrypt(wrapped_dek)
#Encryption and decryption of the actual secret value using the DEK
def encrypt_secret(plaintext: str, dek: bytes) -> bytes:
    """Encrypt the actual secret value using its DEK."""
    f = Fernet(dek)
    return f.encrypt(plaintext.encode())


def decrypt_secret(ciphertext: bytes, dek: bytes) -> str:
    """Decrypt the actual secret value using its DEK."""
    f = Fernet(dek)
    return f.decrypt(ciphertext).decode()

def seal_secret(plaintext: str, kek: bytes) -> tuple[bytes, bytes]:
    """
    Full envelope-encryption flow for storing a new secret.
    Returns (encrypted_secret, wrapped_dek) - both get written to the database.
    The plaintext and the raw DEK are never stored anywhere, only their
    encrypted forms.
    """
    dek = generate_dek()
    encrypted_secret = encrypt_secret(plaintext, dek)
    wrapped_dek = wrap_dek(dek, kek)
    return encrypted_secret, wrapped_dek


def open_secret(encrypted_secret: bytes, wrapped_dek: bytes, kek: bytes) -> str:
    """
    Full envelope-decryption flow for retrieving a secret.
    Unwraps the DEK using the KEK, then uses that DEK to decrypt the
    actual secret.
    """
    dek = unwrap_dek(wrapped_dek, kek)
    return decrypt_secret(encrypted_secret, dek)