import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidTag
import base64

def generate_salt():
    return os.urandom(16)

def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode())
    return hashed_password, salt

def verify_password(stored_password, provided_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        print("Almacenada:", stored_password, "nueva", provided_password, "salt", salt)
        kdf.verify(provided_password.encode(), stored_password)

        return True
    except InvalidKey:
        return False

def generate_key():
    """Genera una clave aleatoria de 32 bytes para AES."""
    key= os.urandom(32)
    print(f"Clave generada (AES): {base64.b64encode(key).decode()} - Longitud: {len(key)*8} bits")
    return key

def encrypt_aes_gcm(plain_text, key):
    """Cifra un texto plano usando AES-GCM."""
    nonce = os.urandom(12)  # Nonce para AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
    tag = encryptor.tag
    print(f"Texto cifrado: {base64.b64encode(cipher_text).decode()} - "
          f"Algoritmo: AES-GCM, Nonce: {base64.b64encode(nonce).decode()}, "
          f"Tag: {base64.b64encode(tag).decode()}, Longitud clave: {len(key) * 8} bits")
    return base64.b64encode(nonce + tag + cipher_text).decode('utf-8')


def decrypt_aes_gcm(cipher_text_b64, key):
    """Descifra un texto cifrado usando AES-GCM."""
    # Decodifica el texto cifrado de base64
    cipher_text = base64.b64decode(cipher_text_b64)

    nonce = cipher_text[:12]  # Los primeros 12 bytes son el nonce
    tag = cipher_text[12:28]  # Los siguientes 16 bytes son el tag
    cipher_text = cipher_text[28:]  # El resto es el texto cifrado
    print(f"Nonce: {base64.b64encode(nonce).decode()}")
    print(f"Tag: {base64.b64encode(tag).decode()}")
    print(f"Cipher Text: {base64.b64encode(cipher_text).decode()}")
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()
        print(
            f"Texto descifrado: {plain_text.decode()} - Algoritmo: AES-GCM, Longitud clave: {len(key) * 8} bits")
        return plain_text.decode()
    except InvalidTag:
        print("Error: Tag de autenticación no válido.")
        raise
