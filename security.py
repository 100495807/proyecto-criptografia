import os
import sqlite3

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidTag
import base64

def create_connection():
    base_dir = os.path.dirname(__file__)
    db_path = os.path.join(base_dir, 'database.db')
    conn = sqlite3.connect(db_path)
    return conn

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
    encoded_hashed_password = base64.b64encode(hashed_password).decode('utf-8')
    encoded_salt = base64.b64encode(salt).decode('utf-8')
    return encoded_hashed_password, encoded_salt

def verify_password(stored_password, provided_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        print("Contraseña almacenada:", stored_password, "salt", salt)
        kdf.verify(provided_password.encode(), stored_password)
        return True
    except InvalidKey:
        return False

def generate_key():
    """Genera una clave aleatoria de 32 bytes para AES."""
    key= os.urandom(32)
    print(f"Clave generada (AES): {base64.b64encode(key).decode()} - Longitud: {len(key)*8} bits")
    return key

def derive_key(password, salt):
    """Deriva una clave usando PBKDF2HMAC con SHA-256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_aes_gcm(plain_text, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
    tag = encryptor.tag

    print(f"Cifrado AES-GCM: Texto plano: '{plain_text}' | Clave: {len(key) * 8} bits | "
          f"Etiqueta: {base64.b64encode(tag).decode()} | Texto cifrado: {base64.b64encode(cipher_text).decode()} | Nonce: {base64.b64encode(nonce).decode()}")
    return base64.b64encode(nonce + tag + cipher_text).decode('utf-8')

def decrypt_aes_gcm(cipher_text_b64, key, nonce):
    cipher_text = base64.b64decode(cipher_text_b64)
    tag = cipher_text[12:28]
    cipher_text = cipher_text[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()
        print(f"Descifrado AES-GCM: Texto cifrado: {cipher_text_b64} | Clave: {len(key) * 8} bits | "
              f"Etiqueta: {base64.b64encode(tag).decode()} | Texto plano: '{plain_text.decode()}'")
        return plain_text.decode()
    except InvalidTag:
        print("Error: Etiqueta inválida.")
        return None