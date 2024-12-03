import os
import sqlite3
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidTag, InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime


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
        print("Contraseña almacenada:", stored_password, "salt", salt)
        kdf.verify(provided_password.encode(), stored_password)
        return True
    except InvalidKey:
        return False


def generate_key():
    """Genera una clave aleatoria de 32 bytes para AES."""
    key = os.urandom(32)
    print(f"Clave generada (AES): {base64.b64encode(key).decode()} - Longitud: {len(key) * 8} bits")
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
          f"Etiqueta: {base64.b64encode(tag).decode()} | "
          f"Texto cifrado: {base64.b64encode(cipher_text).decode()} | "
          f"Nonce: {base64.b64encode(nonce).decode()}")
    return base64.b64encode(nonce + tag + cipher_text).decode('utf-8')


def decrypt_aes_gcm(cipher_text_b64, key, nonce):
    cipher_text = base64.b64decode(cipher_text_b64)
    tag = cipher_text[12:28]
    cipher_text = cipher_text[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()
        print(
            f"Descifrado AES-GCM: Texto cifrado: {cipher_text_b64} | Clave: {len(key) * 8} bits | "
            f"Etiqueta: {base64.b64encode(tag).decode()} | Texto plano: '{plain_text.decode()}'")
        return plain_text.decode()
    except InvalidTag:
        print("Error: Etiqueta inválida.")
        return None


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("Clave pública generada:", public_pem.decode())
    print("Algoritmo: RSA, Longitud de clave: 2048 bits")

    return private_pem, public_pem


def sign_comment(private_key_pem, comment):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    signature = private_key.sign(
        comment.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Comentario firmado:", base64.b64encode(signature).decode())
    print("Algoritmo: RSA-PSS, Longitud de clave: 2048 bits")

    return signature


def verify_comment_signature(public_key_pem, comment, signature):
    # Cargar la clave pública desde el PEM
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    try:
        # Verificar la firma con la clave pública
        public_key.verify(
            signature,
            comment.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Firma verificada correctamente.")
        return True
    except InvalidSignature:
        print("La firma no es válida.")
        return False


def create_root_ca(user_type):
    CERT_FOLDER = "certificados"

    # Crear la carpeta de certificados si no existe
    os.makedirs(CERT_FOLDER, exist_ok=True)
    CERT_FOLDER = os.path.abspath(CERT_FOLDER)
    # Generar la clave privada para el certificado raíz
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Crear el certificado raíz auto-firmado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, user_type),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{user_type} Root CA"),
    ])
    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(root_key, hashes.SHA256())

    # Guardar el certificado raíz dentro de CERT_FOLDER
    with open(os.path.join(CERT_FOLDER, 'root_cert.pem'), 'wb') as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))

    return root_key, root_cert


def create_subordinate_ca(root_key, root_cert, user_type, CERT_FOLDER):
    # Generar clave privada para la CA subordinada
    sub_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Crear el certificado para la CA subordinada firmado por la raíz
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, user_type),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{user_type} Subordinate CA"),
    ])
    sub_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        sub_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    ).sign(root_key, hashes.SHA256())

    # Guardar el certificado subordinado dentro de CERT_FOLDER
    with open(os.path.join(CERT_FOLDER, f"{user_type.lower()}_sub_cert.pem"), "wb") as f:
        f.write(sub_cert.public_bytes(serialization.Encoding.PEM))

    return sub_key, sub_cert


def issue_certificate(sub_key, sub_cert, user_name):
    # Generar clave privada para el usuario
    user_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    print(f"{user_name} private key generated. Algorithm: RSA, Key length: 2048 bits")

    # Crear el certificado para el usuario firmado por la CA subordinada
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "User"),
        x509.NameAttribute(NameOID.COMMON_NAME, user_name),
    ])
    user_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        sub_cert.subject
    ).public_key(
        user_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(sub_key, hashes.SHA256())
    print(f"{user_name} certificate created and signed by {sub_cert.subject.rfc4514_string()}.")

    # Guardar el certificado y la clave en la carpeta 'certificados'
    cert_folder = "certificados"
    os.makedirs(cert_folder, exist_ok=True)

    # Ruta de los archivos dentro de la carpeta 'certificados'
    user_cert_path = os.path.join(cert_folder, f"{user_name.lower()}_cert.pem")

    # Guardar el certificado del usuario
    with open(user_cert_path, "wb") as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))

    return user_key, user_cert


def verify_certificate(cert):
    try:
        current_time = datetime.datetime.now(
            datetime.timezone.utc)
        if cert.not_valid_before_utc > current_time or cert.not_valid_after_utc < current_time:
            print(f"El certificado ha expirado o no es válido aún.")
            return False
        print("Certificado válido.")
        return True
    except Exception as e:
        print(f"Error al verificar el certificado: {e}")
        return False


def delete_pem_files(directory=None):
    # Usar el directorio actual si no se proporciona ninguno
    if directory is None:
        directory = os.getcwd()

    for filename in os.listdir(directory):
        # Comprobar si el archivo tiene extensión .pem
        if filename.endswith(".pem"):
            file_path = os.path.join(directory, filename)
            try:
                # Eliminar el archivo .pem
                os.remove(file_path)
                print(f"Archivo eliminado: {file_path}")
            except Exception as e:
                print(f"No se pudo eliminar el archivo {file_path}. Error: {e}")


def encrypt_private_key(private_key, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(private_key) + encryptor.finalize()
    tag = encryptor.tag

    print(f"Cifrado AES-GCM: Clave privada cifrada | Clave: {len(key) * 8} bits | "
          f"Etiqueta: {base64.b64encode(tag).decode()} | "
          f"Texto cifrado: {base64.b64encode(cipher_text).decode()} | "
          f"Nonce: {base64.b64encode(nonce).decode()}")
    return base64.b64encode(nonce + tag + cipher_text).decode('utf-8')


def decrypt_private_key(encrypted_private_key_b64, key, nonce):
    try:
        encrypted_private_key = base64.b64decode(encrypted_private_key_b64)
        tag = encrypted_private_key[12:28]
        cipher_text = encrypted_private_key[28:]

        if isinstance(nonce, str):
            nonce = base64.b64decode(nonce)

        # Verificar la longitud del nonce
        if not (8 <= len(nonce) <= 128):
            raise ValueError("El nonce debe tener entre 8 y 128 bytes (64 y 1024 bits).")

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        private_key = decryptor.update(cipher_text) + decryptor.finalize()

        print(f"Descifrado AES-GCM: Clave privada descifrada | Clave: {len(key) * 8} bits | "
              f"Etiqueta: {base64.b64encode(tag).decode()} | "
              f"Texto descifrado: {base64.b64encode(private_key).decode()} | "
              f"Nonce: {base64.b64encode(nonce).decode()}")
        return private_key
    except InvalidTag:
        print("Error: Etiqueta inválida.")
        return None


def save_private_key(cert_name, private_key):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Convertir la clave privada a formato PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Guardar la clave privada en la base de datos
    cursor.execute('''
    INSERT OR REPLACE INTO private_keys (cert_name, private_key) 
    VALUES (?, ?)
    ''', (cert_name, private_key_pem))

    conn.commit()
    conn.close()


# Función para obtener la clave privada de la base de datos
def get_private_key_from_db(cert_name):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
    SELECT private_key FROM private_keys WHERE cert_name = ?
    ''', (cert_name,))
    row = cursor.fetchone()

    conn.close()

    if row:
        private_key_pem = row[0]
        return serialization.load_pem_private_key(private_key_pem, password=None,
                                                  backend=default_backend())
    else:
        return None
