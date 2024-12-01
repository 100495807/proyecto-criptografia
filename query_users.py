import os
import sqlite3

from cryptography import x509

from security import create_connection, encrypt_private_key


def register_user(username, email, hashed_password, salt, phone, gender, address, private_key, public_key, user_type):
    nonce = os.urandom(12)  # Generar un nonce de 12 bytes
    encrypted_private_key = encrypt_private_key(private_key, hashed_password, nonce)

    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username = ? OR email = ? OR phone = ?', (username, email, phone))
    if cursor.fetchone():
        conn.close()
        return False

    cursor.execute(
        'INSERT INTO users (username, email, hashed_password, salt, phone, gender, address, private_key, nonce, public_key, user_type) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (username, email, sqlite3.Binary(hashed_password), sqlite3.Binary(salt), phone, gender, address, encrypted_private_key, nonce, public_key, user_type))
    conn.commit()
    conn.close()
    print(f"Usuario registrado: {username}, Contraseña Hasheada: {hashed_password}, Salt: {salt}")
    return True

def search_user(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result


def authenticate_user(username):
    print("usuario",username)
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT hashed_password, salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    print(f"Consulta ejecutada: SELECT hashed_password, salt FROM users WHERE username = {username}")
    print(f"Resultado: {result}")
    conn.close()
    if result:
        stored_password, salt = result
        return bytes(stored_password), bytes(salt)
    return None

def get_user_id(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def get_user_type(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT user_type FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def delete_songs_by_user_id(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM songs WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def verify_email_recovery(email):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()
    return result

def get_user_by_email(email):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def update_password(user_id, hashed_password, salt):
    print(f"Actualizando contraseña del usuario: {user_id}")
    print(f"Contraseña Hasheada: {hashed_password}")
    print(f"Salt: {salt}")
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET hashed_password = ?, salt = ? WHERE id = ?",
                   (hashed_password, salt, user_id))
    conn.commit()
    conn.close()
    print(f"columnas afectadas: {cursor.rowcount}")
    return cursor.rowcount > 0

# Definir la función para obtener el nombre de usuario por ID
def get_username_by_id(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

CERTIFICATES_FOLDER = "certificados"  # Ruta a la carpeta donde se almacenan los certificados
def get_user_certificate(user_id):
    """
    Obtiene el certificado de un usuario basado en su ID.
    """
    username = get_username_by_id(user_id)

    if not username:
        raise ValueError(f"No se encontró un nombre de usuario para el ID {user_id}.")

    cert_path = os.path.join(CERTIFICATES_FOLDER, f"{username}_cert.pem")

    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"No se encontró el certificado para el usuario con ID {user_id} y nombre {username}.")

    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        try:
            user_cert = x509.load_pem_x509_certificate(cert_data)
            print(f"Certificado cargado para el usuario {username} (ID: {user_id}).")
            return user_cert
        except ValueError:
            raise ValueError(f"El archivo del certificado para el usuario {username} no es válido.")
