import sqlite3
import os
from security import encrypt_aes_gcm, decrypt_aes_gcm, generate_key, derive_key


def create_connection():
    base_dir = os.path.dirname(__file__)
    db_path = os.path.join(base_dir, 'database.db')
    print(f"Conectando a la base de datos en: {db_path}")
    conn = sqlite3.connect(db_path)
    return conn


def create_users_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        hashed_password BLOB NOT NULL,
        salt BLOB NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        gender TEXT,
        address TEXT
    )''')
    conn.commit()
    conn.close()


def create_songs_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS songs (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        encrypted_song_name BLOB NOT NULL,
        encrypted_author_name BLOB NOT NULL,
        nonce BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def create_all_tables():
    create_users_table()
    create_songs_table()

import base64

def register_user(username, email, hashed_password, salt, phone, gender, address):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username = ? OR email = ? OR phone = ?',
                   (username, email, phone))
    if cursor.fetchone():
        conn.close()
        return False

    # Decode Base64-encoded hashed_password and salt back to bytes
    hashed_password_bytes = base64.b64decode(hashed_password)
    salt_bytes = base64.b64decode(salt)

    cursor.execute(
        'INSERT INTO users (username, email, hashed_password, salt, phone, gender, address) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (username, email, sqlite3.Binary(hashed_password_bytes), sqlite3.Binary(salt_bytes), phone, gender, address))
    conn.commit()
    conn.close()
    print(f"Usuario registrado: {username}, Hashed Password: {hashed_password}, Salt: {salt}")
    return True


def authenticate_user(username):
    print("usuario",username)
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT hashed_password, salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    print(f"Query executed: SELECT hashed_password, salt FROM users WHERE username = {username}")
    print(f"Result: {result}")
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


def delete_user(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    print(f"User '{username}' deleted successfully.")



def register_song(user_id, song_name, author_name, password, salt):
    conn = create_connection()
    cursor = conn.cursor()

    # Fetch all songs for the user
    cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce FROM songs WHERE user_id = ?', (user_id,))
    songs = cursor.fetchall()

    key = derive_key(password, salt)

    # Decrypt all songs and check if the song already exists
    for encrypted_song_name, encrypted_author_name, nonce in songs:
        decrypted_song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce)
        decrypted_author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce)
        if decrypted_song_name == song_name and decrypted_author_name == author_name:
            conn.close()
            return False  # Song already exists

    # Encrypt the new song
    nonce = os.urandom(12)
    encrypted_song_name = encrypt_aes_gcm(song_name, key, nonce)
    encrypted_author_name = encrypt_aes_gcm(author_name, key, nonce)

    # Insert the new song
    cursor.execute(
        'INSERT INTO songs (user_id, encrypted_song_name, encrypted_author_name, nonce) VALUES (?, ?, ?, ?)',
        (user_id, encrypted_song_name, encrypted_author_name, nonce)
    )
    conn.commit()
    conn.close()
    return True

def get_songs_by_user(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT song_name FROM songs WHERE user_id = ?', (user_id,))
    songs = cursor.fetchall()
    conn.close()
    return songs

def get_all_users():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="users";')
    table_exists = cursor.fetchone()
    if table_exists:
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        conn.close()
        return users
    else:
        print("La tabla 'users' no existe.")
        return []

def delete_all_users():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DROP TABLE users')
    conn.commit()
    conn.close()
    print("Tabla 'users' eliminada correctamente.")

def delete_all_songs():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DROP TABLE songs')
    conn.commit()
    conn.close()
    print("Tabla 'songs' eliminada correctamente.")

def delete_all_tables():
    delete_all_users()
    delete_all_songs()

def save_song(user_id, song_name, author_name):
    """Cifra y guarda una canción para el usuario."""
    # Cifrar el nombre de la canción
    key = generate_key()
    encrypted_song = encrypt_aes_gcm(song_name, key)
    print(f"DEBUG: Canción cifrada: '{song_name}'.")

    # Almacena la canción cifrada en la base de datos
    success = register_song(user_id, song_name, author_name, encrypted_song, key)
    if success:
        print(f"DEBUG: Canción '{song_name}' guardada correctamente para el usuario ID {user_id}.")
    else:
        print(f"DEBUG: Error al guardar la canción '{song_name}' para el usuario ID {user_id}.")


def get_songs(user_id):
    """Recupera y descifra las canciones del usuario."""
    # Obtiene las canciones del usuario desde la base de datos
    songs = get_songs_by_user(user_id)
    print(f"DEBUG: Recuperando {len(songs)} canciones para el usuario ID {user_id}.")

    decrypted_songs = []
    for song in songs:
        song_name = song[0]
        encrypted_song_name, encryption_key = get_encrypted_song(user_id, song_name)

        if encrypted_song_name and encryption_key:
            decrypted_song = decrypt_aes_gcm(encrypted_song_name, encryption_key)
            decrypted_songs.append({'name': song_name, 'data': decrypted_song})
            print(f"DEBUG: Canción '{song_name}' descifrada correctamente.")
        else:
            print(f"DEBUG: No se encontró canción cifrada para '{song_name}'.")

    return decrypted_songs


def get_encrypted_song(user_id, song_name):
    """Recupera la canción cifrada por el nombre del usuario y el nombre de la canción."""
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_song_name FROM songs WHERE user_id = ? AND song_name = ?',
                   (user_id, song_name))
    result = cursor.fetchone()
    conn.close()
    if result:
        print(f"DEBUG: Canción cifrada '{song_name}' recuperada para el usuario ID {user_id}.")
    else:
        print(f"DEBUG: No se encontró la canción cifrada '{song_name}' para el usuario ID {user_id}.")
    return result if result else None (None, None)



# Imprimir los usuarios en la consola
users = get_all_users()
for user in users:
    print(user)

