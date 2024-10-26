import sqlite3
import os
from security import encrypt_aes_gcm, decrypt_aes_gcm, generate_key, derive_key
import base64

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
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT hashed_password, salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
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
    cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce FROM songs WHERE user_id = ?', (user_id,))
    songs = cursor.fetchall()
    conn.close()
    return songs

def get_songs(user_id, password, salt):
    """Recupera y descifra las canciones del usuario."""
    # Obtiene las canciones del usuario desde la base de datos
    key = derive_key(password, salt)
    songs = get_songs_by_user(user_id)

    decrypted_songs = []
    for encrypted_song_name, encrypted_author_name, nonce in songs:
        if encrypted_song_name and encrypted_author_name and key:
            song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce)
            author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce)
            decrypted_songs.append({'name': song_name, 'author': author_name})
            print(f"DEBUG: Canción '{song_name}' de '{author_name}' descifrada.")
        else:
            print("DEBUG: Error al descifrar la canción.")
    return decrypted_songs


def get_encrypted_song(user_id, encrypted_song_name):
    """Recupera la canción cifrada por el nombre del usuario y el nombre de la canción."""
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_song_name, nonce FROM songs WHERE user_id = ? AND encrypted_song_name = ?',
                   (user_id, encrypted_song_name))
    result = cursor.fetchone()
    conn.close()
    if result:
        print(f"DEBUG: Canción cifrada '{encrypted_song_name}' recuperada para el usuario ID {user_id}.")
    else:
        print(f"DEBUG: No se encontró la canción cifrada '{encrypted_song_name}' para el usuario ID {user_id}.")
    return result if result else None


