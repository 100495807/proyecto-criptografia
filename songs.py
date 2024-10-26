import sqlite3
import os
from security import encrypt_aes_gcm, decrypt_aes_gcm, derive_key, create_connection

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
