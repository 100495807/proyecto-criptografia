import os
from security import encrypt_aes_gcm, decrypt_aes_gcm, derive_key, create_connection


def register_song(user_id, song_name, author_name, password, salt):
    conn = create_connection()
    cursor = conn.cursor()

    # Selecione todas las canciones del usuario
    cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce FROM songs WHERE '
                   'user_id = ?', (user_id,))
    songs = cursor.fetchall()

    key = derive_key(password, salt)

    # Descifrar las canciones y verificar si la canción ya existe
    for encrypted_song_name, encrypted_author_name, nonce in songs:
        decrypted_song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce)
        decrypted_author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce)
        if decrypted_song_name == song_name and decrypted_author_name == author_name:
            conn.close()
            return False  # Song already exists

    # Encriptar el nombre de la canción y el nombre del autor
    nonce = os.urandom(12)
    encrypted_song_name = encrypt_aes_gcm(song_name, key, nonce)
    encrypted_author_name = encrypt_aes_gcm(author_name, key, nonce)

    # Inserta la canción en la base de datos
    cursor.execute(
        'INSERT INTO songs (user_id, encrypted_song_name, encrypted_author_name, nonce) VALUES ('
        '?, ?, ?, ?)',
        (user_id, encrypted_song_name, encrypted_author_name, nonce)
    )
    conn.commit()
    conn.close()
    return True


def get_encrypted_song(user_id, encrypted_song_name):
    """Recupera la canción cifrada por el nombre del usuario y el nombre de la canción."""
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_song_name, nonce FROM songs WHERE user_id = ? AND '
                   'encrypted_song_name = ?',
                   (user_id, encrypted_song_name))
    result = cursor.fetchone()
    conn.close()
    if result:
        print(
            f"DEBUG: Canción cifrada '{encrypted_song_name}' recuperada para el usuario ID {user_id}.")
    else:
        print(
            f"DEBUG: No se encontró la canción cifrada '{encrypted_song_name}' para el usuario ID {user_id}.")
    return result if result else None


def get_songs_by_user(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce FROM songs WHERE '
                   'user_id = ?', (user_id,))
    songs = cursor.fetchall()
    conn.close()
    return songs


def get_songs(user_id, password, salt):
    """Recupera y descifra las canciones del usuario."""
    key = derive_key(password, salt)
    songs = get_songs_by_user(user_id)

    decrypted_songs = []
    for encrypted_song_name, encrypted_author_name, nonce in songs:
        if encrypted_song_name and encrypted_author_name and key:
            song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce)
            author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce)
            decrypted_songs.append({'Canción': song_name, 'autor': author_name})
            print(f"DEBUG: Canción '{song_name}' de '{author_name}' descifrada.")
        else:
            print("DEBUG: Error al descifrar la canción.")
    return decrypted_songs
