import os
from security import encrypt_aes_gcm, decrypt_aes_gcm, derive_key, create_connection, generate_salt


def register_song(user_id, song_name, author_name, password):
    conn = create_connection()
    cursor = conn.cursor()

    # Seleccionar todas las canciones del usuario
    cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt FROM songs WHERE user_id = ?', (user_id,))
    songs = cursor.fetchall()



    # Descifrar las canciones y verificar si la canción ya existe
    for encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt in songs:
        key = derive_key(password, song_salt)
        decrypted_song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce_song)
        decrypted_author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce_author)
        if decrypted_song_name == song_name and decrypted_author_name == author_name:
            conn.close()
            return False  # La canción ya existe

    # Encriptar el nombre de la canción y el nombre del autor
    nonce_song = os.urandom(12)
    nonce_author = os.urandom(12)
    salt = generate_salt()
    key = derive_key(password, salt)
    encrypted_song_name = encrypt_aes_gcm(song_name, key, nonce_song)
    encrypted_author_name = encrypt_aes_gcm(author_name, key, nonce_author)

    # Insertar la canción en la base de datos
    cursor.execute(
        'INSERT INTO songs (user_id, encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, salt)
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
    cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt FROM songs WHERE '
                   'user_id = ?', (user_id,))
    songs = cursor.fetchall()
    conn.close()
    return songs


def get_songs(user_id, password):
    """Recupera y descifra las canciones del usuario."""
    songs = get_songs_by_user(user_id)

    decrypted_songs = []
    for encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt in songs:
        key = derive_key(password, song_salt)
        if encrypted_song_name and encrypted_author_name and key:
            song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce_song)
            author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce_author)
            decrypted_songs.append({'Canción': song_name, 'autor': author_name})
            print(f"DEBUG: Canción '{song_name}' de '{author_name}' descifrada.")
        else:
            print("DEBUG: Error al descifrar la canción.")
    return decrypted_songs
