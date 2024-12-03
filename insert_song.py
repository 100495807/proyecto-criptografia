import os
from security import create_connection, encrypt_aes_gcm, derive_key, decrypt_aes_gcm, generate_salt


def insert_artist_song(user_id, song_name, lyrics, description, credits, password):
    # Derivar la clave de cifrado a partir de la contraseña y la salt
    artist_salt = generate_salt()
    key = derive_key(password, artist_salt)

    # Generar nonces para cada campo
    nonce_song = os.urandom(12)
    nonce_lyrics = os.urandom(12)
    nonce_description = os.urandom(12)
    nonce_credits = os.urandom(12)

    # Cifrar cada campo
    encrypted_song_name = encrypt_aes_gcm(song_name, key, nonce_song)
    encrypted_lyrics = encrypt_aes_gcm(lyrics, key, nonce_lyrics)
    encrypted_description = encrypt_aes_gcm(description, key, nonce_description)
    encrypted_credits = encrypt_aes_gcm(credits, key, nonce_credits)

    # Insertar la canción en la base de datos
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO artist_songs (user_id, song_name, lyrics, description, credits, nonce_song, nonce_lyrics, nonce_description, nonce_credits, artist_salt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, encrypted_song_name, encrypted_lyrics, encrypted_description, encrypted_credits, nonce_song, nonce_lyrics, nonce_description, nonce_credits, artist_salt))
    conn.commit()
    conn.close()

    return True


def get_artist_songs(user_id, password):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('''
    SELECT song_name, lyrics, description, credits, nonce_song, nonce_lyrics, nonce_description, nonce_credits, artist_salt
    FROM artist_songs
    WHERE user_id = ?
    ''', (user_id,))

    encrypted_songs = cursor.fetchall()
    conn.close()
    decrypted_songs = []

    for encrypted_song in encrypted_songs:
        encrypted_song_name, encrypted_lyrics, encrypted_description, encrypted_credits, nonce_song, nonce_lyrics, nonce_description, nonce_credits, artist_salt = encrypted_song
        key = derive_key(password, artist_salt)
        song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce_song)
        lyrics = decrypt_aes_gcm(encrypted_lyrics, key, nonce_lyrics)
        description = decrypt_aes_gcm(encrypted_description, key, nonce_description)
        credits = decrypt_aes_gcm(encrypted_credits, key, nonce_credits)

        decrypted_songs.append({
            'song_name': song_name,
            'lyrics': lyrics,
            'description': description,
            'credits': credits
        })

    return decrypted_songs
