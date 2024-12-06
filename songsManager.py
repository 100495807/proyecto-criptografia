import os
from securityManager import SecurityManager


class SongManager:
    def __init__(self):
        self.security_manager = SecurityManager()

    def insert_artist_song(self, user_id, song_name, lyrics, description, credits, password):
        # Derivar la clave de cifrado a partir de la contraseña y la salt
        artist_salt = self.security_manager.generate_salt()
        key = self.security_manager.derive_key(password, artist_salt)

        # Generar nonces para cada campo
        nonce_song = os.urandom(12)
        nonce_lyrics = os.urandom(12)
        nonce_description = os.urandom(12)
        nonce_credits = os.urandom(12)

        # Cifrar cada campo
        encrypted_song_name = self.security_manager.encrypt_aes_gcm(song_name, key, nonce_song)
        encrypted_lyrics = self.security_manager.encrypt_aes_gcm(lyrics, key, nonce_lyrics)
        encrypted_description = self.security_manager.encrypt_aes_gcm(description, key, nonce_description)
        encrypted_credits = self.security_manager.encrypt_aes_gcm(credits, key, nonce_credits)

        # Insertar la canción en la base de datos
        conn = self.security_manager.create_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO artist_songs (user_id, song_name, lyrics, description, credits, nonce_song, nonce_lyrics, nonce_description, nonce_credits, artist_salt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, encrypted_song_name, encrypted_lyrics, encrypted_description, encrypted_credits, nonce_song, nonce_lyrics, nonce_description, nonce_credits, artist_salt))
        conn.commit()
        conn.close()

        return True

    def get_artist_songs(self, user_id, password):
        conn = self.security_manager.create_connection()
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
            key = self.security_manager.derive_key(password, artist_salt)
            song_name = self.security_manager.decrypt_aes_gcm(encrypted_song_name, key, nonce_song)
            lyrics = self.security_manager.decrypt_aes_gcm(encrypted_lyrics, key, nonce_lyrics)
            description = self.security_manager.decrypt_aes_gcm(encrypted_description, key, nonce_description)
            credits = self.security_manager.decrypt_aes_gcm(encrypted_credits, key, nonce_credits)

            decrypted_songs.append({
                'song_name': song_name,
                'lyrics': lyrics,
                'description': description,
                'credits': credits
            })

        return decrypted_songs


    def register_song(self, user_id, song_name, author_name, password):
        conn = self.security_manager.create_connection()
        cursor = conn.cursor()

        # Seleccionar todas las canciones del usuario
        cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt FROM songs WHERE user_id = ?', (user_id,))
        songs = cursor.fetchall()

        # Descifrar las canciones y verificar si la canción ya existe
        for encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt in songs:
            key = self.security_manager.derive_key(password, song_salt)
            decrypted_song_name = self.security_manager.decrypt_aes_gcm(encrypted_song_name, key, nonce_song)
            decrypted_author_name = self.security_manager.decrypt_aes_gcm(encrypted_author_name, key, nonce_author)
            if decrypted_song_name == song_name and decrypted_author_name == author_name:
                conn.close()
                return False  # La canción ya existe

        # Encriptar el nombre de la canción y el nombre del autor
        nonce_song = os.urandom(12)
        nonce_author = os.urandom(12)
        salt_song = self.security_manager.generate_salt()
        salt_author = self.security_manager.generate_salt()
        key_song = self.security_manager.derive_key(password, salt_song)
        key_author = self.security_manager.derive_key(password, salt_author)
        encrypted_song_name = self.security_manager.encrypt_aes_gcm(song_name, key_song, nonce_song)
        encrypted_author_name = self.security_manager.encrypt_aes_gcm(author_name, key_author, nonce_author)

        # Insertar la canción en la base de datos
        cursor.execute(
            'INSERT INTO songs (user_id, encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt, author_salt) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (user_id, encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, salt_song, salt_author)
        )
        conn.commit()
        conn.close()
        return True


    def get_encrypted_song(self, user_id, encrypted_song_name):
        """Recupera la canción cifrada por el nombre del usuario y el nombre de la canción."""
        conn = self.security_manager.create_connection()
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


    def get_songs_by_user(self, user_id):
        conn = self.security_manager.create_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt, author_salt FROM songs WHERE '
                       'user_id = ?', (user_id,))
        songs = cursor.fetchall()
        conn.close()
        return songs


