from security import create_connection, sign_comment, verify_comment_signature, decrypt_aes_gcm, \
    derive_key
from query_songs import get_songs_by_user


def add_comment(user_id, song_name, author_name, comment, private_key_pem, password, salt):
    # Verificar si la canción ya está registrada por el usuario
    songs = get_songs_by_user(user_id)
    key = derive_key(password, salt)
    song_exists = any(
        decrypt_aes_gcm(encrypted_song_name, key, nonce_song) == song_name and
        decrypt_aes_gcm(encrypted_author_name, key, nonce_author) == author_name
        for encrypted_song_name, encrypted_author_name, nonce_song, nonce_author in songs
    )

    if song_exists:
        signature = sign_comment(private_key_pem, comment)
    else:
        signature = None

    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute \
        ('INSERT INTO comments (user_id, song_name, author_name, comment, signature) VALUES (?, ?, ?, ?, ?)',
         (user_id, song_name, author_name, comment, signature))
    conn.commit()
    conn.close()
    return True


def get_comments(song_id=None):
    conn = create_connection()
    cursor = conn.cursor()
    if song_id:
        cursor.execute \
            ('SELECT user_id, song_name, author_name, comment, signature FROM comments WHERE song_id = ?',
             (song_id,))
    else:
        cursor.execute('SELECT user_id, song_name, author_name, comment, signature FROM comments')
    comments = cursor.fetchall()
    conn.close()
    return comments


def verify_comment(user_id, comment, signature):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE id = ?', (user_id,))
    public_key_pem = cursor.fetchone()[0]
    conn.close()
    if signature is None:
        return None
    else:
        return verify_comment_signature(public_key_pem, comment, signature)

def get_private_key(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT private_key FROM users WHERE id = ?', (user_id,))
    private_key_pem = cursor.fetchone()[0]
    conn.close()
    return private_key_pem
