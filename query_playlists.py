import sqlite3
from security import create_connection

def insert_playlist(user_id, playlist_name, song_ids, signature):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO playlists (user_id, name, song_ids, signature) VALUES (?, ?, ?, ?)',
        (user_id, playlist_name, ','.join(map(str, song_ids)), signature)
    )
    conn.commit()
    conn.close()

def get_private_key(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT private_key FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def get_public_key(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def get_playlist(playlist_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT name, song_ids, signature FROM playlists WHERE id = ?', (playlist_id,))
    result = cursor.fetchone()
    conn.close()
    return result