from security import create_connection


def create_users_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        hashed_password BLOB NOT NULL,
        salt BLOB NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        gender TEXT NOT NULL,
        address TEXT NOT NULL,
        private_key BLOB NOT NULL,
        nonce BLOB NOT NULL,
        public_key BLOB NOT NULL,
        user_type TEXT NOT NULL
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
        nonce_song BLOB NOT NULL,
        nonce_author BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def create_comments_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        song_name TEXT NOT NULL,
        author_name TEXT NOT NULL,
        comment TEXT NOT NULL,
        signature BLOB,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def create_private_keys_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS private_keys (
        cert_name TEXT PRIMARY KEY,
        private_key BLOB
    )
    ''')
    conn.commit()
    conn.close()


import sqlite3


def create_artist_songs_table():
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS artist_songs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        song_name TEXT NOT NULL,
        lyrics TEXT NOT NULL,
        description TEXT NOT NULL,
        credits TEXT NOT NULL,
        nonce_song BLOB NOT NULL,
        nonce_lyrics BLOB NOT NULL,
        nonce_description BLOB NOT NULL,
        nonce_credits BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')

    conn.commit()
    conn.close()


# Llamar a la función para crear la tabla
create_artist_songs_table()


def create_all_tables():
    create_private_keys_table()
    create_users_table()
    create_songs_table()
    create_comments_table()
    create_artist_songs_table()


def delete_all_tables():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS songs')
    cursor.execute('DROP TABLE IF EXISTS comments')
    cursor.execute('DROP TABLE IF EXISTS private_keys')
    cursor.execute('DROP TABLE IF EXISTS artist_songs')
    conn.commit()
    conn.close()





