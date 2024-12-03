import sqlite3
import os

class Database:
    def __init__(self, db_name='database.db'):
        base_dir = os.path.dirname(__file__)
        self.db_path = os.path.join(base_dir, db_name)
        self.conn = None

    def create_connection(self):
        self.conn = sqlite3.connect(self.db_path)
        return self.conn

    def close_connection(self):
        if self.conn:
            self.conn.close()

    def create_all_tables(self):
        self.create_connection()
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
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
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS songs (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        encrypted_song_name BLOB NOT NULL,
        encrypted_author_name BLOB NOT NULL,
        nonce_song BLOB NOT NULL,
        nonce_author BLOB NOT NULL,
        song_salt BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        song_name TEXT NOT NULL,
        author_name TEXT NOT NULL,
        comment TEXT NOT NULL,
        signature BLOB,
        com_salt BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
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
        artist_salt BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
                )
                ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS private_keys (
        cert_name TEXT PRIMARY KEY,
        private_key BLOB
        )
        ''')
        self.conn.commit()
        self.close_connection()

    def delete_all_tables(self):
        self.create_connection()
        cursor = self.conn.cursor()
        cursor.execute('DROP TABLE IF EXISTS users')
        cursor.execute('DROP TABLE IF EXISTS songs')
        cursor.execute('DROP TABLE IF EXISTS comments')
        cursor.execute('DROP TABLE IF EXISTS artist_songs')
        cursor.execute('DROP TABLE IF EXISTS private_keys')
        self.conn.commit()
        self.close_connection()