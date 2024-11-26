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
        private_key BLOB,
        public_key BLOB
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


def create_playlists_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS playlists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        song_ids TEXT NOT NULL,
        signature TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()


def create_all_tables():
    create_users_table()
    create_songs_table()
    create_playlists_table()



def delete_all_tables():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS songs')
    cursor.execute('DROP TABLE IF EXISTS playlists')
    conn.commit()
    conn.close()





