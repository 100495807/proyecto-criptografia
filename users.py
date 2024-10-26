import sqlite3
import os
import base64

from database import create_songs_table
from security import derive_key, create_connection

def create_all_tables():
    create_users_table()
    create_songs_table()
def create_users_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        hashed_password BLOB NOT NULL,
        salt BLOB NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        gender TEXT,
        address TEXT
    )''')
    conn.commit()
    conn.close()

def register_user(username, email, hashed_password, salt, phone, gender, address):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username = ? OR email = ? OR phone = ?',
                   (username, email, phone))
    if cursor.fetchone():
        conn.close()
        return False

    # Decode Base64-encoded hashed_password and salt back to bytes
    hashed_password_bytes = base64.b64decode(hashed_password)
    salt_bytes = base64.b64decode(salt)

    cursor.execute(
        'INSERT INTO users (username, email, hashed_password, salt, phone, gender, address) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (username, email, sqlite3.Binary(hashed_password_bytes), sqlite3.Binary(salt_bytes), phone, gender, address))
    conn.commit()
    conn.close()
    print(f"Usuario registrado: {username}, Hashed Password: {hashed_password}, Salt: {salt}")
    return True

def authenticate_user(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT hashed_password, salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        stored_password, salt = result
        return bytes(stored_password), bytes(salt)
    return None

def get_user_id(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None
