import sqlite3
from security import create_connection, generate_rsa_key_pair


def register_user(username, email, hashed_password, salt, phone, gender, address):
    private_key, public_key = generate_rsa_key_pair()

    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username = ? OR email = ? OR phone = ?',
                   (username, email, phone))
    if cursor.fetchone():
        conn.close()
        return False

    cursor.execute(
        'INSERT INTO users (username, email, hashed_password, salt, phone, gender, address, private_key, public_key) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (username, email, sqlite3.Binary(hashed_password), sqlite3.Binary(salt), phone, gender,
         address, private_key, public_key))
    conn.commit()
    conn.close()
    print(f"Usuario registrado: {username}, Contraseña Hasheada: {hashed_password}, Salt: {salt}")
    return True

def search_user(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result


def authenticate_user(username):
    print("usuario",username)
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT hashed_password, salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    print(f"Consulta ejecutada: SELECT hashed_password, salt FROM users WHERE username = {username}")
    print(f"Resultado: {result}")
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

def delete_songs_by_user_id(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM songs WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def verify_email_recovery(email):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()
    return result

def get_user_by_email(email):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def update_password(user_id, hashed_password, salt):
    print(f"Actualizando contraseña del usuario: {user_id}")
    print(f"Contraseña Hasheada: {hashed_password}")
    print(f"Salt: {salt}")
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET hashed_password = ?, salt = ? WHERE id = ?",
                   (hashed_password, salt, user_id))
    conn.commit()
    conn.close()
    print(f"columnas afectadas: {cursor.rowcount}")
    return cursor.rowcount > 0