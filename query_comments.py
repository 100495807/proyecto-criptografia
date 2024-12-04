import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from query_users import get_user_certificate, get_username_by_id, get_user_type
from security import create_connection, sign_comment, verify_comment_signature, decrypt_aes_gcm, \
    derive_key, verify_certificate, decrypt_private_key, generate_salt
from query_songs import get_songs_by_user


def add_comment(user_id, song_name, author_name, comment, private_key_pem, password):
    # Verificar si la canción ya está registrada por el usuario
    songs = get_songs_by_user(user_id)
    song_exists = any(
        decrypt_aes_gcm(encrypted_song_name, derive_key(password, song_salt), nonce_song) == song_name and
        decrypt_aes_gcm(encrypted_author_name, derive_key(password, song_salt), nonce_author) == author_name
        for encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt in songs
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
            ('SELECT user_id, song_name, author_name, comment, signature FROM comments WHERE id = ?',
             (song_id,))
    else:
        cursor.execute('SELECT user_id, song_name, author_name, comment, signature FROM comments')
    comments = cursor.fetchall()
    conn.close()
    return comments


def verify_comment(user_id, comment, signature):
    # Obtener el nombre de usuario a partir del user_id
    username = get_username_by_id(user_id)

    # Ruta al archivo del certificado del usuario
    cert_path = f"certificados/{username}_cert.pem"

    # Verificar si el archivo del certificado existe
    if not os.path.exists(cert_path):
        print(f"El certificado para el usuario {username} no se encuentra.")
        return False  # Si el certificado no existe, devolver False

    # Cargar el certificado desde el archivo
    with open(cert_path, 'rb') as cert_file:
        cert_pem = cert_file.read()

    # Cargar el certificado del usuario
    user_cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())

    user_type = get_user_type(username)
    if user_type == "Oyente":
        sub_cert_path = "certificados/oyente_sub_cert.pem"
    elif user_type == "Artista":
        sub_cert_path = "certificados/artista_sub_cert.pem"
    else:
        print(f"Tipo de usuario desconocido: {user_type}")
        return False

    if not os.path.exists(sub_cert_path):
        print(f"El certificado subordinado correspondiente ({sub_cert_path}) no se encuentra.")
        return False

    with open(sub_cert_path, 'rb') as sub_cert_file:
        sub_cert_pem = sub_cert_file.read()
    sub_cert = x509.load_pem_x509_certificate(sub_cert_pem, backend=default_backend())


    # Verificar la validez del certificado
    if not verify_certificate(user_cert, sub_cert):
        return False  # Si el certificado no es válido, no verificamos la firma

    # Obtener la clave pública desde la base de datos
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE id = ?', (user_id,))
    public_key_pem = cursor.fetchone()[0]
    conn.close()

    # Verificar la firma del comentario
    if signature is None:
        print("No se ha proporcionado firma para este comentario.")
        return None
    else:
        print(f"Verificando la firma del comentario para el usuario {username}...")
        is_verified = verify_comment_signature(public_key_pem, comment, signature)
        if is_verified:
            print("Firma verificada correctamente.")
        else:
            print("La firma no es válida.")
        return is_verified


def get_private_key(user_id, password, salt):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT private_key, nonce FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        encrypted_private_key, nonce = result
        key = derive_key(password, salt)
        private_key_pem = decrypt_private_key(encrypted_private_key, key, nonce)
        return private_key_pem
    else:
        return None

