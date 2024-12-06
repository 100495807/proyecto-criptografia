import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from usersManager import UserManager
from securityManager import SecurityManager
from songsManager import SongManager

class CommentManager:
    def __init__(self):
        self.song_manager = SongManager()
        self.user_manager = UserManager()
        self.security_manager = SecurityManager()

    def add_comment(self, user_id, song_name, author_name, comment, private_key_pem):
        # Firmar el comentario sin verificar si la canción está registrada
        signature = self.security_manager.sign_comment(private_key_pem, comment)

        conn = self.security_manager.create_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO comments (user_id, song_name, author_name, comment, signature) VALUES (?, ?, ?, ?, ?)',
            (user_id, song_name, author_name, comment, signature)
        )
        conn.commit()
        conn.close()
        return True

    def get_comments(self, song_id=None):
        conn = self.security_manager.create_connection()
        cursor = conn.cursor()
        if song_id:
            cursor.execute(
                'SELECT user_id, song_name, author_name, comment, signature FROM comments WHERE id = ?',
                (song_id,)
            )
        else:
            cursor.execute('SELECT user_id, song_name, author_name, comment, signature FROM comments')
        comments = cursor.fetchall()
        conn.close()
        return comments

    def verify_comment(self, user_id, comment, signature):
        # Obtener el nombre de usuario a partir del user_id
        username = self.user_manager.get_username_by_id(user_id)

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

        user_type = self.user_manager.get_user_type(username)
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
        if not self.security_manager.verify_certificate(user_cert, sub_cert):
            return False  # Si el certificado no es válido, no verificamos la firma

        # Obtener la clave pública desde la base de datos
        conn = self.security_manager.create_connection()
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
            is_verified = self.security_manager.verify_comment_signature(public_key_pem, comment, signature)
            if is_verified:
                print("Firma verificada correctamente.")
            else:
                print("La firma no es válida.")
            return is_verified

    def get_private_key(self, user_id, password, salt):
        conn = self.security_manager.create_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT private_key, nonce FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            encrypted_private_key, nonce = result
            key = self.security_manager.derive_key(password, salt)
            private_key_pem = self.security_manager.decrypt_private_key(encrypted_private_key, key, nonce)
            return private_key_pem
        else:
            return None

    def alter_comment(self, comment_id, new_comment):
        conn = self.security_manager.create_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE comments SET comment = ? WHERE id = ?', (new_comment, comment_id))
        conn.commit()
        conn.close()