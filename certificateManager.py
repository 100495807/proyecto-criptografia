import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from securityManager import SecurityManager
from usersManager import UserManager

class CertificateManager:
    def __init__(self, cert_folder="certificados"):
        self.cert_folder = cert_folder
        os.makedirs(self.cert_folder, exist_ok=True)
        self.user_manager = UserManager()
        self.security_manager = SecurityManager()

    def initialize_certificates(self):
        # Paths de los certificados
        root_cert_path = os.path.join(self.cert_folder, 'root_cert.pem')
        oyente_sub_cert_path = os.path.join(self.cert_folder, 'oyente_sub_cert.pem')
        artista_sub_cert_path = os.path.join(self.cert_folder, 'artista_sub_cert.pem')

        # Verificar si el certificado raíz y su clave privada existen en la base de datos
        root_key = self.security_manager.certificate_exist('root_key')

        # Comprobar si el certificado raíz ya existe en la carpeta
        if not os.path.exists(root_cert_path) or not root_key:
            master_key = input("Introduzca la contraseña maestra: ")
            print("Certificado raíz o clave no encontrados. Creando ambos...")
            if os.path.exists(root_cert_path):
                os.remove(root_cert_path)
            root_key, root_cert = self.security_manager.create_root_ca("Root")
            self.security_manager.save_private_key('root_key', root_key, master_key)
            with open(root_cert_path, 'wb') as f:
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado raíz cargado correctamente.")

        # Verificar si el certificado subordinado de oyente y su clave privada existen en la base de datos
        oyente_sub_key = self.security_manager.certificate_exist('oyente_sub_key')

        if not os.path.exists(oyente_sub_cert_path) or not oyente_sub_key:
            print("Certificado subordinado de oyente o clave no encontrados. Creando ambos...")
            if os.path.exists(oyente_sub_cert_path):
                os.remove(oyente_sub_cert_path)
            oyente_sub_key, oyente_sub_cert = self.security_manager.create_subordinate_ca(root_key, root_cert, "Oyente", self.cert_folder)
            self.security_manager.save_private_key('oyente_sub_key', oyente_sub_key, master_key)
            with open(oyente_sub_cert_path, 'wb') as f:
                f.write(oyente_sub_cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado subordinado de oyente cargado correctamente.")

        # Verificar si el certificado subordinado de artista y su clave privada existen en la base de datos
        artista_sub_key = self.security_manager.certificate_exist('artista_sub_key')

        if not os.path.exists(artista_sub_cert_path) or not artista_sub_key:
            print("Certificado subordinado de artista o clave no encontrados. Creando ambos...")
            if os.path.exists(artista_sub_cert_path):
                os.remove(artista_sub_cert_path)
            artista_sub_key, artista_sub_cert = self.security_manager.create_subordinate_ca(root_key, root_cert, "Artista", self.cert_folder)
            self.security_manager.save_private_key('artista_sub_key', artista_sub_key, master_key)
            with open(artista_sub_cert_path, 'wb') as f:
                f.write(artista_sub_cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado subordinado de artista cargado correctamente.")

    def create_user_certificate(self, username):
        cert_filename = os.path.join(self.cert_folder, f"{username.lower()}_cert.pem")

        # Verificar si el certificado ya existe
        if os.path.exists(cert_filename):
            with open(cert_filename, 'rb') as f:
                existing_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
            cn = existing_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if cn.lower() == username.lower():
                print(f"El certificado para {username} ya existe.")
                return
            else:
                print(f"El certificado existente no corresponde a {username}. Se generará uno nuevo.")

        # Obtener las claves subordinadas desde la base de datos
        user_type = self.user_manager.get_user_type(username)
        if user_type == "Artista":
            print("Solicitando certificado de Artista...")

            artista_sub_key, salt = self.security_manager.get_private_key_from_db('artista_sub_key')
            with open(os.path.join(self.cert_folder, 'artista_sub_cert.pem'), 'rb') as f:
                artista_sub_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            master_key = input("Introduzca la contraseña maestra: ")
            user_key, user_cert = self.security_manager.user_certificate(artista_sub_key, artista_sub_cert, username, master_key, salt)
            print(f"Certificado de Artista para {username} emitido correctamente.")

        elif user_type == "Oyente":
            print("Solicitando certificado de Oyente...")

            oyente_sub_key, salt = self.security_manager.get_private_key_from_db('oyente_sub_key')
            with open(os.path.join(self.cert_folder, 'oyente_sub_cert.pem'), 'rb') as f:
                oyente_sub_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            master_key = input("Introduzca la contraseña maestra: ")
            user_key, user_cert = self.security_manager.user_certificate(oyente_sub_key, oyente_sub_cert, username, master_key, salt)
            print(f"Certificado de Oyente para {username} emitido correctamente.")
        else:
            raise ValueError(f"Tipo de usuario desconocido: {user_type}")

        # Validar que se haya generado el certificado
        if user_cert is None:
            raise RuntimeError("El certificado no se generó correctamente.")

        # Guardar el nuevo certificado
        with open(cert_filename, 'wb') as f:
            f.write(user_cert.public_bytes(encoding=serialization.Encoding.PEM))
        print(f"Certificado para {username} guardado correctamente.")

