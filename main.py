import smtplib
import random
import string
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk


from certificate import CertificateManager
from database import Database
from query_users import register_user, authenticate_user, get_user_id, delete_songs_by_user_id, \
    verify_email_recovery, get_user_by_email, update_password, get_username_by_id, get_user_type, \
    get_user_certificate
from query_songs import register_song, get_songs_by_user
from security import hash_password, verify_password, generate_salt, \
    decrypt_aes_gcm, derive_key, generate_rsa_key_pair
from email.message import EmailMessage
from cryptography.exceptions import InvalidTag
from validation import validate_username, validate_password, validate_phone, validate_email
from query_comments import add_comment, get_comments, verify_comment, get_private_key
from insert_song import insert_artist_song, get_artist_songs


class UserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Inicio de sesión y registro")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Define un estilo
        self.style = ttk.Style()

        # Estilo para botones
        self.style.configure("TButton",
                             font=("Helvetica", 12),
                             padding=10,
                             background="#4CAF50",  # Verde suave
                             foreground="#000000")  # Texto blanco

        # Estilo para etiquetas
        self.style.configure("TLabel",
                             font=("Helvetica", 12),
                             background="#f0f0f0",  # Blanco para etiquetas
                             foreground="#333333")  # Texto gris oscuro

        # Estilo para el frame principal
        self.style.configure("TFrame",
                             background="#F0F0F0")  # Gris claro para el fondo

        # Estilo para los botones de la barra de menú
        self.style.configure("TEntry", font=("Arial", 12), padding=5)

        self.main_frame = ttk.Frame(root, style="TFrame")
        self.main_frame.pack(fill="both", expand=True)

        self.current_user = None
        self.current_password = None
        self.current_salt = None
        self.user_type = None

        # Frames para las diferentes secciones
        self.login_username_frame = ttk.Frame(root, style="TFrame")
        self.login_password_frame = ttk.Frame(root, style="TFrame")
        self.register_frame = ttk.Frame(root, style="TFrame")
        self.song_frame = ttk.Frame(root, style="TFrame")
        self.recover_frame = ttk.Frame(root, style="TFrame")
        self.post_login_frame = ttk.Frame(root, style="TFrame")
        self.view_songs_frame = ttk.Frame(root, style="TFrame")
        self.comment_frame = ttk.Frame(root, style="TFrame")
        self.view_comments_frame = ttk.Frame(root, style="TFrame")
        self.artist_song_frame = ttk.Frame(root, style="TFrame")

        self.create_main_frame()
        self.create_login_username_frame()
        self.create_register_frame()
        self.create_song_frame()
        self.create_recover_frame()
        self.create_post_login_frame()
        self.create_view_songs_frame()
        self.create_comment_frame()
        self.create_view_comments_frame()
        self.create_artist_song_frame()
        self.create_view_artist_songs_frame()

        self.main_frame.pack(fill="both", expand=True)
        self.login_username_frame.pack(fill="both", expand=True)
        self.login_password_frame.pack(fill="both", expand=True)
        self.register_frame.pack(fill="both", expand=True)
        self.song_frame.pack(fill="both", expand=True)
        self.recover_frame.pack(fill="both", expand=True)
        self.post_login_frame.pack(fill="both", expand=True)
        self.view_artist_songs_frame.pack(fill="both", expand=True)
        self.show_frame(self.main_frame)
        self.password_visible = False

    def show_frame(self, frame):
        self.main_frame.pack_forget()
        self.login_username_frame.pack_forget()
        self.register_frame.pack_forget()
        self.song_frame.pack_forget()
        self.recover_frame.pack_forget()
        self.post_login_frame.pack_forget()
        self.view_songs_frame.pack_forget()
        self.comment_frame.pack_forget()
        self.view_comments_frame.pack_forget()
        self.artist_song_frame.pack_forget()
        self.view_artist_songs_frame.pack_forget()

        if frame == self.recover_frame:
            self.show_email_widgets()
            self.hide_verification_widgets()

        frame.pack(fill="both", expand=True)
        self.clear_entries(frame)

    def clear_entries(self, frame):
        for widget in frame.winfo_children():
            if isinstance(widget, ttk.Entry) or isinstance(widget, ttk.Combobox):
                widget.delete(0, tk.END)

    def create_main_frame(self):
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(3, weight=1)

        self.login_button = ttk.Button(self.main_frame, text="Inicio de sesión", style="TButton",
                                       command=lambda: self.show_frame(self.login_username_frame))
        self.login_button.grid(row=0, column=1, columnspan=2, padx=20, pady=20, sticky="ew")

        self.register_button = ttk.Button(self.main_frame, text="Registro", style="TButton",
                                          command=lambda: self.show_frame(self.register_frame))
        self.register_button.grid(row=1, column=1, columnspan=2, padx=20, pady=20, sticky="ew")

        self.close_app_button = ttk.Button(self.main_frame, text="Cerrar App", style="TButton",
                                           command=self.on_close)
        self.close_app_button.grid(row=2, column=1, columnspan=2, padx=20, pady=20, sticky="ew")

    def create_login_username_frame(self):
        self.login_username_frame = ttk.Frame(self.root, style="TFrame")
        self.login_username_frame.grid_columnconfigure(0, weight=1)
        self.login_username_frame.grid_columnconfigure(4, weight=1)

        self.username_label = ttk.Label(self.login_username_frame, text="Usuario")
        self.username_label.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry_login = ttk.Entry(self.login_username_frame, font=("Arial", 12))
        self.username_entry_login.grid(row=0, column=2, padx=5, pady=5)

        self.password_label = ttk.Label(self.login_username_frame, text="Contraseña")
        self.password_label.grid(row=1, column=1, padx=5, pady=5)
        self.password_entry_login = ttk.Entry(self.login_username_frame, show="*",
                                              font=("Arial", 12))
        self.password_entry_login.grid(row=1, column=2, padx=5, pady=5)

        self.show_password_button_login = ttk.Button(self.login_username_frame,
                                                     text="Mostrar Contraseña", style="TButton",
                                                     command=lambda:
                                                     self.toggle_password_visibility(
                                                         self.password_entry_login,
                                                         self.show_password_button_login))
        self.show_password_button_login.grid(row=1, column=3, padx=5, pady=5)

        self.verify_username_button = ttk.Button(self.login_username_frame, text="Inicio de sesión",
                                                 style="TButton",
                                                 command=self.login)
        self.verify_username_button.grid(row=2, column=1, columnspan=2, pady=10, sticky="ew")

        self.forgot_password_button = ttk.Button(self.login_username_frame,
                                                 text="¿Olvidaste la contraseña?", style="TButton",
                                                 command=self.show_recover_password)
        self.forgot_password_button.grid(row=3, column=1, columnspan=2, pady=10, sticky="ew")

        self.back_button = ttk.Button(self.login_username_frame, text="Atrás", style="TButton",
                                      command=lambda: self.show_frame(self.main_frame))
        self.back_button.grid(row=4, column=1, columnspan=2, pady=10, sticky="ew")

    def show_password_widgets(self):
        self.password_label.grid(row=0, column=1, padx=5, pady=5)
        self.password_entry_login.grid(row=0, column=2, padx=5, pady=5)
        self.show_password_button_login.grid(row=0, column=3, padx=5, pady=5)
        self.login_button.grid(row=1, column=1, columnspan=2, pady=10, sticky="ew")
        self.forgot_password_button.grid(row=2, column=1, columnspan=2, pady=10, sticky="ew")

    def hide_password_widgets(self):
        self.password_label.grid_forget()
        self.password_entry_login.grid_forget()
        self.show_password_button_login.grid_forget()
        self.login_button.grid_forget()
        self.forgot_password_button.grid_forget()

    def create_register_frame(self):
        self.username_label = ttk.Label(self.register_frame, text="Usuario")
        self.username_label.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry_register = ttk.Entry(self.register_frame)
        self.username_entry_register.grid(row=0, column=2, padx=5, pady=5)

        self.email_label = ttk.Label(self.register_frame, text="Email")
        self.email_label.grid(row=1, column=1, padx=5, pady=5)
        self.email_entry = ttk.Entry(self.register_frame)
        self.email_entry.grid(row=1, column=2, padx=5, pady=5)

        self.password_label = ttk.Label(self.register_frame, text="Contraseña")
        self.password_label.grid(row=2, column=1, padx=5, pady=5)
        self.password_entry_register = ttk.Entry(self.register_frame, show="*")
        self.password_entry_register.grid(row=2, column=2, padx=5, pady=5)

        self.show_password_button = ttk.Button(self.register_frame, text="Mostrar Contraseña",
                                               command=lambda: self.toggle_password_visibility(
                                                   self.password_entry_register,
                                                   self.show_password_button))
        self.show_password_button.grid(row=2, column=3, padx=5, pady=5)

        self.repeat_password_label = ttk.Label(self.register_frame, text="Repetir Contraseña")
        self.repeat_password_label.grid(row=3, column=1, padx=5, pady=5)
        self.repeat_password_entry_register = ttk.Entry(self.register_frame, show="*")
        self.repeat_password_entry_register.grid(row=3, column=2, padx=5, pady=5)

        self.show_repeat_password_button = ttk.Button(self.register_frame,
                                                      text="Mostrar Contraseña",
                                                      command=lambda:
                                                      self.toggle_password_visibility(
                                                          self.repeat_password_entry_register,
                                                          self.show_repeat_password_button))
        self.show_repeat_password_button.grid(row=3, column=3, padx=5, pady=5)

        self.phone_label = ttk.Label(self.register_frame, text="Móvil")
        self.phone_label.grid(row=4, column=1, padx=5, pady=5)
        self.phone_entry = ttk.Entry(self.register_frame)
        self.phone_entry.grid(row=4, column=2, padx=5, pady=5)

        self.gender_label = ttk.Label(self.register_frame, text="Género")
        self.gender_label.grid(row=5, column=1, padx=5, pady=5)
        self.gender_combobox = ttk.Combobox(self.register_frame, values=["Hombre", "Mujer", "Otro",
                                                                         "Prefiero no decirlo"],
                                            state="readonly")
        self.gender_combobox.grid(row=5, column=2, padx=5, pady=5)

        self.address_label = ttk.Label(self.register_frame, text="Dirección")
        self.address_label.grid(row=6, column=1, padx=5, pady=5)
        self.address_entry = ttk.Entry(self.register_frame)
        self.address_entry.grid(row=6, column=2, padx=5, pady=5)

        self.artist_listener_label = ttk.Label(self.register_frame, text="¿Eres artista u oyente?")
        self.artist_listener_label.grid(row=7, column=1, padx=5, pady=5)
        self.artist_listener_combobox = ttk.Combobox(self.register_frame,
                                                     values=["Artista", "Oyente"], state="readonly")
        self.artist_listener_combobox.grid(row=7, column=2, padx=5, pady=5)

        self.register_button = ttk.Button(self.register_frame, text="Registro",
                                          command=self.register)
        self.register_button.grid(row=8, column=1, columnspan=3, pady=10, sticky="ew")

        self.back_button = ttk.Button(self.register_frame, text="Atrás",
                                      command=lambda: self.show_frame(self.main_frame))
        self.back_button.grid(row=9, column=1, columnspan=3, pady=10, sticky="ew")

        self.register_frame.grid_columnconfigure(0, weight=1)
        self.register_frame.grid_columnconfigure(4, weight=1)

    def create_recover_frame(self):
        self.recover_frame = ttk.Frame(self.root)
        self.recover_frame.grid_columnconfigure(0, weight=1)
        self.recover_frame.grid_columnconfigure(4, weight=1)

        self.email_label_recover = ttk.Label(self.recover_frame, text="Email")
        self.email_entry_recover = ttk.Entry(self.recover_frame)
        self.send_code_button = ttk.Button(self.recover_frame, text="Enviar Código de Verificación",
                                           command=self.send_verification_code)

        self.code_label = ttk.Label(self.recover_frame, text="Código de Verificación")
        self.code_entry = ttk.Entry(self.recover_frame)
        self.new_password_label = ttk.Label(self.recover_frame, text="Nueva Contraseña")
        self.new_password_entry = ttk.Entry(self.recover_frame, show="*")
        self.show_new_password_button = ttk.Button(self.recover_frame, text="Mostrar Contraseña",
                                                   command=lambda: self.toggle_password_visibility(
                                                       self.new_password_entry,
                                                       self.show_new_password_button))
        self.new_repeat_password_label = ttk.Label(self.recover_frame,
                                                   text="Repetir Nueva Contraseña")
        self.new_repeat_password_entry = ttk.Entry(self.recover_frame, show="*")
        self.show_new_repeat_password_button = ttk.Button(self.recover_frame,
                                                          text="Mostrar Contraseña",
                                                          command=lambda:
                                                          self.toggle_password_visibility(
                                                              self.new_repeat_password_entry,
                                                              self.show_new_repeat_password_button))
        self.verify_code_button = ttk.Button(self.recover_frame, text="Verificar Código y Cambiar "
                                                                      "Contraseña",
                                             command=self.verify_code_and_change_password)
        self.back_button_recover = ttk.Button(self.recover_frame, text="Atrás",
                                              command=lambda: self.show_frame(self.main_frame))

    def show_recover_password(self):
        self.show_frame(self.recover_frame)

    def show_email_widgets(self):
        self.email_label_recover.grid(row=0, column=1, padx=5, pady=5)
        self.email_entry_recover.grid(row=0, column=2, padx=5, pady=5)
        self.send_code_button.grid(row=1, column=1, columnspan=2, pady=10, sticky="ew")
        self.back_button_recover.grid(row=2, column=1, columnspan=2, pady=10, sticky="ew")

    def hide_email_widgets(self):
        self.email_label_recover.grid_forget()
        self.email_entry_recover.grid_forget()
        self.send_code_button.grid_forget()
        self.back_button_recover.grid_forget()

    def show_verification_widgets(self):
        self.code_label.grid(row=2, column=1, padx=5, pady=5)
        self.code_entry.grid(row=2, column=2, padx=5, pady=5)
        self.new_password_label.grid(row=3, column=1, padx=5, pady=5)
        self.new_password_entry.grid(row=3, column=2, padx=5, pady=5)
        self.show_new_password_button.grid(row=3, column=3, padx=5, pady=5)
        self.new_repeat_password_label.grid(row=4, column=1, padx=5, pady=5)
        self.new_repeat_password_entry.grid(row=4, column=2, padx=5, pady=5)
        self.show_new_repeat_password_button.grid(row=4, column=3, padx=5, pady=5)
        self.verify_code_button.grid(row=5, column=1, columnspan=2, pady=10, sticky="ew")
        self.back_button_recover.grid(row=6, column=1, columnspan=2, pady=10, sticky="ew")

    def hide_verification_widgets(self):
        self.code_label.grid_forget()
        self.code_entry.grid_forget()
        self.new_password_label.grid_forget()
        self.new_password_entry.grid_forget()
        self.show_new_password_button.grid_forget()
        self.verify_code_button.grid_forget()

    def create_song_frame(self):
        self.song_label = ttk.Label(self.song_frame, text="Nombre de la canción")
        self.song_label.pack()
        self.song_entry = ttk.Entry(self.song_frame)
        self.song_entry.pack()

        self.author_label = ttk.Label(self.song_frame, text="Cantante/Grupo")
        self.author_label.pack()
        self.author_entry = ttk.Entry(self.song_frame)
        self.author_entry.pack()

        self.insert_song = ttk.Button(self.song_frame, text="Registrar canción",
                                      command=self.insert_song)
        self.insert_song.pack()

        self.back_button = ttk.Button(self.song_frame, text="Atrás",
                                      command=lambda: self.show_frame(self.post_login_frame))
        self.back_button.pack()

    def create_post_login_frame(self):
        self.post_login_frame = ttk.Frame(self.root)
        self.post_login_frame.grid_columnconfigure(0, weight=1)
        self.post_login_frame.grid_columnconfigure(1, weight=1)

        self.insert_song_button = ttk.Button(self.post_login_frame, text="Insertar Canción",
                                             command=lambda: self.show_frame(self.song_frame))
        self.insert_song_button.grid(row=0, column=0, padx=20, pady=20, sticky="ew")

        self.view_songs_button = ttk.Button(self.post_login_frame, text="Ver Canciones",
                                            command=self.view_songs)
        self.view_songs_button.grid(row=0, column=1, padx=20, pady=20, sticky="ew")

        self.comment_button = ttk.Button(self.post_login_frame, text="Agregar Comentario",
                                         command=lambda: self.show_frame(self.comment_frame))
        self.comment_button.grid(row=1, column=0, padx=20, pady=20, sticky="ew")

        self.view_comments_button = ttk.Button(self.post_login_frame, text="Ver Comentarios",
                                               command=self.view_comments)
        self.view_comments_button.grid(row=1, column=1, padx=20, pady=20, sticky="ew")

        self.request_certificate_button = ttk.Button(self.post_login_frame,
                                                     text="Solicitar certificado",
                                                     command=self.issue_user_certificate)
        self.request_certificate_button.grid(row=2, column=0, padx=20, pady=20, sticky="ew")

        self.create_song_button = ttk.Button(self.post_login_frame, text="Crear Canción (artistas)",
                                             command=self.show_artist_song_frame)
        self.create_song_button.grid(row=2, column=1, padx=20, pady=20, sticky="ew")

        self.logout_button = ttk.Button(self.post_login_frame, text="Cerrar Sesión",
                                        command=lambda: self.show_frame(self.main_frame))
        self.logout_button.grid(row=3, column=0, columnspan=2, padx=20, pady=20, sticky="ew")

    def create_view_songs_frame(self):
        self.view_songs_frame = ttk.Frame(self.root)
        self.view_songs_frame.grid_columnconfigure(0, weight=1)
        self.view_songs_frame.grid_columnconfigure(1, weight=1)
        self.view_songs_frame.grid_columnconfigure(2, weight=1)
        self.view_songs_frame.grid_columnconfigure(3, weight=1)
        self.view_songs_frame.grid_columnconfigure(4, weight=1)

        self.songs_treeview = ttk.Treeview(self.view_songs_frame, columns=("Canción", "Autor"),
                                           show="headings")
        self.songs_treeview.heading("Canción", text="Canción")
        self.songs_treeview.heading("Autor", text="Autor")
        self.songs_treeview.column("Canción", anchor="center")
        self.songs_treeview.column("Autor", anchor="center")
        self.songs_treeview.grid(row=0, column=1, columnspan=3, padx=20, pady=20, sticky="ew")

        self.back_button = ttk.Button(self.view_songs_frame, text="Atrás",
                                      command=lambda: self.show_frame(self.post_login_frame))
        self.back_button.grid(row=1, column=2, padx=20, pady=20, sticky="ew")

        self.play_song_button = ttk.Button(self.view_songs_frame, text="Reproducir canción "
                                                                       "aleatoria",
                                           command=self.play_random_song)
        self.play_song_button.grid(row=1, column=1, padx=20, pady=20, sticky="ew")

    def create_comment_frame(self):
        self.comment_frame = ttk.Frame(self.root)
        self.comment_frame.grid_columnconfigure(0, weight=1)
        self.comment_frame.grid_columnconfigure(4, weight=1)

        self.song_name_comment_label = ttk.Label(self.comment_frame, text="Nombre de la canción")
        self.song_name_comment_label.grid(row=0, column=1, padx=5, pady=5)
        self.song_name_comment_entry = ttk.Entry(self.comment_frame)
        self.song_name_comment_entry.grid(row=0, column=2, padx=5, pady=5)

        self.author_comment_label = ttk.Label(self.comment_frame, text="Nombre del artista")
        self.author_comment_label.grid(row=1, column=1, padx=5, pady=5)
        self.author_comment_entry = ttk.Entry(self.comment_frame)
        self.author_comment_entry.grid(row=1, column=2, padx=5, pady=5)

        self.comment_label = ttk.Label(self.comment_frame, text="Comentario")
        self.comment_label.grid(row=2, column=1, padx=5, pady=5)
        self.comment_entry = ttk.Entry(self.comment_frame)
        self.comment_entry.grid(row=2, column=2, padx=5, pady=5)

        self.add_comment_button = ttk.Button(self.comment_frame, text="Agregar comentario",
                                             command=self.add_comment)
        self.add_comment_button.grid(row=3, column=1, columnspan=2, pady=10, sticky="ew")

        self.back_button = ttk.Button(self.comment_frame, text="Atrás",
                                      command=lambda: self.show_frame(self.post_login_frame))
        self.back_button.grid(row=4, column=1, columnspan=2, pady=10, sticky="ew")

    def create_view_comments_frame(self):
        self.view_comments_frame = ttk.Frame(self.root)
        self.view_comments_frame.grid_columnconfigure(0, weight=1)
        self.view_comments_frame.grid_columnconfigure(1, weight=1)
        self.view_comments_frame.grid_columnconfigure(2, weight=1)
        self.view_comments_frame.grid_columnconfigure(3, weight=1)
        self.view_comments_frame.grid_columnconfigure(4, weight=1)
        self.view_comments_frame.grid_columnconfigure(5, weight=1)

        self.comments_treeview = ttk.Treeview(self.view_comments_frame,
                                              columns=(
                                                  "Usuario", "Canción", "Artista", "Comentario",
                                                  "Firma Verificada"),
                                              show="headings")
        self.comments_treeview.heading("Usuario", text="Usuario")
        self.comments_treeview.heading("Canción", text="Canción")
        self.comments_treeview.heading("Artista", text="Artista")
        self.comments_treeview.heading("Comentario", text="Comentario")
        self.comments_treeview.heading("Firma Verificada", text="Firma Verificada")
        self.comments_treeview.column("Usuario", anchor="center")
        self.comments_treeview.column("Canción", anchor="center")
        self.comments_treeview.column("Artista", anchor="center")
        self.comments_treeview.column("Comentario", anchor="center")
        self.comments_treeview.column("Firma Verificada", anchor="center")
        self.comments_treeview.grid(row=0, column=1, columnspan=4, padx=20, pady=20, sticky="ew")

        self.back_button = ttk.Button(self.view_comments_frame, text="Atrás",
                                      command=lambda: self.show_frame(self.post_login_frame))
        self.back_button.grid(row=1, column=2, padx=20, pady=20, sticky="ew")

    def create_artist_song_frame(self):
        self.artist_song_frame = ttk.Frame(self.root)
        self.artist_song_frame.grid_columnconfigure(0, weight=1)
        self.artist_song_frame.grid_columnconfigure(4, weight=1)

        self.song_name_label = ttk.Label(self.artist_song_frame, text="Nombre de la canción")
        self.song_name_label.grid(row=0, column=1, padx=5, pady=5)
        self.song_name_entry = ttk.Entry(self.artist_song_frame)
        self.song_name_entry.grid(row=0, column=2, padx=5, pady=5)

        self.lyrics_label = ttk.Label(self.artist_song_frame, text="Letra")
        self.lyrics_label.grid(row=1, column=1, padx=5, pady=5)
        self.lyrics_entry = tk.Text(self.artist_song_frame, height=10, width=40)
        self.lyrics_entry.grid(row=1, column=2, padx=5, pady=5)

        self.description_label = ttk.Label(self.artist_song_frame, text="Descripción")
        self.description_label.grid(row=2, column=1, padx=5, pady=5)
        self.description_entry = tk.Text(self.artist_song_frame, height=5, width=40)
        self.description_entry.grid(row=2, column=2, padx=5, pady=5)

        self.credits_label = ttk.Label(self.artist_song_frame, text="Créditos")
        self.credits_label.grid(row=3, column=1, padx=5, pady=5)
        self.credits_entry = tk.Text(self.artist_song_frame, height=5, width=40)
        self.credits_entry.grid(row=3, column=2, padx=5, pady=5)

        self.insert_song_button = ttk.Button(self.artist_song_frame, text="Insertar Canción",
                                             command=self.insert_artist_song)
        self.insert_song_button.grid(row=4, column=1, columnspan=2, pady=10, sticky="ew")

        self.view_my_songs_button = ttk.Button(self.artist_song_frame, text="Ver mis canciones",
                                               command=self.view_artists_songs)
        self.view_my_songs_button.grid(row=5, column=1, columnspan=2, pady=10, sticky="ew")

        self.back_button = ttk.Button(self.artist_song_frame, text="Atrás",
                                      command=lambda: self.show_frame(self.post_login_frame))
        self.back_button.grid(row=6, column=1, columnspan=2, pady=10, sticky="ew")

    def create_view_artist_songs_frame(self):
        self.view_artist_songs_frame = ttk.Frame(self.root)
        self.view_artist_songs_frame.grid_columnconfigure(0, weight=1)
        self.view_artist_songs_frame.grid_columnconfigure(1, weight=1)
        self.view_artist_songs_frame.grid_columnconfigure(2, weight=1)
        self.view_artist_songs_frame.grid_columnconfigure(3, weight=1)
        self.view_artist_songs_frame.grid_columnconfigure(4, weight=1)
        self.view_artist_songs_frame.grid_columnconfigure(5, weight=1)
        self.view_artist_songs_frame.grid_columnconfigure(6, weight=1)

        self.artist_songs_treeview = ttk.Treeview(self.view_artist_songs_frame,
                                           columns=("Canción", "Letra", "Descripción", "Créditos"),
                                           show="headings")
        self.artist_songs_treeview.heading("Canción", text="Canción")
        self.artist_songs_treeview.heading("Letra", text="Letra")
        self.artist_songs_treeview.heading("Descripción", text="Descripción")
        self.artist_songs_treeview.heading("Créditos", text="Créditos")
        self.artist_songs_treeview.column("Canción", anchor="center")
        self.artist_songs_treeview.column("Letra", anchor="center")
        self.artist_songs_treeview.column("Descripción", anchor="center")
        self.artist_songs_treeview.column("Créditos", anchor="center")
        self.artist_songs_treeview.grid(row=0, column=1, columnspan=5, padx=20, pady=20, sticky="ew")

        self.back_button = ttk.Button(self.view_artist_songs_frame, text="Atrás",
                                      command=lambda: self.show_frame(self.artist_song_frame))
        self.back_button.grid(row=1, column=3, padx=20, pady=20, sticky="ew")

    def show_artist_song_frame(self):
        user_type = get_user_type(self.current_user)
        if user_type != "Artista":
            messagebox.showerror("Error", "Solo los artistas pueden acceder a esta sección")
            return
        self.show_frame(self.artist_song_frame)

    def login(self):
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()
        user_type = get_user_type(username)

        result = authenticate_user(username)
        if result:
            stored_password, salt = result
            if verify_password(stored_password, password, salt):
                messagebox.showinfo("Inicio de sesión", "Inicio de sesión completado")
                self.current_user = username
                self.current_password = password
                self.current_salt = salt
                self.user_type = user_type
                self.show_frame(self.post_login_frame)  # Show the new frame
            else:
                messagebox.showerror("Inicio de sesión",
                                     "Nombre de usuario o contraseña "
                                     "incorrectos")
        else:
            messagebox.showerror("Inicio de sesión",
                                 "Nombre de usuario o contraseña incorrectos")

    def register(self):
        username = self.username_entry_register.get()
        email = self.email_entry.get()
        password = self.password_entry_register.get()
        repeat_password = self.repeat_password_entry_register.get()
        phone = self.phone_entry.get()
        gender = self.gender_combobox.get()
        address = self.address_entry.get()
        self.user_type = self.artist_listener_combobox.get()
        user_type = self.user_type

        print(f"Tipo de usuario registrado: {self.user_type}")
        if not all([username, email, password, repeat_password, phone, gender, address, user_type]):
            messagebox.showerror("Registro", "Todos los campos son obligatorios")
            return

        if (not validate_username(username) or not validate_password(password,
                                                                     repeat_password)
                or not validate_email(email) or not validate_phone(phone)):
            return

        salt = generate_salt()
        hashed_password, salt = hash_password(password, salt)

        # Generar claves RSA
        private_key, public_key = generate_rsa_key_pair()

        if register_user(username, email, hashed_password, salt, phone, gender, address,
                         private_key, public_key, user_type):
            messagebox.showinfo("Registro", "Usuario registrado")
            self.show_frame(self.login_username_frame)
        else:
            messagebox.showerror("Registro", "Usuario, email o móvil ya registrados")

    def insert_song(self):
        song_name = self.song_entry.get()
        author_name = self.author_entry.get()

        if not song_name or not author_name:
            messagebox.showerror("Registrar Canción",
                                 "Por favor, ingrese el nombre de la canción y el autor")
            return

        user_id = get_user_id(self.current_user)
        if user_id is None:
            messagebox.showerror("Registrar Canción", "Id de usuario no encontrado")
            return

        try:
            if not register_song(user_id, song_name, author_name, self.current_password):
                raise ValueError("Error al registrar la canción")

            messagebox.showinfo("Registrar Canción", "Canción registrada")
            self.song_entry.delete(0, tk.END)
            self.author_entry.delete(0, tk.END)
        except ValueError as e:
            messagebox.showerror("Registrar Canción", str(e))

    def play_random_song(self):
        user_id = get_user_id(self.current_user)
        if user_id is None:
            messagebox.showerror("Escuchar Canción", "Id de usuario no encontrado")
            return

        try:
            songs = get_songs_by_user(user_id)
        except Exception as e:
            messagebox.showerror("Escuchar Canción", f"Error al encontar canción: {e}")
            return

        if self.current_user is not None and not songs:
            messagebox.showerror("Escuchar Canción", "Canción no encontrada")
            return

        song = random.choice(songs)
        encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt = song

        try:
            key = derive_key(self.current_password, song_salt)
            song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce_song)
            author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce_author)
            messagebox.showinfo("Escuchar Canción", f"Escuchando '{song_name}' de "
                                                    f"'{author_name}'")
        except Exception as e:
            messagebox.showerror("Escuchar Canción",
                                 f"Error al desencriptar canción: {e}")

    def toggle_password_visibility(self, entry, button):
        if entry.cget('show') == '*':
            entry.config(show='')
            button.config(text='Esconder contraseña')
        else:
            entry.config(show='*')
            button.config(text='Mostrar contraseña')

    def send_verification_code(self):
        email = self.email_entry_recover.get()
        if not email:
            messagebox.showerror("Error", "Por favor, ingrese su correo electrónico")
            return

        try:
            result = verify_email_recovery(email)
        except Exception as e:
            messagebox.showerror("Error", f"Fallo al obtener email: {e}")
            return

        if result is None:
            messagebox.showerror("Error", "Usuario no encontrado")
            return

        registered_email = result[0]

        # Chequear si el email introducido coincide con el registrado
        if email != registered_email:
            messagebox.showerror("Error",
                                 "El correo electrónico no coincide con el registrado")
            return

        # Generar un código de verificación
        self.verification_code = ''.join(
            random.choices(string.ascii_uppercase + string.digits, k=6))

        # Enviar el código de verificación por email
        try:
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            sender_email = 'SMTP_SENDER_EMAIL'
            sender_password = 'SMTP_SENDER_PASSWORD'

            # Create the email message
            msg = EmailMessage()
            msg['Subject'] = 'Código de verificación'
            msg['From'] = sender_email
            msg['To'] = email
            msg.set_content(f"Tu código de verificación es: {self.verification_code}")

            # Send the email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)

            messagebox.showinfo("Exitoso", "Código de verificación enviado")
            self.hide_email_widgets()
            self.show_verification_widgets()
        except Exception as e:
            messagebox.showerror("Error", f"Error al enviar email: {e}")

    def verify_code_and_change_password(self):
        entered_code = self.code_entry.get()
        new_password = self.new_password_entry.get()
        new_repeat_password = self.new_repeat_password_entry.get()

        if entered_code != self.verification_code:
            messagebox.showerror("Error", "Código de verificación incorrecto")
            return

        if not new_password or not new_repeat_password:
            messagebox.showerror("Error", "Por favor, ingrese su nueva contraseña")
            return

        if new_password != new_repeat_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return

        # Borramos las canciones del usuario
        email = self.email_entry_recover.get()
        if not email:
            messagebox.showerror("Error", "Por favor, ingrese su correo electrónico")
            return
        user_id = get_user_by_email(email)
        if user_id is None:
            messagebox.showerror("Error", "Usuario no encontrado")
            return

        try:
            delete_songs_by_user_id(user_id)
        except Exception as e:
            messagebox.showerror("Error", f"Error al borrar canciones: {e}")
            return

        # Actualizamos la contraseña
        salt = generate_salt()
        hashed_password, salt = hash_password(new_password, salt)
        if update_password(user_id, hashed_password, salt):
            messagebox.showinfo("Exitoso", "Contraseña cambiada")
            self.current_password = new_password
            self.show_frame(self.login_username_frame)
        else:
            messagebox.showerror("Error", "Error al cambiar la contraseña")

    def view_songs(self):
        for item in self.songs_treeview.get_children():
            self.songs_treeview.delete(item)  # Clear the treeview

        user_id = get_user_id(self.current_user)
        if user_id is None:
            messagebox.showerror("View Songs", "Id de usuario no encontrado")
            return

        songs = get_songs_by_user(user_id)

        # Desciframos las canciones y las mostramos en el treeview
        for encrypted_song_name, encrypted_author_name, nonce_song, nonce_author, song_salt in songs:
            try:
                key = derive_key(self.current_password, song_salt)
                song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce_song)
                author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce_author)
                self.songs_treeview.insert("", "end", values=(song_name, author_name))
            except InvalidTag as e:
                messagebox.showerror("Ver canciones",
                                     f"Error desencriptando canciones: {e}")

        self.show_frame(self.view_songs_frame)

    def add_comment(self):
        song_name = self.song_name_comment_entry.get()
        author_name = self.author_comment_entry.get()
        comment = self.comment_entry.get()
        user_id = get_user_id(self.current_user)
        if user_id is None:
            messagebox.showerror("Agregar comentario", "Id de usuario no encontrado")
            return

        # Obtener la clave privada del usuario
        private_key_pem = get_private_key(user_id, self.current_password, self.current_salt)
        if private_key_pem is None:
            messagebox.showerror("Agregar comentario", "Clave privada no encontrada")
            return

        if add_comment(user_id, song_name, author_name, comment, private_key_pem,
                       self.current_password):
            messagebox.showinfo("Agregar comentario", "Comentario agregado")
            self.song_name_comment_entry.delete(0, tk.END)
            self.author_comment_entry.delete(0, tk.END)
            self.comment_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Agregar comentario",
                                 "Error al agregar comentario o la canción no está registrada")

    def verify_comments(self, song_id):
        comments = get_comments(song_id)  # Obtener comentarios de la canción
        for user_id, comment, signature in comments:
            print(f"Verificando comentario: {comment}")
            user_cert = get_user_certificate(user_id)  # Obtener el certificado del usuario
            print(f"Certificado del usuario {user_id} cargado.")

            # Verificar la firma del comentario con la clave pública
            is_verified = verify_comment(user_id, comment, signature)

            if is_verified:
                print(f"Comentario verificado correctamente: {comment}")
            else:
                print(f"Firma inválida o comentario no verificado: {comment}")

    def view_comments(self):
        # Limpiar el treeview de comentarios
        for item in self.comments_treeview.get_children():
            self.comments_treeview.delete(item)

        # Obtener todos los comentarios
        comments = get_comments()

        for user_id, song_name, author_name, comment, signature, com_salt in comments:
            username = get_username_by_id(user_id)
            # Verificar si el comentario está firmado correctamente
            is_verified = verify_comment(user_id, comment, signature)
            verification_status = "Sí" if is_verified else "No"

            # Insertar en el treeview
            self.comments_treeview.insert(
                "", "end",
                values=(username, song_name, author_name, comment, verification_status)
            )

        # Mostrar el frame correspondiente
        self.show_frame(self.view_comments_frame)

    def issue_user_certificate(self):
        cert_manager.issue_user_certificate(self.username_entry_login.get())


    def insert_artist_song(self):
        song_name = self.song_name_entry.get()
        lyrics = self.lyrics_entry.get("1.0", tk.END).strip()
        description = self.description_entry.get("1.0", tk.END).strip()
        credits = self.credits_entry.get("1.0", tk.END).strip()

        if not song_name or not lyrics or not description or not credits:
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return

        user_id = get_user_id(self.current_user)
        if user_id is None:
            messagebox.showerror("Error", "Usuario no encontrado")
            return

        # Obtener la contraseña del usuario actual
        password = self.current_password

        # Insertar la canción en la base de datos
        if insert_artist_song(user_id, song_name, lyrics, description, credits, password):
            messagebox.showinfo("Éxito", "Canción insertada correctamente")
            self.song_name_entry.delete(0, tk.END)
            self.lyrics_entry.delete("1.0", tk.END)
            self.description_entry.delete("1.0", tk.END)
            self.credits_entry.delete("1.0", tk.END)
        else:
            messagebox.showerror("Error", "No se pudo insertar la canción")

    def view_artists_songs(self):
        user_id = get_user_id(self.current_user)

        if user_id is None:
            messagebox.showerror("Ver mis canciones", "Id de usuario no encontrado")
            return

        password = self.current_password
        songs = get_artist_songs(user_id, password)

        # Limpiar el Treeview antes de agregar nuevas canciones
        for item in self.artist_songs_treeview.get_children():
            self.artist_songs_treeview.delete(item)

        # Agregar las canciones descifradas al Treeview
        for song in songs:
            song_name = song['song_name']
            lyrics = song['lyrics']
            description = song['description']
            credits = song['credits']
            self.artist_songs_treeview.insert("", "end", values=(song_name, lyrics, description, credits))

        # Mostrar el frame de las canciones del artista
        self.show_frame(self.view_artist_songs_frame)

    def on_close(self):
        if messagebox.askokcancel("Salir", "¿Estás seguro que quieres salir?"):
            self.root.destroy()

cert_manager = CertificateManager()
database = Database()
try:
    if __name__ == "__main__":
        root = tk.Tk()
        app = UserApp(root)
        database.delete_all_tables()
        database.create_all_tables()
        cert_manager.initialize_certificates()
        root.geometry("600x500")
        root.mainloop()
except KeyboardInterrupt:
    print("Ejecución detenida.")

