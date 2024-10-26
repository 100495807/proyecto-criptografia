import os
import sqlite3
import tkinter as tk
import re
from tkinter import messagebox
from tkinter import ttk
from users import create_users_table, register_user, authenticate_user, get_user_id, \
    create_connection, create_songs_table, create_all_tables
from songs import register_song
from security import hash_password, verify_password, generate_key, encrypt_aes_gcm, generate_salt, \
    decrypt_aes_gcm, derive_key
import smtplib
import random
import string
from email.message import EmailMessage
from cryptography.exceptions import InvalidTag

from validation import validate_username, validate_password, validate_phone, validate_email


class UserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("User Login and Registration")

        # Define a style
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

        # Frames para las diferentes secciones
        self.login_username_frame = ttk.Frame(root, style="TFrame")
        self.login_password_frame = ttk.Frame(root, style="TFrame")
        self.register_frame = ttk.Frame(root, style="TFrame")
        self.song_frame = ttk.Frame(root, style="TFrame")
        self.recover_frame = ttk.Frame(root, style="TFrame")
        self.post_login_frame = ttk.Frame(root, style="TFrame")

        self.create_main_frame()
        self.create_login_username_frame()
        self.create_login_password_frame()
        self.create_register_frame()
        self.create_song_frame()
        self.create_recover_frame()
        self.create_post_login_frame()
        self.create_view_songs_frame()

        self.main_frame.pack(fill="both", expand=True)
        self.login_username_frame.pack(fill="both", expand=True)
        self.login_password_frame.pack(fill="both", expand=True)
        self.register_frame.pack(fill="both", expand=True)
        self.song_frame.pack(fill="both", expand=True)
        self.recover_frame.pack(fill="both", expand=True)
        self.post_login_frame.pack(fill="both", expand=True)
        self.show_frame(self.main_frame)
        self.password_visible = False

    def show_frame(self, frame):
        self.main_frame.pack_forget()
        self.login_username_frame.pack_forget()
        self.login_password_frame.pack_forget()
        self.register_frame.pack_forget()
        self.song_frame.pack_forget()
        self.recover_frame.pack_forget()
        self.post_login_frame.pack_forget()
        self.view_songs_frame.pack_forget()  # Ensure this frame is also forgotten

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

        self.login_button = ttk.Button(self.main_frame, text="Login", style="TButton",
                                       command=lambda: self.show_frame(self.login_username_frame))
        self.login_button.grid(row=0, column=1, columnspan=2, padx=20, pady=20, sticky="ew")

        self.register_button = ttk.Button(self.main_frame, text="Register", style="TButton",
                                          command=lambda: self.show_frame(self.register_frame))
        self.register_button.grid(row=1, column=1, columnspan=2, padx=20, pady=20, sticky="ew")

        self.close_app_button = ttk.Button(self.main_frame, text="Close App", style="TButton",
                                           command=self.root.quit)
        self.close_app_button.grid(row=2, column=1, columnspan=2, padx=20, pady=20, sticky="ew")


    def create_login_username_frame(self):
        self.login_username_frame = ttk.Frame(self.root, style="TFrame")
        self.login_username_frame.grid_columnconfigure(0, weight=1)
        self.login_username_frame.grid_columnconfigure(4, weight=1)

        self.username_label = ttk.Label(self.login_username_frame, text="Username")
        self.username_label.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry_login = ttk.Entry(self.login_username_frame, font=("Arial", 12))
        self.username_entry_login.grid(row=0, column=2, padx=5, pady=5)

        self.verify_username_button = ttk.Button(self.login_username_frame, text="Next", style="TButton",
                                                 command=self.verify_username)
        self.verify_username_button.grid(row=1, column=1, columnspan=2, pady=10, sticky="ew")

        self.back_button = ttk.Button(self.login_username_frame, text="Back", style="TButton",
                                      command=lambda: self.show_frame(self.main_frame))
        self.back_button.grid(row=2, column=1, columnspan=2, pady=10, sticky="ew")

    def create_login_password_frame(self):
        self.login_password_frame = ttk.Frame(self.root, style="TFrame")
        self.login_password_frame.grid_columnconfigure(0, weight=1)
        self.login_password_frame.grid_columnconfigure(4, weight=1)

        self.password_label = ttk.Label(self.login_password_frame, text="Password")
        self.password_label.grid(row=0, column=1, padx=5, pady=5)
        self.password_entry_login = ttk.Entry(self.login_password_frame, show="*", font=("Arial", 12))
        self.password_entry_login.grid(row=0, column=2, padx=5, pady=5)

        self.show_password_button_login = ttk.Button(self.login_password_frame, text="Show Password", style="TButton",
                                                     command=lambda: self.toggle_password_visibility(
                                                         self.password_entry_login,
                                                         self.show_password_button_login))
        self.show_password_button_login.grid(row=0, column=3, padx=5, pady=5)

        self.login_button = ttk.Button(self.login_password_frame, text="Login", style="TButton", command=self.login)
        self.login_button.grid(row=1, column=1, columnspan=2, pady=10, sticky="ew")

        self.forgot_password_button = ttk.Button(self.login_password_frame, text="Forgot Password?", style="TButton",
                                                 command=self.show_recover_password)
        self.forgot_password_button.grid(row=2, column=1, columnspan=2, pady=10, sticky="ew")

        self.back_button = ttk.Button(self.login_password_frame, text="Back", style="TButton",
                                      command=lambda: self.show_frame(self.login_username_frame))
        self.back_button.grid(row=3, column=1, columnspan=2, pady=10, sticky="ew")

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
        self.username_label = ttk.Label(self.register_frame, text="Username")
        self.username_label.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry_register = ttk.Entry(self.register_frame)
        self.username_entry_register.grid(row=0, column=2, padx=5, pady=5)

        self.email_label = ttk.Label(self.register_frame, text="Email")
        self.email_label.grid(row=1, column=1, padx=5, pady=5)
        self.email_entry = ttk.Entry(self.register_frame)
        self.email_entry.grid(row=1, column=2, padx=5, pady=5)

        self.password_label = ttk.Label(self.register_frame, text="Password")
        self.password_label.grid(row=2, column=1, padx=5, pady=5)
        self.password_entry_register = ttk.Entry(self.register_frame, show="*")
        self.password_entry_register.grid(row=2, column=2, padx=5, pady=5)

        self.show_password_button = ttk.Button(self.register_frame, text="Show Password",
                                               command=lambda: self.toggle_password_visibility(
                                                   self.password_entry_register,
                                                   self.show_password_button))
        self.show_password_button.grid(row=2, column=3, padx=5, pady=5)

        self.repeat_password_label = ttk.Label(self.register_frame, text="Repeat Password")
        self.repeat_password_label.grid(row=3, column=1, padx=5, pady=5)
        self.repeat_password_entry_register = ttk.Entry(self.register_frame, show="*")
        self.repeat_password_entry_register.grid(row=3, column=2, padx=5, pady=5)

        self.show_repeat_password_button = ttk.Button(self.register_frame, text="Show Password",
                                                      command=lambda: self.toggle_password_visibility(
                                                          self.repeat_password_entry_register,
                                                          self.show_repeat_password_button))
        self.show_repeat_password_button.grid(row=3, column=3, padx=5, pady=5)

        self.phone_label = ttk.Label(self.register_frame, text="Phone")
        self.phone_label.grid(row=4, column=1, padx=5, pady=5)
        self.phone_entry = ttk.Entry(self.register_frame)
        self.phone_entry.grid(row=4, column=2, padx=5, pady=5)

        self.gender_label = ttk.Label(self.register_frame, text="Gender")
        self.gender_label.grid(row=5, column=1, padx=5, pady=5)
        self.gender_combobox = ttk.Combobox(self.register_frame, values=["Male", "Female", "Other", "I'd rather not say"], state="readonly")
        self.gender_combobox.grid(row=5, column=2, padx=5, pady=5)

        self.address_label = ttk.Label(self.register_frame, text="Address")
        self.address_label.grid(row=6, column=1, padx=5, pady=5)
        self.address_entry = ttk.Entry(self.register_frame)
        self.address_entry.grid(row=6, column=2, padx=5, pady=5)

        self.register_button = ttk.Button(self.register_frame, text="Register",
                                          command=self.register)
        self.register_button.grid(row=7, column=1, columnspan=3, pady=10, sticky="ew")

        self.back_button = ttk.Button(self.register_frame, text="Back",
                                      command=lambda: self.show_frame(self.main_frame))
        self.back_button.grid(row=8, column=1, columnspan=3, pady=10, sticky="ew")

        self.register_frame.grid_columnconfigure(0, weight=1)
        self.register_frame.grid_columnconfigure(4, weight=1)

    def create_recover_frame(self):
        self.recover_frame = ttk.Frame(self.root)
        self.recover_frame.grid_columnconfigure(0, weight=1)
        self.recover_frame.grid_columnconfigure(4, weight=1)

        self.email_label_recover = ttk.Label(self.recover_frame, text="Email")
        self.email_entry_recover = ttk.Entry(self.recover_frame)
        self.send_code_button = ttk.Button(self.recover_frame, text="Send Code",
                                           command=self.send_verification_code)

        self.code_label = ttk.Label(self.recover_frame, text="Verification Code")
        self.code_entry = ttk.Entry(self.recover_frame)
        self.new_password_label = ttk.Label(self.recover_frame, text="New Password")
        self.new_password_entry = ttk.Entry(self.recover_frame, show="*")
        self.show_new_password_button = ttk.Button(self.recover_frame, text="Show Password",
                                                   command=lambda: self.toggle_password_visibility(
                                                       self.new_password_entry,
                                                       self.show_new_password_button))
        self.new_repeat_password_label = ttk.Label(self.recover_frame, text="Repeat New Password")
        self.new_repeat_password_entry = ttk.Entry(self.recover_frame, show="*")
        self.show_new_repeat_password_button = ttk.Button(self.recover_frame, text="Show Password",
                                                          command=lambda: self.toggle_password_visibility(
                                                              self.new_repeat_password_entry,
                                                              self.show_new_repeat_password_button))
        self.verify_code_button = ttk.Button(self.recover_frame, text="Verify and Change Password",
                                             command=self.verify_code_and_change_password)
        self.back_button_recover = ttk.Button(self.recover_frame, text="Back",
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
        self.song_label = ttk.Label(self.song_frame, text="Song Name")
        self.song_label.pack()
        self.song_entry = ttk.Entry(self.song_frame)
        self.song_entry.pack()

        self.author_label = ttk.Label(self.song_frame, text="Author/Group")
        self.author_label.pack()
        self.author_entry = ttk.Entry(self.song_frame)
        self.author_entry.pack()

        self.insert_song = ttk.Button(self.song_frame, text="Register Song",
                                      command=self.insert_song)
        self.insert_song.pack()

        self.back_button = ttk.Button(self.song_frame, text="Back",
                                      command=lambda: self.show_frame(self.post_login_frame))
        self.back_button.pack()

    def create_post_login_frame(self):
        self.post_login_frame = ttk.Frame(self.root)
        self.post_login_frame.grid_columnconfigure(0, weight=1)
        self.post_login_frame.grid_columnconfigure(4, weight=1)

        self.insert_song_button = ttk.Button(self.post_login_frame, text="Insert Song",
                                             command=lambda: self.show_frame(self.song_frame))
        self.insert_song_button.grid(row=0, column=1, columnspan=2, padx=20, pady=20, sticky="ew")

        self.view_songs_button = ttk.Button(self.post_login_frame, text="View Songs",
                                            command=self.view_songs)
        self.view_songs_button.grid(row=1, column=1, columnspan=2, padx=20, pady=20, sticky="ew")

        self.logout_button = ttk.Button(self.post_login_frame, text="Logout",
                                        command=lambda: self.show_frame(self.main_frame))
        self.logout_button.grid(row=2, column=1, columnspan=2, padx=20, pady=20, sticky="ew")

    def create_view_songs_frame(self):
        self.view_songs_frame = ttk.Frame(self.root)
        self.view_songs_frame.grid_columnconfigure(0, weight=1)
        self.view_songs_frame.grid_columnconfigure(1, weight=1)
        self.view_songs_frame.grid_columnconfigure(2, weight=1)
        self.view_songs_frame.grid_columnconfigure(3, weight=1)
        self.view_songs_frame.grid_columnconfigure(4, weight=1)

        self.songs_treeview = ttk.Treeview(self.view_songs_frame, columns=("Song", "Author"), show="headings")
        self.songs_treeview.heading("Song", text="Song")
        self.songs_treeview.heading("Author", text="Author")
        self.songs_treeview.column("Song", anchor="center")
        self.songs_treeview.column("Author", anchor="center")
        self.songs_treeview.grid(row=0, column=1, columnspan=3, padx=20, pady=20, sticky="ew")

        self.back_button = ttk.Button(self.view_songs_frame, text="Back",
                                      command=lambda: self.show_frame(self.post_login_frame))
        self.back_button.grid(row=1, column=2, padx=20, pady=20, sticky="ew")

        self.play_song_button = ttk.Button(self.view_songs_frame, text="Reproducir canción aleatoria", command=self.play_random_song)
        self.play_song_button.grid(row=1, column=1, padx=20, pady=20, sticky="ew")

    def login(self):
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()

        if not validate_username(username):
            return

        result = authenticate_user(username)
        if result:
            stored_password, salt = result
            if verify_password(stored_password, password, salt):
                messagebox.showinfo("Login", "Login successful!")
                self.current_user = username
                self.current_password = password
                self.current_salt = salt
                self.show_frame(self.post_login_frame)  # Show the new frame
            else:
                messagebox.showerror("Login", "Invalid password")
        else:
            messagebox.showerror("Login", "Invalid username or password")

    def verify_username(self):
        username = self.username_entry_login.get()

        if not validate_username(username):
            return
        result = authenticate_user(username)
        if result:
            self.show_frame(self.login_password_frame)
        else:
            messagebox.showerror("Login", "Username does not exist")

    def register(self):
        username = self.username_entry_register.get()
        email = self.email_entry.get()
        password = self.password_entry_register.get()
        repeat_password = self.repeat_password_entry_register.get()
        phone = self.phone_entry.get()
        gender = self.gender_combobox.get()
        address = self.address_entry.get()

        if not all([username, email, password, repeat_password, phone, gender, address]):
            messagebox.showerror("Register", "All fields are required")
            return

        if not validate_username(username) or not validate_password(password,
                                                                    repeat_password) or not validate_email(
                email) or not validate_phone(phone):
            return

        salt = generate_salt()
        print(salt)
        hashed_password, salt = hash_password(password, salt)
        if register_user(username, email, hashed_password, salt, phone, gender, address):
            messagebox.showinfo("Register", "You have registered successfully")
            self.show_frame(self.login_username_frame)
        else:
            messagebox.showerror("Register", "Username, email, or phone already exists")

    def insert_song(self):
        song_name = self.song_entry.get()
        author_name = self.author_entry.get()

        if not song_name or not author_name:
            messagebox.showerror("Register Song", "Song name and author/group cannot be empty.")
            return

        user_id = get_user_id(self.current_user)  # Get the authenticated user's ID

        if user_id is None:
            messagebox.showerror("Register Song", "User ID not found")
            return

        try:
            if not register_song(user_id, song_name, author_name, self.current_password, self.current_salt):
                raise ValueError("Song already exists")
            messagebox.showinfo("Register Song", "Song registered successfully.")
            # Clear the fields after registering
            self.song_entry.delete(0, tk.END)
            self.author_entry.delete(0, tk.END)
        except ValueError as e:
            messagebox.showerror("Register Song", str(e))

    def play_random_song(self):
        user_id = get_user_id(self.current_user)
        if user_id is None:
            messagebox.showerror("Play Song", "User ID not found")
            return

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_song_name, encrypted_author_name, nonce FROM songs WHERE user_id = ?',
                       (user_id,))
        songs = cursor.fetchall()
        conn.close()

        if self.current_user is not None and not songs:
            messagebox.showerror("Play Song", "No songs found")
            return

        song = random.choice(songs)
        encrypted_song_name, encrypted_author_name, nonce = song

        try:
            key = derive_key(self.current_password, self.current_salt)
            song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce)
            author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce)
            messagebox.showinfo("Play Song", f"Playing '{song_name}' by '{author_name}'")
        except Exception as e:
            messagebox.showerror("Play Song", f"Error decrypting song: {e}")


    def toggle_password_visibility(self, entry, button):
        if entry.cget('show') == '*':
            entry.config(show='')
            button.config(text='Hide Password')
        else:
            entry.config(show='*')
            button.config(text='Show Password')
        

    def send_verification_code(self):
        email = self.email_entry_recover.get()
        if not email:
            messagebox.showerror("Error", "Please enter your email")
            return

        # Retrieve the registered email for the current user from the database
        conn = create_connection()
        cursor = conn.cursor()
        user_id = self.username_entry_login.get()
        print(user_id)
        cursor.execute("SELECT email FROM users WHERE username = ?", (user_id,))
        result = cursor.fetchone()
        print(result)
        conn.close()

        if result is None:
            messagebox.showerror("Error", "User not found")
            return

        registered_email = result[0]

        # Check if the entered email matches the registered email
        if email != registered_email:
            messagebox.showerror("Error", "The entered email does not match the registered email")
            return

        # Generate a random verification code
        self.verification_code = ''.join(
            random.choices(string.ascii_uppercase + string.digits, k=6))

        # Send the verification code to the user's email
        try:
            smtp_server = 'smtp.gmail.com'  # Replace with your SMTP server address
            smtp_port = 587  # Replace with your SMTP server port
            sender_email = 'SMTP_SENDER_EMAIL'  # Replace with your email address
            sender_password = 'SMTP_SENDER_PASSWORD'

            # Create the email message
            msg = EmailMessage()
            msg['Subject'] = 'Verification Code'
            msg['From'] = sender_email
            msg['To'] = email
            msg.set_content(f"Your verification code is: {self.verification_code}")

            # Send the email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)

            messagebox.showinfo("Success", "Verification code sent to your email")
            self.hide_email_widgets()
            self.show_verification_widgets()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send email: {e}")

    def verify_code_and_change_password(self):
        entered_code = self.code_entry.get()
        new_password = self.new_password_entry.get()
        new_repeat_password = self.new_repeat_password_entry.get()
        print(new_password, new_repeat_password)

        if entered_code != self.verification_code:
            messagebox.showerror("Error", "Invalid verification code")
            return

        if not new_password or not new_repeat_password:
            messagebox.showerror("Error", "Please enter a new password")
            return

        if new_password != new_repeat_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        # Update the password in the database
        email = self.email_entry_recover.get()
        salt = generate_salt()
        hashed_password, salt = hash_password(new_password, salt)
        if update_password(email, hashed_password, salt):
            messagebox.showinfo("Success", "Password changed successfully")
            self.show_frame(self.login_password_frame)
        else:
            messagebox.showerror("Error", "Failed to change password")

    def view_songs(self):
        for item in self.songs_treeview.get_children():
            self.songs_treeview.delete(item)  # Clear the treeview

        # Fetch songs from the database
        user_id = get_user_id(self.current_user)
        if user_id is None:
            messagebox.showerror("View Songs", "User ID not found")
            return

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_song_name, encrypted_author_name, nonce FROM songs WHERE user_id = ?",
                       (user_id,))
        songs = cursor.fetchall()
        conn.close()

        # Decrypt and insert songs into the treeview
        for encrypted_song_name, encrypted_author_name, nonce in songs:
            try:
                key = derive_key(self.current_password, self.current_salt)
                song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce)
                author_name = decrypt_aes_gcm(encrypted_author_name, key, nonce)
                self.songs_treeview.insert("", "end", values=(song_name, author_name))
            except InvalidTag as e:
                messagebox.showerror("View Songs", f"Error decrypting song: {e}")

        self.show_frame(self.view_songs_frame)


def update_password(email, hashed_password, salt):
    print(f"Updating password for email: {email}")
    print(f"Hashed Password: {hashed_password}")
    print(f"Salt: {salt}")
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET hashed_password = ?, salt = ? WHERE email = ?",
                   (hashed_password, salt, email))
    conn.commit()
    conn.close()
    print(f"Rows affected: {cursor.rowcount}")
    return cursor.rowcount > 0



"""def test_aes_gcm_with_db(user_id, password, salt):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_song_name, nonce FROM songs WHERE user_id = ?', (user_id,))
    song = cursor.fetchone()
    conn.close()

    if not song:
        print("No songs found for the user.")
        return

    encrypted_song_name, nonce = song
    key = derive_key(password, salt)

    # Decrypt the song
    decrypted_song_name = decrypt_aes_gcm(encrypted_song_name, key, nonce)
    print(f"Decrypted Song: {decrypted_song_name}")

    # Encrypt the song again
    re_encrypted_song_name = encrypt_aes_gcm(decrypted_song_name, key, nonce)
    print(f"Re-encrypted Song: {re_encrypted_song_name}")

    # Verify if the re-encrypted song matches the original encrypted song
    assert re_encrypted_song_name == encrypted_song_name, "Error: The re-encrypted song does not match the original."
    print("Encryption and decryption successful.")

def test_authentication_failure_with_db(user_id, password, salt):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_song_name, nonce FROM songs WHERE user_id = ?', (user_id,))
    song = cursor.fetchone()
    conn.close()

    if not song:
        print("No songs found for the user.")
        return

    encrypted_song_name, nonce = song
    key = derive_key(password, salt)

    # Modify the encrypted song to simulate an authentication failure
    modified_encrypted_song_name = encrypted_song_name[:16] + "XXXXXX" + encrypted_song_name[22:]

    try:
        print("Attempting to decrypt the modified song...")
        decrypted_song_name = decrypt_aes_gcm(modified_encrypted_song_name, key, nonce)
        print(f"Decrypted Song: {decrypted_song_name}")
    except InvalidTag as e:
        print(f"Expected error (InvalidTag): {str(e)}")
    except Exception as e:
        print(f"Other error: {str(e)}")

# Example usage
user_id = "jorge"
password = "a"
salt = "kV2YlrkB/XTphc2zNRLqtw=="  # This should be the actual salt used for the user

test_aes_gcm_with_db(user_id, password, salt)
test_authentication_failure_with_db(user_id, password, salt)"""


if __name__ == "__main__":
    create_all_tables()
    root = tk.Tk()
    root.geometry("400x400")
    app = UserApp(root)
    root.mainloop()

