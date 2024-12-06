import re
from tkinter import messagebox

class ValidateManager:
    @staticmethod
    def validate_username(username):
        if len(username) < 3 or len(username) > 20 or not re.match(r"^\w+$", username):
            messagebox.showerror("Error de Validación", "Nombre de usuario inválido")
            return False
        return True

    @staticmethod
    def validate_password(password, repeat_password):
        if password != repeat_password:
            messagebox.showerror("Error de Validación", "Las contraseñas no coinciden")
            return False
        if (len(password) < 9 or not re.search(r"[A-Z]", password)
                or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password)
                or not re.search(r"[!@#$%^&*()]", password)):
            messagebox.showerror("Error de Validación",
                                 "La contraseña debe tener al menos 9 caracteres y "
                                 "contener una letra mayúscula, "
                                 "una letra minúscula, un número y un carácter especial")
            return False
        return True

    @staticmethod
    def validate_email(email):
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, email):
            messagebox.showerror("Error de Validación",
                                 "Formato de correo electrónico inválido")
            return False
        return True

    @staticmethod
    def validate_phone(phone):
        number_pattern = r"^[0-9]+$"
        if not re.match(number_pattern, phone):
            messagebox.showerror("Error de Validación", "Número de teléfono inválido")
            return False
        return True