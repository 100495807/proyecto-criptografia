import re
from tkinter import messagebox

def validate_username(username):
    if len(username) < 3 or len(username) > 20 or not re.match(r"^\w+$", username):
        messagebox.showerror("Validation Error", "Invalid username")
        return False
    return True

def validate_password(password, repeat_password):
    if password != repeat_password:
        messagebox.showerror("Validation Error", "Passwords do not match")
        return False
    if len(password) < 9 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*()]", password):
        messagebox.showerror("Validation Error", "Password must be at least 9 characters long and contain an uppercase letter, a lowercase letter, a number, and a special character")
        return False
    return True

def validate_email(email):
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        messagebox.showerror("Validation Error", "Invalid email format")
        return False
    return True

def validate_phone(phone):
    number_pattern = r"^[0-9]+$"
    if not re.match(number_pattern, phone):
        messagebox.showerror("Validation Error", "Invalid phone number")
        return False
    return True
