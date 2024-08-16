from cryptography.fernet import Fernet
import sqlite3
import os
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, filedialog
from PIL import Image, ImageTk

# Directory to store uploaded files
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Generate and save a key for encryption
def generate_key():
    return Fernet.generate_key()

# Load the encryption key
def load_key():
    if not os.path.exists("secret.key"):
        key = generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
    return Fernet(key)

# Encrypt data
def encrypt_data(data, fernet):
    return fernet.encrypt(data.encode()).decode()

# Decrypt data
def decrypt_data(data, fernet):
    return fernet.decrypt(data.encode()).decode()

# Initialize database
def init_db():
    conn = sqlite3.connect("social_media.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (username TEXT PRIMARY KEY, password TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages
                      (username TEXT, message TEXT, file_path TEXT)''')
    conn.commit()
    conn.close()

# Save messages to a file
def save_messages_to_file():
    conn = sqlite3.connect("social_media.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, message, file_path FROM messages")
    messages = cursor.fetchall()
    
    with open("messages.txt", "w") as file:
        for username, message, file_path in messages:
            file.write(f"{username}: {message}")
            if file_path:
                file.write(f" [File: {file_path}]")
            file.write("\n")
    
    conn.close()

# Load and display messages from the file
def display_messages():
    if os.path.exists("messages.txt"):
        with open("messages.txt", "r") as file:
            return file.read()
    else:
        return "No messages found."

# Signup function
def signup():
    username = simpledialog.askstring("Signup", "Enter username:")
    if not username:
        return
    password = simpledialog.askstring("Signup", "Enter password:", show='*')
    if not password:
        return

    encrypted_password = encrypt_data(password, fernet)
    
    conn = sqlite3.connect("social_media.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, encrypted_password))
        conn.commit()
        messagebox.showinfo("Signup", "Signup successful!")
        show_main_window()
    except sqlite3.IntegrityError:
        messagebox.showerror("Signup", "Username already exists.")
    conn.close()

# Login function
def login():
    username = simpledialog.askstring("Login", "Enter username:")
    if not username:
        return
    password = simpledialog.askstring("Login", "Enter password:", show='*')
    if not password:
        return
    
    conn = sqlite3.connect("social_media.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    
    if row:
        encrypted_password = row[0]
        if decrypt_data(encrypted_password, fernet) == password:
            messagebox.showinfo("Login", "Login successful!")
            show_main_window(username)
        else:
            messagebox.showerror("Login", "Invalid password.")
    else:
        messagebox.showerror("Login", "Username not found.")
    conn.close()

# Post a message
def post_message(username, message, file_path=None):
    if not message:
        messagebox.showwarning("Post Message", "Message cannot be empty.")
        return
    
    conn = sqlite3.connect("social_media.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (username, message, file_path) VALUES (?, ?, ?)", (username, message, file_path))
    conn.commit()
    messagebox.showinfo("Post Message", "Message posted!")
    conn.close()
    
    # Save messages to file
    save_messages_to_file()
    show_messages()

# Handle file upload
def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*"), ("PNG Files", "*.png"), ("JPEG Files", "*.jpeg;*.jpg"), ("Executable Files", "*.exe"), ("Python Files", "*.py")])
    if file_path:
        dest_path = os.path.join(UPLOAD_DIR, os.path.basename(file_path))
        os.rename(file_path, dest_path)
        return dest_path
    return None

# Post message with file support
def post_message_window():
    if not current_user:
        messagebox.showwarning("Post Message", "Please log in first.")
        return
    
    window = tk.Toplevel(main_window)
    window.title("Post Message")

    tk.Label(window, text="Post a message:").pack(pady=5)
    
    message_entry = tk.Entry(window, width=50)
    message_entry.pack(pady=5)
    
    upload_button = tk.Button(window, text="Upload File", command=lambda: upload_file_action())
    upload_button.pack(pady=5)
    
    post_button = tk.Button(window, text="Post", command=lambda: post_message_action(message_entry.get(), file_path))
    post_button.pack(pady=5)

    cancel_button = tk.Button(window, text="Cancel", command=window.destroy)
    cancel_button.pack(pady=5)

def upload_file_action():
    global file_path
    file_path = upload_file()

def post_message_action(message, file_path=None):
    post_message(current_user, message, file_path)

# Display messages in the text area
def show_messages():
    messages = display_messages()
    message_area.config(state=tk.NORMAL)
    message_area.delete(1.0, tk.END)
    message_area.insert(tk.END, messages)
    message_area.config(state=tk.DISABLED)

# Show the main window after login or signup
def show_main_window(username=None):
    global current_user
    if username:
        current_user = username
    root.withdraw()
    main_window.deiconify()

# Handle login/signup window
def show_login_signup_window():
    root.deiconify()
    main_window.withdraw()

# Initialize the application
def setup_gui():
    global fernet
    global root
    global main_window
    global message_area
    global current_user
    global logo
    global file_path

    fernet = load_key()
    init_db()
    
    # Main window setup
    main_window = tk.Tk()
    main_window.title("Social Media App")
    main_window.geometry("600x400")
    
    # Load and display the logo
    image = Image.open("logo.png")
    logo = ImageTk.PhotoImage(image)
    logo_label = tk.Label(main_window, image=logo)
    logo_label.place(x=10, y=10)  # Position logo at top-left corner

    message_area = scrolledtext.ScrolledText(main_window, width=70, height=20, wrap=tk.WORD)
    message_area.pack(pady=10)

    show_messages_button = tk.Button(main_window, text="Show Messages", command=show_messages)
    show_messages_button.pack(pady=5)
    
    post_message_button = tk.Button(main_window, text="Post Message", command=post_message_window)
    post_message_button.pack(pady=5)
    
    logout_button = tk.Button(main_window, text="Logout", command=show_login_signup_window)
    logout_button.pack(pady=5)
    
    main_window.withdraw()  # Hide main window initially

    # Root window setup
    root = tk.Tk()
    root.title("Social Media App")
    root.geometry("300x200")
    
    login_button = tk.Button(root, text="Login", command=lambda: login())
    login_button.pack(pady=5)

    signup_button = tk.Button(root, text="Signup", command=signup)
    signup_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    current_user = None
    file_path = None
    setup_gui()
