import time
import tkinter as tk
from tkinter import ttk, messagebox
from proj3103.client_side.gui.input_validation import validate_username, validate_password, get_validation_rules



class AuthFrame:
    """Frame for selecting login or register."""

    def __init__(self, parent, login_callback, register_callback, exit_callback):
        self.parent = parent
        self.frame = ttk.Frame(parent, padding="20")
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(self.frame, text="Credential Manager", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=20)

        # Login button
        login_btn = ttk.Button(self.frame, text="Login", command=login_callback, width=20)
        login_btn.pack(pady=10)

        # Register button
        register_btn = ttk.Button(self.frame, text="Register", command=register_callback, width=20)
        register_btn.pack(pady=10)

        # Exit button
        exit_btn = ttk.Button(self.frame, text="Exit", command=exit_callback, width=20)
        exit_btn.pack(pady=10)

    def show_validation_info(self):
        """Show validation requirements to the user."""
        rules = get_validation_rules()
        info_text = "Input Requirements:\n\n"

        info_text += "Username:\n"
        info_text += f"• Length: {rules['username']['min_length']}-{rules['username']['max_length']} characters\n"
        info_text += f"• {rules['username']['allowed_chars']}\n"
        info_text += f"• {rules['username']['restrictions']}\n\n"

        info_text += "Password:\n"
        info_text += f"• Length: {rules['password']['min_length']}-{rules['password']['max_length']} characters\n"
        info_text += f"• {rules['password']['allowed_chars']}\n"
        info_text += f"• {rules['password']['restrictions']}\n\n"

        info_text += "Environment Names:\n"
        info_text += f"• Length: {rules['environment_name']['min_length']}-{rules['environment_name']['max_length']} characters\n"
        info_text += f"• {rules['environment_name']['allowed_chars']}\n"

        messagebox.showinfo("Input Requirements", info_text)


class LoginFrame:
    """Frame for user login with input validation."""

    def __init__(self, parent, login_callback, back_callback):
        self.parent = parent
        self.frame = ttk.Frame(parent, padding="20")
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.login_callback = login_callback

        # Title
        title_label = ttk.Label(self.frame, text="Login", font=("Helvetica", 14, "bold"))
        title_label.pack(pady=10)

        # Username field
        username_frame = ttk.Frame(self.frame)
        username_frame.pack(fill=tk.X, pady=5)

        username_label = ttk.Label(username_frame, text="Username:", width=15)
        username_label.pack(side=tk.LEFT, padx=5)

        self.username_entry = ttk.Entry(username_frame, width=30)
        self.username_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Bind validation on username entry
        self.username_entry.bind('<KeyRelease>', self.validate_username_input)
        self.username_entry.bind('<FocusOut>', self.validate_username_input)

        # Username validation label
        self.username_validation_label = ttk.Label(self.frame, text="", foreground="red", font=("Helvetica", 8))
        self.username_validation_label.pack(fill=tk.X, padx=20)

        # Password field
        password_frame = ttk.Frame(self.frame)
        password_frame.pack(fill=tk.X, pady=5)

        password_label = ttk.Label(password_frame, text="Password:", width=15)
        password_label.pack(side=tk.LEFT, padx=5)

        self.password_entry = ttk.Entry(password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Bind validation on password entry
        self.password_entry.bind('<KeyRelease>', self.validate_password_input)
        self.password_entry.bind('<FocusOut>', self.validate_password_input)

        # Password validation label
        self.password_validation_label = ttk.Label(self.frame, text="", foreground="red", font=("Helvetica", 8))
        self.password_validation_label.pack(fill=tk.X, padx=20)

        # Buttons frame
        buttons_frame = ttk.Frame(self.frame)
        buttons_frame.pack(pady=20)

        back_btn = ttk.Button(buttons_frame, text="Back", command=back_callback, width=10)
        back_btn.pack(side=tk.LEFT, padx=5)

        self.login_btn = ttk.Button(
            buttons_frame,
            text="Login",
            command=self.trigger_login,
            width=10
        )
        self.login_btn.pack(side=tk.LEFT, padx=5)

        # Info button
        info_btn = ttk.Button(buttons_frame, text="Requirements", command=self.show_validation_info, width=12)
        info_btn.pack(side=tk.LEFT, padx=5)

    def validate_username_input(self, event=None):
        """Validate username input in real-time."""
        username = self.username_entry.get().strip()
        if username:
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                self.username_validation_label.config(text=error_msg, foreground="red")
                return False
            else:
                self.username_validation_label.config(text="✓ Valid username", foreground="green")
                return True
        else:
            self.username_validation_label.config(text="")
            return False

    def validate_password_input(self, event=None):
        """Validate password input in real-time."""
        password = self.password_entry.get()
        if password:
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                self.password_validation_label.config(text=error_msg, foreground="red")
                return False
            else:
                self.password_validation_label.config(text="✓ Valid password", foreground="green")
                return True
        else:
            self.password_validation_label.config(text="")
            return False

    def show_validation_info(self):
        """Show validation requirements to the user."""
        rules = get_validation_rules()
        info_text = "Input Requirements:\n\n"

        info_text += "Username:\n"
        info_text += f"• Length: {rules['username']['min_length']}-{rules['username']['max_length']} characters\n"
        info_text += f"• {rules['username']['allowed_chars']}\n"
        info_text += f"• {rules['username']['restrictions']}\n\n"

        info_text += "Password:\n"
        info_text += f"• Length: {rules['password']['min_length']}-{rules['password']['max_length']} characters\n"
        info_text += f"• {rules['password']['allowed_chars']}\n"
        info_text += f"• {rules['password']['restrictions']}"
        messagebox.showinfo("Input Requirements", info_text)

    def trigger_login(self):
        """Trigger the login callback with validated entries."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        # Validate inputs before attempting login
        username_valid = self.validate_username_input()
        password_valid = self.validate_password_input()

        if not username_valid or not password_valid:
            messagebox.showerror("Validation Error", "Please fix the input errors before logging in.")
            return

        self.login_callback(username, password)


class RegisterFrame:
    """Frame for user registration with input validation."""

    def __init__(self, parent, register_callback, back_callback):
        self.parent = parent
        self.frame = ttk.Frame(parent, padding="20")
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.register_callback = register_callback

        # Title
        title_label = ttk.Label(self.frame, text="Register", font=("Helvetica", 14, "bold"))
        title_label.pack(pady=10)

        # Username field
        username_frame = ttk.Frame(self.frame)
        username_frame.pack(fill=tk.X, pady=5)

        username_label = ttk.Label(username_frame, text="Username:", width=17)
        username_label.pack(side=tk.LEFT, padx=5)

        self.username_entry = ttk.Entry(username_frame, width=30)
        self.username_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Bind validation on username entry
        self.username_entry.bind('<KeyRelease>', self.validate_username_input)
        self.username_entry.bind('<FocusOut>', self.validate_username_input)

        # Username validation label
        self.username_validation_label = ttk.Label(self.frame, text="", foreground="red", font=("Helvetica", 8))
        self.username_validation_label.pack(fill=tk.X, padx=20)

        # Password field
        password_frame = ttk.Frame(self.frame)
        password_frame.pack(fill=tk.X, pady=5)

        password_label = ttk.Label(password_frame, text="Password:", width=17)
        password_label.pack(side=tk.LEFT, padx=5)

        self.password_entry = ttk.Entry(password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Bind validation on password entry
        self.password_entry.bind('<KeyRelease>', self.validate_password_input)
        self.password_entry.bind('<FocusOut>', self.validate_password_input)

        # Password validation label
        self.password_validation_label = ttk.Label(self.frame, text="", foreground="red", font=("Helvetica", 8))
        self.password_validation_label.pack(fill=tk.X, padx=20)

        # Confirm Password field
        confirm_frame = ttk.Frame(self.frame)
        confirm_frame.pack(fill=tk.X, pady=5)

        confirm_label = ttk.Label(confirm_frame, text="Confirm Password:", width=17)
        confirm_label.pack(side=tk.LEFT, padx=5)

        self.confirm_entry = ttk.Entry(confirm_frame, show="*", width=30)
        self.confirm_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Bind validation on confirm password entry
        self.confirm_entry.bind('<KeyRelease>', self.validate_confirm_password)
        self.confirm_entry.bind('<FocusOut>', self.validate_confirm_password)

        # Confirm password validation label
        self.confirm_validation_label = ttk.Label(self.frame, text="", foreground="red", font=("Helvetica", 8))
        self.confirm_validation_label.pack(fill=tk.X, padx=20)

        # Admin checkbox
        admin_frame = ttk.Frame(self.frame)
        admin_frame.pack(fill=tk.X, pady=5)

        # Create a variable to hold the checkbox state
        self.is_admin_var = tk.BooleanVar()
        admin_checkbox = ttk.Checkbutton(admin_frame, text="Register as Admin", variable=self.is_admin_var)
        admin_checkbox.pack(side=tk.LEFT, padx=20)

        # Buttons frame
        buttons_frame = ttk.Frame(self.frame)
        buttons_frame.pack(pady=20)

        back_btn = ttk.Button(buttons_frame, text="Back", command=back_callback, width=10)
        back_btn.pack(side=tk.LEFT, padx=5)

        self.register_btn = ttk.Button(
            buttons_frame,
            text="Register",
            command=self.trigger_register,
            width=10
        )
        self.register_btn.pack(side=tk.LEFT, padx=5)

        # Info button
        info_btn = ttk.Button(buttons_frame, text="Requirements", command=self.show_validation_info, width=12)
        info_btn.pack(side=tk.LEFT, padx=5)

    def validate_username_input(self, event=None):
        """Validate username input in real-time."""
        username = self.username_entry.get().strip()
        if username:
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                self.username_validation_label.config(text=error_msg, foreground="red")
                return False
            else:
                self.username_validation_label.config(text="✓ Valid username", foreground="green")
                return True
        else:
            self.username_validation_label.config(text="")
            return False

    def validate_password_input(self, event=None):
        """Validate password input in real-time."""
        password = self.password_entry.get()
        if password:
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                self.password_validation_label.config(text=error_msg, foreground="red")
                return False
            else:
                self.password_validation_label.config(text="✓ Valid password", foreground="green")
                return True
        else:
            self.password_validation_label.config(text="")
            return False

    def validate_confirm_password(self, event=None):
        """Validate password confirmation."""
        password = self.password_entry.get()
        confirm_password = self.confirm_entry.get()

        if confirm_password:
            if password != confirm_password:
                self.confirm_validation_label.config(text="Passwords do not match", foreground="red")
                return False
            else:
                self.confirm_validation_label.config(text="✓ Passwords match", foreground="green")
                return True
        else:
            self.confirm_validation_label.config(text="")
            return False

    def show_validation_info(self):
        """Show validation requirements to the user."""
        rules = get_validation_rules()
        info_text = "Input Requirements:\n\n"

        info_text += "Username:\n"
        info_text += f"• Length: {rules['username']['min_length']}-{rules['username']['max_length']} characters\n"
        info_text += f"• {rules['username']['allowed_chars']}\n"
        info_text += f"• {rules['username']['restrictions']}\n\n"

        info_text += "Password:\n"
        info_text += f"• Length: {rules['password']['min_length']}-{rules['password']['max_length']} characters\n"
        info_text += f"• {rules['password']['allowed_chars']}\n"
        info_text += f"• {rules['password']['restrictions']}"

        messagebox.showinfo("Input Requirements", info_text)

    def trigger_register(self):
        """Trigger the register callback with validated entries."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_entry.get()

        # Validate all inputs before attempting registration
        username_valid = self.validate_username_input()
        password_valid = self.validate_password_input()
        confirm_valid = self.validate_confirm_password()

        if not username_valid or not password_valid or not confirm_valid:
            messagebox.showerror("Validation Error", "Please fix all input errors before registering.")
            return

        self.register_callback(username, password, confirm_password, self.is_admin_var.get())