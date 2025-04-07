import tkinter as tk
from tkinter import ttk


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


class LoginFrame:
    """Frame for user login."""

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

        # Password field
        password_frame = ttk.Frame(self.frame)
        password_frame.pack(fill=tk.X, pady=5)

        password_label = ttk.Label(password_frame, text="Password:", width=15)
        password_label.pack(side=tk.LEFT, padx=5)

        self.password_entry = ttk.Entry(password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Buttons frame
        buttons_frame = ttk.Frame(self.frame)
        buttons_frame.pack(pady=20)

        back_btn = ttk.Button(buttons_frame, text="Back", command=back_callback, width=10)
        back_btn.pack(side=tk.LEFT, padx=5)

        login_btn = ttk.Button(
            buttons_frame,
            text="Login",
            command=self.trigger_login,
            width=10
        )
        login_btn.pack(side=tk.LEFT, padx=5)

    def trigger_login(self):
        """Trigger the login callback with current entries."""
        self.login_callback(self.username_entry.get(), self.password_entry.get())


class RegisterFrame:
    """Frame for user registration."""

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

        # Password field
        password_frame = ttk.Frame(self.frame)
        password_frame.pack(fill=tk.X, pady=5)

        password_label = ttk.Label(password_frame, text="Password:", width=17)
        password_label.pack(side=tk.LEFT, padx=5)

        self.password_entry = ttk.Entry(password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Confirm Password field
        confirm_frame = ttk.Frame(self.frame)
        confirm_frame.pack(fill=tk.X, pady=5)

        confirm_label = ttk.Label(confirm_frame, text="Confirm Password:", width=17)
        confirm_label.pack(side=tk.LEFT, padx=5)

        self.confirm_entry = ttk.Entry(confirm_frame, show="*", width=30)
        self.confirm_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

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

        register_btn = ttk.Button(
            buttons_frame,
            text="Register",
            command=self.trigger_register,
            width=10
        )
        register_btn.pack(side=tk.LEFT, padx=5)

    def trigger_register(self):
        """Trigger the register callback with current entries."""
        self.register_callback(
            self.username_entry.get(),
            self.password_entry.get(),
            self.confirm_entry.get(),
            self.is_admin_var.get()
        )