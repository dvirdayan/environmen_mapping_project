import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess

# Import the database class
from ..cdatabase import CredentialDatabase

# Import GUI components
from auth_frames import AuthFrame, LoginFrame, RegisterFrame
from dashboard import DashboardFrame


class CredentialManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Credential Manager")
        self.root.geometry("800x500")
        self.root.resizable(True, True)

        # Initialize database
        self.db = CredentialDatabase()

        # Current user state
        self.current_user_id = None
        self.current_username = None
        self.is_admin = False

        # Set up the main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create the initial login/register frame
        self.show_auth_frame()

        # Set up a protocol for when the window is closed
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Handle closing the application."""
        if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
            self.db.close()
            self.root.destroy()

    def clear_frame(self, frame):
        """Clear all widgets from a frame."""
        for widget in frame.winfo_children():
            widget.destroy()

    def show_auth_frame(self):
        """Display the authentication frame with login and register options."""
        self.clear_frame(self.main_frame)
        auth_frame = AuthFrame(self.main_frame, self.show_login_form, self.show_register_form, self.on_close)

    def show_login_form(self):
        """Display the login form."""
        self.clear_frame(self.main_frame)
        login_frame = LoginFrame(self.main_frame, self.login_user, self.show_auth_frame)
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: login_frame.trigger_login())

    def show_register_form(self):
        """Display the registration form."""
        self.clear_frame(self.main_frame)
        RegisterFrame(self.main_frame, self.register_user, self.show_auth_frame)

    def login_user(self, username, password):
        """Attempt to log in a user."""
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        result = self.db.authenticate_user(username, password)
        if result:
            user_id, is_admin = result
            self.current_user_id = user_id
            self.current_username = username
            self.is_admin = is_admin
            self.root.unbind('<Return>')  # Unbind the Enter key
            self.show_main_dashboard()

            # Start the client automatically if the user is not an admin
            if not is_admin:
                self.start_client()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def start_client(self):
        """Start the packet capture client in a separate process."""
        try:
            subprocess.Popen(["python", "client/client_main.py"])
            messagebox.showinfo("Client Started",
                                "The packet capture client has been started in a separate window.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start client: {str(e)}")

    def register_user(self, username, password, confirm_password, is_admin=False):
        """Register a new user."""
        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        if self.db.add_user(username, password, is_admin):
            messagebox.showinfo("Success",
                                f"User '{username}' registered successfully{' as Admin' if is_admin else ''}!")
            self.show_login_form()
        else:
            messagebox.showerror("Error", f"Username '{username}' already exists. Please choose another username.")

    def logout_user(self):
        """Log out the current user."""
        self.current_user_id = None
        self.current_username = None
        self.is_admin = False
        self.show_auth_frame()

    def show_main_dashboard(self):
        """Display the main dashboard after login."""
        self.clear_frame(self.main_frame)
        DashboardFrame(
            self.main_frame,
            self.current_username,
            self.is_admin,
            self.logout_user,
            self.current_user_id,
            self.db
        )