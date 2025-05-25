import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import json
import subprocess

from proj3103.databaseV3.gui.environment_frames import (
    MyEnvironmentsTab,
    AdminConsoleTab,
    JoinEnvironmentTab
)


class DashboardFrame:
    """Main dashboard frame after login."""

    def __init__(self, parent, username, is_admin, logout_callback, user_id, db, start_client_callback=None):
        self.parent = parent
        self.username = username
        self.is_admin = is_admin
        self.user_id = user_id
        self.db = db
        self.start_client_callback = start_client_callback

        # Create the main dashboard frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Header frame with title, logout and start client button
        self.create_header(logout_callback)

        # Create tabbed interface
        self.create_notebook()

    def create_header(self, logout_callback):
        """Create the header with welcome message and buttons."""
        header_frame = ttk.Frame(self.frame)
        header_frame.pack(fill=tk.X, pady=5)

        welcome_label = ttk.Label(
            header_frame,
            text=f"Welcome, {self.username}! {'(Admin)' if self.is_admin else ''}",
            font=("Helvetica", 14, "bold")
        )
        welcome_label.pack(side=tk.LEFT, padx=10)

        # Single "Start Client" button that behaves differently based on admin status
        if self.is_admin:
            # For admin users, "Start Client" opens the admin dashboard
            start_client_btn = ttk.Button(
                header_frame,
                text="Admin Dashboard",
                command=self.start_admin_dashboard
            )
        else:
            # For regular users, "Start Client" opens the regular client
            start_client_btn = ttk.Button(
                header_frame,
                text="Start Client",
                command=self.start_client_callback if self.start_client_callback else self.no_client_callback
            )

        start_client_btn.pack(side=tk.RIGHT, padx=5)

        logout_btn = ttk.Button(header_frame, text="Logout", command=logout_callback)
        logout_btn.pack(side=tk.RIGHT, padx=10)

    def no_client_callback(self):
        """Fallback when no client callback is provided."""
        from tkinter import messagebox
        messagebox.showwarning("No Client", "Client functionality is not available.")

    def start_admin_dashboard(self):
        """Simplified version that just starts the dashboard without excessive config warnings"""
        try:
            # Quick config save attempt (without warnings if it fails)
            try:
                config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "client")
                os.makedirs(config_dir, exist_ok=True)

                config_data = {
                    "username": self.username,
                    "user_id": self.user_id,
                    "environments": getattr(self, 'db', None) and self.db.get_user_environments(self.user_id) or []
                }

                with open(os.path.join(config_dir, "user_config.json"), "w") as f:
                    json.dump(config_data, f, indent=2)
            except:
                pass  # Silently ignore config save errors

            # Find and start admin dashboard
            current_dir = os.path.dirname(os.path.abspath(__file__))

            # Common locations to check
            locations = [
                os.path.join(current_dir, "..", "admin", "standalone_admin_dashboard.py"),
                os.path.join(current_dir, "..", "..", "admin", "standalone_admin_dashboard.py"),
                os.path.join(current_dir, "standalone_admin_dashboard.py"),
                "standalone_admin_dashboard.py"
            ]

            dashboard_path = None
            for loc in locations:
                abs_path = os.path.abspath(loc)
                if os.path.exists(abs_path):
                    dashboard_path = abs_path
                    break

            if not dashboard_path:
                messagebox.showerror("Error", "Admin dashboard script not found.")
                return

            # Start the dashboard
            subprocess.Popen([sys.executable, dashboard_path])

            # Simple success message
            messagebox.showinfo("Success", f"Admin Dashboard started for {self.username}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start admin dashboard: {e}")


    def create_notebook(self):
        """Create the tabbed interface."""
        notebook = ttk.Notebook(self.frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # My Environments tab (for all users)
        my_environments_frame = ttk.Frame(notebook)
        notebook.add(my_environments_frame, text="My Environments")
        MyEnvironmentsTab(my_environments_frame, self.user_id, self.db)

        # Create Admin tab if user is admin
        if self.is_admin:
            admin_frame = ttk.Frame(notebook)
            notebook.add(admin_frame, text="Admin Console")
            AdminConsoleTab(admin_frame, self.user_id, self.db)

        # Join Environment tab (for all users)
        join_frame = ttk.Frame(notebook)
        notebook.add(join_frame, text="Join Environment")
        JoinEnvironmentTab(join_frame, self.user_id, self.db)