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

    def __init__(self, parent, username, is_admin, logout_callback, user_id, db_client, start_client_callback=None):
        self.parent = parent
        self.username = username
        self.is_admin = is_admin
        self.user_id = user_id
        self.db_client = db_client
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
        messagebox.showwarning("No Client", "Client functionality is not available.")

    def start_admin_dashboard(self):
        """Start admin dashboard with config from database_client."""
        try:
            # Check if client is authenticated
            if not self.db_client.is_authenticated():
                messagebox.showerror("Error", "Not authenticated. Please log in again.")
                return

            # Save config using database_client data
            try:
                config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "client")
                os.makedirs(config_dir, exist_ok=True)

                # Get environments from database client
                environments = self.db_client.get_environments()
                if environments is None:
                    environments = []

                config_data = {
                    "username": self.db_client.username,
                    "user_id": self.db_client.user_id,
                    "is_admin": self.db_client.is_admin,
                    "server_host": self.db_client.host,
                    "server_port": self.db_client.port,
                    "session_token": self.db_client.session_token,
                    "environments": environments
                }

                with open(os.path.join(config_dir, "user_config.json"), "w") as f:
                    json.dump(config_data, f, indent=2)
            except Exception as e:
                # Log the error but continue - config save is optional
                print(f"Warning: Could not save config: {e}")

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

            # Success message
            messagebox.showinfo("Success", f"Admin Dashboard started for {self.db_client.username}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start admin dashboard: {e}")

    def create_notebook(self):
        """Create the tabbed interface using database_client."""
        notebook = ttk.Notebook(self.frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # My Environments tab (for all users) - pass refresh callback
        my_environments_frame = ttk.Frame(notebook)
        notebook.add(my_environments_frame, text="My Environments")
        self.my_environments_tab = MyEnvironmentsTab(my_environments_frame, self.db_client.user_id, self.db_client)

        # Create Admin tab if user is admin
        if self.db_client.is_admin:
            admin_frame = ttk.Frame(notebook)
            notebook.add(admin_frame, text="Admin Console")
            self.admin_console_tab = AdminConsoleTab(admin_frame, self.db_client.user_id, self.db_client)

        # Join Environment tab (for all users) - pass refresh callback
        join_frame = ttk.Frame(notebook)
        notebook.add(join_frame, text="Join Environment")
        self.join_environment_tab = JoinEnvironmentTab(
            join_frame,
            self.db_client.user_id,
            self.db_client,
            on_join_success=self.refresh_all_tabs
        )

    def refresh_all_tabs(self):
        """Refresh all tabs after environment changes using database_client."""
        try:
            # Refresh My Environments tab
            if hasattr(self, 'my_environments_tab'):
                self.my_environments_tab.populate_user_environments()

            # Refresh Admin Console tab if it exists
            if hasattr(self, 'admin_console_tab'):
                self.admin_console_tab.populate_admin_environments()

            # Refresh Join Environment tab
            if hasattr(self, 'join_environment_tab'):
                self.join_environment_tab.populate_available_environments()

        except Exception as e:
            print(f"Error refreshing tabs: {e}")