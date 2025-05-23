import tkinter as tk
from tkinter import ttk

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

        # Header frame with title, logout and start client/admin buttons
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

        # Add appropriate button based on user type
        if self.is_admin:
            # Add "Start Admin Dashboard" button for admin users
            admin_dashboard_btn = ttk.Button(
                header_frame,
                text="🔧 Start Admin Dashboard",
                command=self.start_admin_dashboard
            )
            admin_dashboard_btn.pack(side=tk.RIGHT, padx=5)

            # Also add regular client button for admin users
            if self.start_client_callback:
                start_client_btn = ttk.Button(
                    header_frame,
                    text="Start Client",
                    command=self.start_client_callback
                )
                start_client_btn.pack(side=tk.RIGHT, padx=5)
        else:
            # Add "Start Client" button for regular users
            if self.start_client_callback:
                start_client_btn = ttk.Button(
                    header_frame,
                    text="Start Client",
                    command=self.start_client_callback
                )
                start_client_btn.pack(side=tk.RIGHT, padx=5)

        logout_btn = ttk.Button(header_frame, text="Logout", command=logout_callback)
        logout_btn.pack(side=tk.RIGHT, padx=10)

    def start_admin_dashboard(self):
        """Start the standalone admin dashboard application"""
        try:
            import subprocess
            import os
            import sys

            # Save the latest config first
            if self.start_client_callback:
                # Try to call the parent's save_user_config method
                try:
                    # Navigate up to find the CredentialManagerGUI instance
                    parent = self.parent
                    while parent and not hasattr(parent, 'save_user_config'):
                        if hasattr(parent, 'master'):
                            parent = parent.master
                        else:
                            parent = None

                    # If we found the GUI instance, use its method
                    if parent and hasattr(parent, 'current_username'):
                        # This is the CredentialManagerGUI
                        gui = parent
                        # Find the actual save_user_config method
                        if hasattr(gui, 'save_user_config'):
                            gui.save_user_config(gui.current_username)
                except Exception as e:
                    print(f"Could not save config: {e}")

            # Look for admin dashboard script
            possible_paths = [
                "standalone_admin_dashboard.py",
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "standalone_admin_dashboard.py"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "standalone_admin_dashboard.py"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                             "standalone_admin_dashboard.py")
            ]

            admin_dashboard_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    admin_dashboard_path = path
                    break

            if not admin_dashboard_path:
                from tkinter import messagebox
                messagebox.showerror(
                    "Admin Dashboard Not Found",
                    "The standalone_admin_dashboard.py file was not found.\n\n"
                    "Please ensure it exists in your project directory."
                )
                return

            # Start admin dashboard process
            subprocess.Popen([sys.executable, admin_dashboard_path])

            from tkinter import messagebox
            messagebox.showinfo(
                "Admin Dashboard Started",
                "The Admin Dashboard has been launched in a new window.\n\n"
                "Use it to monitor all connected clients and network traffic."
            )
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Error", f"Failed to start admin dashboard: {str(e)}")

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