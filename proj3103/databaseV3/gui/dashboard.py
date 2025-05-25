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
        """Start the standalone admin dashboard application"""
        try:
            import subprocess
            import os
            import sys
            from tkinter import messagebox

            print(f"[DEBUG] Starting admin dashboard...")

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
                            print(f"[DEBUG] Config saved for user: {gui.current_username}")
                except Exception as e:
                    print(f"Could not save config: {e}")

            # Get current file directory
            current_file = os.path.abspath(__file__)
            current_dir = os.path.dirname(current_file)

            print(f"[DEBUG] Current file: {current_file}")
            print(f"[DEBUG] Current directory: {current_dir}")

            # Look for admin dashboard script in multiple locations
            possible_paths = [
                "standalone_admin_dashboard.py",  # Current working directory
                os.path.join(current_dir, "standalone_admin_dashboard.py"),  # Same dir as this file
                os.path.join(os.path.dirname(current_dir), "standalone_admin_dashboard.py"),  # Parent dir
                os.path.join(os.path.dirname(os.path.dirname(current_dir)), "standalone_admin_dashboard.py"),
                # Grandparent
                os.path.join(current_dir, "..", "standalone_admin_dashboard.py"),  # Relative parent
                os.path.join(current_dir, "..", "..", "standalone_admin_dashboard.py"),  # Relative grandparent
                os.path.join(current_dir, "..", "admin", "standalone_admin_dashboard.py"),  # admin dir
                os.path.join(os.path.dirname(current_dir), "admin", "standalone_admin_dashboard.py"),  # Parent/client
            ]

            print(f"[DEBUG] Searching for admin dashboard in paths:")
            admin_dashboard_path = None
            for i, path in enumerate(possible_paths):
                abs_path = os.path.abspath(path)
                exists = os.path.exists(abs_path)
                print(f"[DEBUG] {i + 1}. {abs_path} - {'EXISTS' if exists else 'NOT FOUND'}")

                if exists and not admin_dashboard_path:
                    admin_dashboard_path = abs_path

            if not admin_dashboard_path:
                error_msg = (
                        "The standalone_admin_dashboard.py file was not found.\n\n"
                        f"Searched in {len(possible_paths)} locations:\n" +
                        "\n".join([f"• {os.path.abspath(p)}" for p in possible_paths[:5]]) +
                        f"\n... and {len(possible_paths) - 5} more locations\n\n"
                        "Please ensure standalone_admin_dashboard.py exists in your project directory."
                )
                print(f"[ERROR] {error_msg}")
                messagebox.showerror("Admin Dashboard Not Found", error_msg)
                return

            print(f"[DEBUG] Found admin dashboard at: {admin_dashboard_path}")

            # Start admin dashboard process
            print(f"[DEBUG] Starting process: {sys.executable} {admin_dashboard_path}")
            process = subprocess.Popen([sys.executable, admin_dashboard_path])
            print(f"[DEBUG] Process started with PID: {process.pid}")

            messagebox.showinfo(
                "Admin Dashboard Started",
                f"The Admin Dashboard has been launched in a new window.\n\n"
                f"Process ID: {process.pid}\n"
                f"File: {os.path.basename(admin_dashboard_path)}\n\n"
                "Use it to monitor all connected clients and network traffic."
            )
        except FileNotFoundError as e:
            error_msg = f"Python executable not found: {e}"
            print(f"[ERROR] {error_msg}")
            messagebox.showerror("Python Not Found", error_msg)
        except subprocess.SubprocessError as e:
            error_msg = f"Failed to start subprocess: {e}"
            print(f"[ERROR] {error_msg}")
            messagebox.showerror("Subprocess Error", error_msg)
        except Exception as e:
            error_msg = f"Failed to start admin dashboard: {str(e)}"
            print(f"[ERROR] {error_msg}")
            messagebox.showerror("Error", error_msg)
            import traceback
            traceback.print_exc()

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