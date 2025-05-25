#!/usr/bin/env python3
"""
Standalone Admin Dashboard - Fixed version with proper credential detection
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os
import json
import argparse


def setup_imports():
    """Setup import paths to find the required modules"""
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Possible locations for the required modules
    possible_dirs = [
        current_dir,  # Same directory
        os.path.join(current_dir, "../../client"),  # client subdirectory
        os.path.join(current_dir, "../../..", "client"),  # ../client
        os.path.dirname(current_dir),  # Parent directory
        os.path.join(os.path.dirname(current_dir), "../../client"),  # parent/client
        os.path.join(current_dir, ".."),  # databaseV3 subdirectory
        os.path.join(current_dir, "../../..", "databaseV3"),  # ../databaseV3
    ]

    print(f"[DEBUG] Looking for modules in:")
    for i, path in enumerate(possible_dirs):
        abs_path = os.path.abspath(path)
        exists = os.path.exists(abs_path)
        print(f"  {i + 1}. {'✓' if exists else '✗'} {abs_path}")

        if exists and abs_path not in sys.path:
            sys.path.insert(0, abs_path)
            print(f"       Added to Python path")

    print()


def check_required_files():
    """Check if required files exist and can be imported"""
    required_files = [
        'admin_dashboard.py',
        'capture_backend.py',
        'socket_client.py'
    ]

    print("[DEBUG] Checking for required files:")
    found_files = {}

    for file_name in required_files:
        found = False
        for path in sys.path:
            file_path = os.path.join(path, file_name)
            if os.path.exists(file_path):
                print(f"  ✓ Found {file_name} at {file_path}")
                found_files[file_name] = file_path
                found = True
                break

        if not found:
            print(f"  ✗ Missing {file_name}")

    return found_files


# Setup imports before trying to import modules
setup_imports()
required_files = check_required_files()

# Try to import required modules
try:
    print("[DEBUG] Attempting imports...")
    from admin_dashboard import AdminDashboard

    print("  ✓ Successfully imported AdminDashboard")
except ImportError as e:
    print(f"  ✗ Failed to import AdminDashboard: {e}")
    AdminDashboard = None

try:
    from capture_backend import AdminDashboardBackend

    print("  ✓ Successfully imported AdminDashboardBackend")
except ImportError as e:
    print(f"  ✗ Failed to import AdminDashboardBackend: {e}")
    AdminDashboardBackend = None

print()


class AdminLoginDialog:
    """Dialog for admin credentials if auto-detection fails"""

    def __init__(self, parent):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Admin Login")
        self.dialog.geometry("400x300")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (300 // 2)
        self.dialog.geometry(f"400x300+{x}+{y}")

        self.setup_ui()

    def setup_ui(self):
        """Setup the login dialog UI"""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Admin Login Required",
                                font=("Helvetica", 14, "bold"))
        title_label.pack(pady=(0, 20))

        # Info text
        info_text = ttk.Label(main_frame,
                              text="No admin credentials found automatically.\nPlease enter your admin credentials:",
                              justify=tk.CENTER)
        info_text.pack(pady=(0, 20))

        # Form frame
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill=tk.X, pady=(0, 20))

        # Username
        ttk.Label(form_frame, text="Username:").pack(anchor=tk.W)
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(form_frame, textvariable=self.username_var, width=30)
        username_entry.pack(fill=tk.X, pady=(5, 10))
        username_entry.focus()

        # Environment
        ttk.Label(form_frame, text="Environment:").pack(anchor=tk.W)
        self.env_var = tk.StringVar(value="default")
        env_entry = ttk.Entry(form_frame, textvariable=self.env_var, width=30)
        env_entry.pack(fill=tk.X, pady=(5, 10))

        # Environment password
        ttk.Label(form_frame, text="Environment Password:").pack(anchor=tk.W)
        self.env_pass_var = tk.StringVar()
        env_pass_entry = ttk.Entry(form_frame, textvariable=self.env_pass_var,
                                   show="*", width=30)
        env_pass_entry.pack(fill=tk.X, pady=(5, 20))

        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.pack(fill=tk.X)

        ttk.Button(button_frame, text="Login",
                   command=self.login_clicked).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel",
                   command=self.cancel_clicked).pack(side=tk.RIGHT)

        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.login_clicked())

    def login_clicked(self):
        """Handle login button click"""
        username = self.username_var.get().strip()
        env_name = self.env_var.get().strip()
        env_pass = self.env_pass_var.get().strip()

        if not username:
            messagebox.showerror("Error", "Username is required")
            return

        if not env_name:
            messagebox.showerror("Error", "Environment name is required")
            return

        self.result = {
            'username': username,
            'environments': [{'env_name': env_name, 'env_password': env_pass}],
            'account_info': {
                'username': username,
                'is_admin': True
            }
        }

        self.dialog.destroy()

    def cancel_clicked(self):
        """Handle cancel button click"""
        self.result = None
        self.dialog.destroy()


class SimpleAdminDashboard:
    """Simple admin dashboard with fallback UI"""

    def __init__(self, root, server_host="localhost", server_port=9007):
        self.root = root
        self.root.title("Network Admin Dashboard")
        self.root.geometry("1000x700")

        self.server_host = server_host
        self.server_port = server_port
        self.backend = None
        self.dashboard = None

        # Admin credentials
        self.username = None
        self.environments = []
        self.account_info = None

        self.setup_ui()
        self.load_admin_config()

    def setup_ui(self):
        """Setup the main UI"""
        # Header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=5)

        # Title
        title_label = ttk.Label(
            header_frame,
            text="Network Admin Dashboard",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)

        # Connection controls
        controls_frame = ttk.Frame(header_frame)
        controls_frame.pack(side=tk.RIGHT)

        # User info
        self.user_var = tk.StringVar(value="No User")
        self.user_label = ttk.Label(controls_frame, textvariable=self.user_var,
                                    font=("Arial", 10, "italic"))
        self.user_label.pack(side=tk.LEFT, padx=10)

        # Connection status
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(controls_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT, padx=5)

        # Connect button
        self.connect_btn = ttk.Button(
            controls_frame,
            text="Connect",
            command=self.connect_to_server
        )
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        # Disconnect button
        self.disconnect_btn = ttk.Button(
            controls_frame,
            text="Disconnect",
            command=self.disconnect_from_server,
            state="disabled"
        )
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)

        # Main content frame
        content_frame = ttk.Frame(self.root)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        if AdminDashboard:
            # Use real admin dashboard
            try:
                self.dashboard = AdminDashboard(content_frame)
                self.dashboard.pack(fill=tk.BOTH, expand=True)
                print("[DEBUG] Real admin dashboard loaded successfully")
            except Exception as e:
                print(f"[ERROR] Failed to create real dashboard: {e}")
                self.create_fallback_dashboard(content_frame)
        else:
            # Create fallback dashboard
            self.create_fallback_dashboard(content_frame)

    def create_fallback_dashboard(self, parent):
        """Create a simple fallback dashboard"""
        print("[DEBUG] Creating fallback dashboard")

        # Status info
        status_frame = ttk.LabelFrame(parent, text="System Status", padding="10")
        status_frame.pack(fill=tk.X, pady=5)

        ttk.Label(status_frame, text="⚠️ Limited Dashboard Mode",
                  font=("Arial", 12, "bold")).pack(anchor=tk.W)
        ttk.Label(status_frame, text="Some modules could not be loaded.").pack(anchor=tk.W)
        ttk.Label(status_frame, text="Check the console for detailed error messages.").pack(anchor=tk.W)

        # Connection info
        conn_frame = ttk.LabelFrame(parent, text="Connection Info", padding="10")
        conn_frame.pack(fill=tk.X, pady=5)

        ttk.Label(conn_frame, text=f"Server: {self.server_host}:{self.server_port}").pack(anchor=tk.W)
        if self.username:
            ttk.Label(conn_frame, text=f"User: {self.username}").pack(anchor=tk.W)

        # Instructions
        help_frame = ttk.LabelFrame(parent, text="Troubleshooting", padding="10")
        help_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        help_text = tk.Text(help_frame, wrap=tk.WORD, height=10)
        help_text.pack(fill=tk.BOTH, expand=True)
        help_text.insert(tk.END, """
Troubleshooting Steps:

1. Ensure all required Python modules are in the correct location
2. Check that the server is running on the specified host and port
3. Verify admin credentials are correctly configured
4. Check console output for detailed error messages

If you continue to have issues:
- Try running from the main client directory
- Check file permissions
- Verify network connectivity to the server
        """)
        help_text.config(state=tk.DISABLED)

    def load_admin_config(self):
        """Try to load admin configuration from user_config.json"""
        config_paths = [
            "user_config.json",
            os.path.join(os.path.dirname(__file__), "user_config.json"),
            os.path.join(os.path.dirname(__file__), "..", "user_config.json"),
            os.path.join(os.path.dirname(__file__), "..", "..", "user_config.json"),
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "user_config.json"),
        ]

        print("[DEBUG] Searching for user_config.json...")

        for config_path in config_paths:
            abs_path = os.path.abspath(config_path)
            print(f"[DEBUG] Checking: {abs_path}")

            if os.path.exists(abs_path):
                try:
                    print(f"[DEBUG] Loading config from: {abs_path}")
                    with open(abs_path, 'r') as f:
                        config = json.load(f)

                    username = config.get('username')
                    user_id = config.get('user_id')
                    environments = config.get('environments', [])

                    print(f"[DEBUG] Config loaded - Username: {username}")
                    print(f"[DEBUG] Environments: {[env.get('env_name') for env in environments]}")

                    # Check if user has admin privileges in any environment
                    admin_environments = []
                    for env in environments:
                        if env.get('is_admin', False):
                            admin_environments.append(env)
                            print(f"[DEBUG] Found admin environment: {env.get('env_name')}")

                    if admin_environments:
                        self.username = username
                        self.environments = admin_environments
                        self.account_info = {
                            "user_id": user_id,
                            "username": username,
                            "is_admin": True
                        }

                        # Update UI
                        self.user_var.set(f"User: {username} (Admin)")
                        self.root.title(f"Network Admin Dashboard - {username}")

                        print(f"[DEBUG] Successfully loaded admin config for user: {username}")
                        return True

                    else:
                        print(f"[DEBUG] User {username} found but has no admin privileges")

                except Exception as e:
                    print(f"[ERROR] Error loading config from {abs_path}: {e}")

        print("[DEBUG] No valid admin config found.")

        # Show login dialog
        if self.prompt_for_credentials():
            return True

        return False

    def prompt_for_credentials(self):
        """Prompt user for admin credentials"""
        print("[DEBUG] Prompting for admin credentials...")

        dialog = AdminLoginDialog(self.root)
        self.root.wait_window(dialog.dialog)

        if dialog.result:
            self.username = dialog.result['username']
            self.environments = dialog.result['environments']
            self.account_info = dialog.result['account_info']

            # Update UI
            self.user_var.set(f"User: {self.username} (Admin)")
            self.root.title(f"Network Admin Dashboard - {self.username}")

            print(f"[DEBUG] Manual admin credentials set for user: {self.username}")
            return True

        print("[DEBUG] No credentials provided by user")
        return False

    def connect_to_server(self):
        """Connect to the packet capture server"""
        if not self.username:
            messagebox.showerror("Error", "No admin credentials available. Please restart and provide credentials.")
            return

        if not AdminDashboardBackend:
            messagebox.showerror("Error", "AdminDashboardBackend not available. Cannot connect to server.")
            return

        try:
            print(f"[DEBUG] Connecting as admin user: {self.username}")
            print(f"[DEBUG] Admin environments: {[env.get('env_name') for env in self.environments]}")

            # Create backend with admin dashboard flag
            self.backend = AdminDashboardBackend()

            # Configure the backend
            self.backend.configure(
                server_host=self.server_host,
                server_port=self.server_port,
                username=self.username,  # Use the actual username from config
                environments=self.environments,
                account_info=self.account_info
            )

            # Set admin callback
            if self.dashboard and hasattr(self.dashboard, 'update_admin_data'):
                self.backend.set_admin_stats_callback(self.dashboard.update_admin_data)
                print("[DEBUG] Admin stats callback set")

            # Connect to server
            self.backend.start()

            # Update UI
            self.status_var.set("Connected")
            self.status_label.config(foreground="green")
            self.connect_btn.config(state="disabled")
            self.disconnect_btn.config(state="normal")

            print(f"[DEBUG] Connected to server {self.server_host}:{self.server_port} as {self.username}")

        except Exception as e:
            error_msg = f"Failed to connect to server: {e}"
            print(f"[ERROR] {error_msg}")
            messagebox.showerror("Connection Error", error_msg)
            self.status_var.set("Connection Failed")
            self.status_label.config(foreground="red")

    def disconnect_from_server(self):
        """Disconnect from the server"""
        if self.backend:
            self.backend.stop()
            self.backend = None

        # Update UI
        self.status_var.set("Disconnected")
        self.status_label.config(foreground="red")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")

        print("[DEBUG] Disconnected from server")

    def on_closing(self):
        """Handle window closing"""
        if self.backend:
            self.disconnect_from_server()
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description='Standalone Admin Dashboard')
    parser.add_argument('--server', type=str, default="localhost", help='Server hostname or IP')
    parser.add_argument('--port', type=int, default=9007, help='Server port')
    args = parser.parse_args()

    print("=" * 60)
    print("STANDALONE ADMIN DASHBOARD")
    print("=" * 60)
    print()

    # Create root window
    root = tk.Tk()

    # Create and run the dashboard
    app = SimpleAdminDashboard(root, args.server, args.port)

    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    print(f"[DEBUG] Starting dashboard UI...")
    print(f"[DEBUG] Target server: {args.server}:{args.port}")
    print()

    # Start the main loop
    root.mainloop()


if __name__ == "__main__":
    main()