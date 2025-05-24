#!/usr/bin/env python3
"""
Standalone Admin Dashboard - Fixed import version
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

        # Try to load user config for admin credentials
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

        help_content = """
TROUBLESHOOTING ADMIN DASHBOARD:

1. MISSING MODULES:
   - Make sure admin_dashboard.py is in the same directory
   - Check that capture_backend.py exists
   - Verify socket_client.py is available

2. FILE LOCATIONS CHECKED:
   - Current directory: """ + os.path.dirname(os.path.abspath(__file__)) + """
   - Client subdirectory
   - Parent directories

3. IMPORT PATHS TRIED:
""" + "\n".join([f"   - {path}" for path in sys.path[:5]]) + """

4. TO FIX:
   - Copy all required .py files to the same directory as this script
   - Or run from the correct directory where all files exist
   - Or use: python admin_client.py --dashboard-only

5. ALTERNATIVE COMMANDS:
   python admin_client.py --config user_config.json --dashboard-only
   python admin_client.py --force-admin
        """

        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)

    def load_admin_config(self):
        """Try to load admin configuration from user_config.json"""
        config_paths = [
            "user_config.json",
            os.path.join("../../client", "user_config.json"),
            os.path.join("../../..", "client", "user_config.json"),
            os.path.join(os.path.dirname(__file__), "user_config.json"),
            os.path.join(os.path.dirname(__file__), "../../..", "user_config.json"),
        ]

        for config_path in config_paths:
            abs_path = os.path.abspath(config_path)
            if os.path.exists(abs_path):
                try:
                    print(f"[DEBUG] Loading config from: {abs_path}")
                    with open(abs_path, 'r') as f:
                        config = json.load(f)

                    self.username = config.get('username')
                    user_id = config.get('user_id')
                    environments = config.get('environments', [])

                    # Check if user is admin
                    is_admin = False
                    for env in environments:
                        if env.get('is_admin', False):
                            is_admin = True
                            break

                    if is_admin:
                        self.environments = environments
                        self.account_info = {
                            "user_id": user_id,
                            "username": self.username,
                            "is_admin": True
                        }

                        # Update window title with username
                        self.root.title(f"Network Admin Dashboard - {self.username}")

                        print(f"[DEBUG] Loaded admin config for user: {self.username}")
                        return

                except Exception as e:
                    print(f"[ERROR] Error loading config from {abs_path}: {e}")

        print("[DEBUG] No admin config found. Using default credentials.")
        self.username = "AdminUser"
        self.environments = [{'env_name': 'default', 'env_password': 'admin_pass'}]
        self.account_info = {
            "username": self.username,
            "is_admin": True
        }

    def connect_to_server(self):
        """Connect to the packet capture server"""
        if not AdminDashboardBackend:
            messagebox.showerror("Error", "AdminDashboardBackend not available. Cannot connect to server.")
            return

        try:
            # Create backend with admin dashboard flag
            self.backend = AdminDashboardBackend()

            # Configure the backend
            self.backend.configure(
                server_host=self.server_host,
                server_port=self.server_port,
                username=self.username,
                environments=self.environments,
                account_info=self.account_info
            )

            # Set admin callback
            if self.dashboard and hasattr(self.dashboard, 'update_admin_data'):
                self.backend.set_admin_stats_callback(self.dashboard.update_admin_data)

            # Connect to server
            self.backend.start()

            # Update UI
            self.status_var.set("Connected")
            self.status_label.config(foreground="green")
            self.connect_btn.config(state="disabled")
            self.disconnect_btn.config(state="normal")

            print(f"[DEBUG] Connected to server {self.server_host}:{self.server_port}")

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