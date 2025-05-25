#!/usr/bin/env python3
"""
Standalone Admin Dashboard - Fixed version with proper backend integration
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os
import json
import argparse
import threading
import time


def setup_imports():
    """Setup import paths to find the required modules"""
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Possible locations for the required modules
    possible_dirs = [
        current_dir,  # Same directory
        os.path.join(current_dir, ".."),  # Parent directory
        os.path.join(current_dir, "../client"),  # client subdirectory
        os.path.join(current_dir, "../../client"),  # ../client from databaseV3
        os.path.join(current_dir, "../../../client"),  # ../client from deeper nesting
        os.path.dirname(current_dir),  # Parent directory
        os.path.join(os.path.dirname(current_dir), "client"),  # parent/client
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
AdminDashboard = None
AdminDashboardBackend = None

try:
    print("[DEBUG] Attempting imports...")
    from admin_dashboard import AdminDashboard

    print("  ✓ Successfully imported AdminDashboard")
except ImportError as e:
    print(f"  ✗ Failed to import AdminDashboard: {e}")

try:
    from capture_backend import AdminDashboardBackend

    print("  ✓ Successfully imported AdminDashboardBackend")
except ImportError as e:
    print(f"  ✗ Failed to import AdminDashboardBackend: {e}")
    # Try alternative import
    try:
        from capture_backend import OptimizedPacketCaptureBackend


        class AdminDashboardBackend(OptimizedPacketCaptureBackend):
            """Backend specifically for admin dashboard connections"""

            def __init__(self, ui=None):
                super().__init__(ui, is_admin_dashboard=True)


        print("  ✓ Created AdminDashboardBackend from OptimizedPacketCaptureBackend")
    except ImportError as e2:
        print(f"  ✗ Failed to import OptimizedPacketCaptureBackend: {e2}")

print()


class SimpleAdminDashboard:
    """Simple admin dashboard with proper backend integration"""

    def __init__(self, root, server_host="localhost", server_port=9007):
        self.root = root
        self.root.title("Network Admin Dashboard")
        self.root.geometry("1000x700")

        self.server_host = server_host
        self.server_port = server_port
        self.backend = None
        self.dashboard = None
        self.connected = False

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

        # Server info
        server_info = ttk.Label(
            controls_frame,
            text=f"Server: {self.server_host}:{self.server_port}",
            font=("Arial", 9)
        )
        server_info.pack(side=tk.LEFT, padx=5)

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
                self.dashboard = AdminDashboard(content_frame, backend=None)
                self.dashboard.pack(fill=tk.BOTH, expand=True)
                print("[DEBUG] Real admin dashboard loaded successfully")
            except Exception as e:
                print(f"[ERROR] Failed to create real dashboard: {e}")
                self.create_fallback_dashboard(content_frame)
        else:
            # Create fallback dashboard
            self.create_fallback_dashboard(content_frame)

        # Status bar
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_text = ttk.Label(self.status_bar, text="Ready")
        self.status_text.pack(side=tk.LEFT, padx=5, pady=2)

    def create_fallback_dashboard(self, parent):
        """Create a simple fallback dashboard"""
        print("[DEBUG] Creating fallback dashboard")

        # Notebook for tabs
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Status tab
        status_frame = ttk.Frame(notebook)
        notebook.add(status_frame, text="Status")

        # Status info
        status_info = ttk.LabelFrame(status_frame, text="System Status", padding="10")
        status_info.pack(fill=tk.X, pady=5)

        ttk.Label(status_info, text="⚠️ Limited Dashboard Mode",
                  font=("Arial", 12, "bold")).pack(anchor=tk.W)
        ttk.Label(status_info, text="Some modules could not be loaded.").pack(anchor=tk.W)
        ttk.Label(status_info, text="Check the console for detailed error messages.").pack(anchor=tk.W)

        # Connection info
        conn_frame = ttk.LabelFrame(status_frame, text="Connection Info", padding="10")
        conn_frame.pack(fill=tk.X, pady=5)

        ttk.Label(conn_frame, text=f"Server: {self.server_host}:{self.server_port}").pack(anchor=tk.W)
        if self.username:
            ttk.Label(conn_frame, text=f"User: {self.username}").pack(anchor=tk.W)

        # Help tab
        help_frame = ttk.Frame(notebook)
        notebook.add(help_frame, text="Help")

        help_text = tk.Text(help_frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(help_frame, orient="vertical", command=help_text.yview)
        help_text.configure(yscrollcommand=scrollbar.set)

        help_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        help_content = """
TROUBLESHOOTING GUIDE

This dashboard is running in limited mode because some required modules could not be loaded.

COMMON ISSUES:

1. Missing Python modules:
   - Make sure admin_dashboard.py exists in the same directory or client/ directory
   - Make sure capture_backend.py exists in the same directory or client/ directory
   - Make sure socket_client.py exists in the same directory or client/ directory

2. Import path issues:
   - Check the console output for which paths were searched
   - Copy the required files to the same directory as this script

3. Server connection issues:
   - Make sure the packet capture server is running
   - Check that the server host and port are correct
   - Verify admin credentials in user_config.json

4. Admin permissions:
   - Make sure your user has admin privileges
   - Check the environments configuration in user_config.json

TO FIX:
1. Copy admin_dashboard.py, capture_backend.py, and socket_client.py to this directory
2. Create or update user_config.json with admin credentials
3. Restart the dashboard

CONFIGURATION FILE (user_config.json):
{
    "username": "AdminUser",
    "user_id": "admin_001", 
    "environments": [
        {
            "env_name": "default",
            "env_password": "admin_password",
            "is_admin": true
        }
    ]
}
        """

        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)

    def load_admin_config(self):
        """Try to load admin configuration from user_config.json"""
        config_paths = [
            "user_config.json",
            os.path.join(os.path.dirname(__file__), "user_config.json"),
            os.path.join(os.path.dirname(__file__), "..", "user_config.json"),
            os.path.join(os.path.dirname(__file__), "..", "client", "user_config.json"),
            os.path.join(os.path.dirname(__file__), "..", "..", "client", "user_config.json"),
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
                        self.update_status(f"Loaded admin config for: {self.username}")
                        return

                except Exception as e:
                    print(f"[ERROR] Error loading config from {abs_path}: {e}")

        print("[DEBUG] No admin config found. Using default credentials.")
        self.username = "AdminUser"
        self.environments = [{'env_name': 'default', 'env_password': 'admin_pass', 'is_admin': True}]
        self.account_info = {
            "username": self.username,
            "is_admin": True
        }
        self.update_status("Using default admin credentials")

    def update_status(self, message):
        """Update the status bar"""
        if hasattr(self, 'status_text'):
            self.status_text.config(text=message)
        print(f"[STATUS] {message}")

    def connect_to_server(self):
        """Connect to the packet capture server"""
        if not AdminDashboardBackend:
            error_msg = "AdminDashboardBackend not available. Cannot connect to server.\nCheck console for import errors."
            messagebox.showerror("Error", error_msg)
            self.update_status("Connection failed - Missing backend")
            return

        try:
            self.update_status("Connecting to server...")

            # Create backend with admin dashboard flag
            self.backend = AdminDashboardBackend(ui=self)

            # Configure the backend
            self.backend.configure(
                server_host=self.server_host,
                server_port=self.server_port,
                username=self.username,
                environments=self.environments,
                account_info=self.account_info
            )

            # Set admin callback if dashboard supports it
            if self.dashboard and hasattr(self.dashboard, 'update_admin_data'):
                self.backend.set_admin_stats_callback(self.dashboard.update_admin_data)
                print("[DEBUG] Admin stats callback set")

            # Connect to server in a separate thread to avoid blocking UI
            def connect_thread():
                try:
                    self.backend.start()

                    # Wait a moment for connection to establish
                    time.sleep(1)

                    if hasattr(self.backend, 'connected') and self.backend.connected:
                        self.root.after(0, self.connection_success)
                    else:
                        # Try to check if client is connected
                        if hasattr(self.backend, 'client') and self.backend.client:
                            if hasattr(self.backend.client, 'connected') and self.backend.client.connected:
                                self.root.after(0, self.connection_success)
                            else:
                                self.root.after(0, lambda: self.connection_failed("Client connection not established"))
                        else:
                            self.root.after(0, lambda: self.connection_failed("Backend client not created"))

                except Exception as e:
                    self.root.after(0, lambda: self.connection_failed(str(e)))

            thread = threading.Thread(target=connect_thread, daemon=True)
            thread.start()

        except Exception as e:
            self.connection_failed(str(e))

    def connection_success(self):
        """Handle successful connection"""
        self.connected = True

        # Update UI
        self.status_var.set("Connected")
        self.status_label.config(foreground="green")
        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="disabled")  # Keep disabled until we verify connection

        self.update_status(f"Connected to {self.server_host}:{self.server_port}")
        print(f"[DEBUG] Connected to server {self.server_host}:{self.server_port}")

        # Enable disconnect button after a short delay
        self.root.after(2000, lambda: self.disconnect_btn.config(state="normal"))

        # Start requesting admin stats if dashboard supports it
        if self.dashboard and hasattr(self.dashboard, 'update_admin_data'):
            self.start_admin_stats_updates()

    def connection_failed(self, error_msg):
        """Handle connection failure"""
        full_error = f"Failed to connect to server: {error_msg}"
        print(f"[ERROR] {full_error}")
        messagebox.showerror("Connection Error", full_error)

        self.status_var.set("Connection Failed")
        self.status_label.config(foreground="red")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")

        self.update_status("Connection failed")

    def start_admin_stats_updates(self):
        """Start periodic admin stats updates"""

        def request_stats():
            while self.connected and self.backend:
                try:
                    if hasattr(self.backend, 'request_admin_stats'):
                        self.backend.request_admin_stats()
                    time.sleep(5)  # Request every 5 seconds
                except Exception as e:
                    print(f"[ERROR] Error requesting admin stats: {e}")
                    break

        stats_thread = threading.Thread(target=request_stats, daemon=True)
        stats_thread.start()

    def disconnect_from_server(self):
        """Disconnect from the server"""
        self.connected = False

        if self.backend:
            try:
                self.backend.stop()
            except Exception as e:
                print(f"[ERROR] Error stopping backend: {e}")
            self.backend = None

        # Update UI
        self.status_var.set("Disconnected")
        self.status_label.config(foreground="red")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")

        self.update_status("Disconnected from server")
        print("[DEBUG] Disconnected from server")

    def log_message(self, message):
        """Log message (for backend compatibility)"""
        print(f"[LOG] {message}")
        self.update_status(message)

    def update_admin_stats(self, admin_data):
        """Update admin dashboard with new data (fallback method)"""
        if self.dashboard and hasattr(self.dashboard, 'update_admin_data'):
            self.dashboard.update_admin_data(admin_data)
        else:
            print(f"[ADMIN_STATS] Received admin data: {admin_data}")

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