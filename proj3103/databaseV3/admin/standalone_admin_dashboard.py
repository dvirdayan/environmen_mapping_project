#!/usr/bin/env python3
"""
Unified Admin Dashboard that receives authentication from base_gui via temporary config files.
No login required - authentication is passed from the credential manager.
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sys
import os
import argparse
import threading
import time
import json
import tempfile


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
        os.path.join(current_dir, "../databaseV3"),  # For database_client
        os.path.join(current_dir, "../../databaseV3"),  # For database_client
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
        'socket_client.py',
        'database_client.py'
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
DatabaseClient = None

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
                super().__init__(ui)
                self.is_admin_dashboard_connection = True


        print("  ✓ Created AdminDashboardBackend from OptimizedPacketCaptureBackend")
    except ImportError as e2:
        print(f"  ✗ Failed to import OptimizedPacketCaptureBackend: {e2}")

try:
    from database_client import DatabaseClient

    print("  ✓ Successfully imported DatabaseClient")
except ImportError as e:
    print(f"  ✗ Failed to import DatabaseClient: {e}")
    # Try alternative import path
    try:
        from proj3103.databaseV3.database_client import DatabaseClient

        print("  ✓ Successfully imported DatabaseClient from proj3103.databaseV3")
    except ImportError as e2:
        print(f"  ✗ Failed to import DatabaseClient from proj3103.databaseV3: {e2}")

print()


class NoLoginAdminDashboard:
    """Admin dashboard that receives authentication from base_gui via temp file"""

    def __init__(self, root, config_file=None, server_host="localhost", server_port=9007):
        self.root = root
        self.root.title("Admin Dashboard - Auto Login")
        self.root.geometry("1000x700")

        self.server_host = server_host
        self.server_port = server_port
        self.config_file = config_file

        self.backend = None
        self.dashboard = None
        self.connected = False

        # Database and user info (loaded from config)
        self.username = None
        self.user_id = None
        self.environments = []
        self.account_info = None
        self.is_admin = False
        self.authenticated = False

        self.setup_ui()

        # Auto-load config and connect
        if self.config_file:
            self.root.after(100, self.load_config_and_connect)
        else:
            self.root.after(100, self.show_no_config_message)

    def setup_ui(self):
        """Setup the main UI"""
        # Header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=5)

        # Title
        title_label = ttk.Label(
            header_frame,
            text="Admin Dashboard - Auto Login from Credential Manager",
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

        # User info
        self.user_var = tk.StringVar(value="Loading...")
        self.user_label = ttk.Label(controls_frame, textvariable=self.user_var)
        self.user_label.pack(side=tk.LEFT, padx=5)

        # Connection status
        self.status_var = tk.StringVar(value="Initializing...")
        self.status_label = ttk.Label(controls_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT, padx=5)

        # Reconnect button
        self.reconnect_btn = ttk.Button(
            controls_frame,
            text="Reconnect",
            command=self.reconnect_to_server,
            state="disabled"
        )
        self.reconnect_btn.pack(side=tk.LEFT, padx=5)

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

        self.status_text = ttk.Label(self.status_bar, text="Loading configuration...")
        self.status_text.pack(side=tk.LEFT, padx=5, pady=2)

    def create_fallback_dashboard(self, parent):
        """Create a simple fallback dashboard"""
        print("[DEBUG] Creating fallback dashboard")

        # Notebook for tabs
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Status tab
        status_frame = ttk.Frame(notebook)
        notebook.add(status_frame, text="Authentication Status")

        # Authentication status
        auth_info = ttk.LabelFrame(status_frame, text="Auto Login Status", padding="10")
        auth_info.pack(fill=tk.X, pady=5)

        self.auth_status_label = ttk.Label(auth_info, text="Loading from config...",
                                           font=("Arial", 12, "bold"))
        self.auth_status_label.pack(anchor=tk.W)

        self.auth_details_label = ttk.Label(auth_info, text="Authentication passed from Credential Manager")
        self.auth_details_label.pack(anchor=tk.W)

        # System status
        system_info = ttk.LabelFrame(status_frame, text="System Status", padding="10")
        system_info.pack(fill=tk.X, pady=5)

        if not AdminDashboard:
            ttk.Label(system_info, text="⚠️ Limited Dashboard Mode",
                      font=("Arial", 12, "bold"), foreground="orange").pack(anchor=tk.W)
            ttk.Label(system_info, text="Some modules could not be loaded.").pack(anchor=tk.W)
        else:
            ttk.Label(system_info, text="✓ Full Dashboard Mode",
                      font=("Arial", 12, "bold"), foreground="green").pack(anchor=tk.W)

        # Connection info
        conn_frame = ttk.LabelFrame(status_frame, text="Server Configuration", padding="10")
        conn_frame.pack(fill=tk.X, pady=5)

        ttk.Label(conn_frame, text=f"Capture Server: {self.server_host}:{self.server_port}").pack(anchor=tk.W)

        # Environments tab
        env_frame = ttk.Frame(notebook)
        notebook.add(env_frame, text="User Environments")

        env_label = ttk.Label(env_frame, text="User Environments", font=("Arial", 12, "bold"))
        env_label.pack(pady=10)

        # Environment list
        self.env_tree = ttk.Treeview(env_frame, columns=("name", "password", "admin"), show="headings")
        self.env_tree.heading("name", text="Environment Name")
        self.env_tree.heading("password", text="Password")
        self.env_tree.heading("admin", text="Admin Rights")
        self.env_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Config info tab
        config_frame = ttk.Frame(notebook)
        notebook.add(config_frame, text="Configuration")

        config_label = ttk.Label(config_frame, text="Loaded Configuration", font=("Arial", 12, "bold"))
        config_label.pack(pady=10)

        self.config_text = tk.Text(config_frame, height=15, width=80)
        self.config_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Scrollbar for config text
        config_scroll = ttk.Scrollbar(config_frame, orient=tk.VERTICAL, command=self.config_text.yview)
        config_scroll.pack(side=tk.Right, fill=tk.Y)
        self.config_text.config(yscrollcommand=config_scroll.set)

    def show_no_config_message(self):
        """Show message when no config file is provided"""
        self.user_var.set("No config provided")
        self.status_var.set("Waiting for config")
        self.update_status("No configuration file provided. Please launch from Credential Manager.")

        if hasattr(self, 'auth_status_label'):
            self.auth_status_label.config(text="No Configuration", foreground="red")
            self.auth_details_label.config(text="Please launch this dashboard from the Credential Manager")

    def load_config_and_connect(self):
        """Load configuration from temp file and auto-connect"""
        if not self.config_file or not os.path.exists(self.config_file):
            self.show_no_config_message()
            return

        try:
            print(f"[DEBUG] Loading config from: {self.config_file}")

            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)

            # Load user data from config
            self.username = config_data.get('username', 'Unknown')
            self.user_id = config_data.get('user_id')
            self.is_admin = config_data.get('is_admin', False)
            self.environments = config_data.get('environments', [])

            # Create account info
            self.account_info = {
                "user_id": self.user_id,
                "username": self.username,
                "is_admin": self.is_admin
            }

            self.authenticated = True

            print(f"[DEBUG] Loaded user: {self.username} (Admin: {self.is_admin})")
            print(f"[DEBUG] Environments: {[env.get('env_name') for env in self.environments]}")

            # Update UI
            self.update_ui_after_config_load(config_data)

            # Auto-connect to server
            self.root.after(1000, self.connect_to_server)

        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            self.user_var.set("Config load failed")
            self.status_var.set("Error")
            self.update_status(f"Failed to load configuration: {e}")

            if hasattr(self, 'auth_status_label'):
                self.auth_status_label.config(text="Configuration Error", foreground="red")
                self.auth_details_label.config(text=f"Error: {e}")

    def update_ui_after_config_load(self, config_data):
        """Update UI after loading configuration"""
        # Update user display
        admin_text = " [ADMIN]" if self.is_admin else ""
        self.user_var.set(f"{self.username}{admin_text}")

        # Update window title
        self.root.title(f"Admin Dashboard - {self.username} (Auto Login)")

        # Enable buttons
        self.reconnect_btn.config(state="normal")

        # Update status
        self.update_status(f"Configuration loaded for {self.username} - Connecting...")

        # Update fallback dashboard if needed
        if hasattr(self, 'auth_status_label'):
            self.auth_status_label.config(text="✓ Configuration Loaded", foreground="green")
            self.auth_details_label.config(
                text=f"User: {self.username} | Environments: {len(self.environments)} | Auto-connecting...")

        # Show config in fallback dashboard
        if hasattr(self, 'config_text'):
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(1.0, json.dumps(config_data, indent=2))

        # Refresh environments display
        self.refresh_environments()

    def refresh_environments(self):
        """Refresh the environments display"""
        if not hasattr(self, 'env_tree'):
            return

        # Clear existing items
        for item in self.env_tree.get_children():
            self.env_tree.delete(item)

        # Add environments
        for env in self.environments:
            self.env_tree.insert("", "end", values=(
                env.get('env_name', ''),
                env.get('env_password', ''),
                "Yes" if env.get('is_admin', False) else "No"
            ))

    def update_status(self, message):
        """Update the status bar"""
        if hasattr(self, 'status_text'):
            self.status_text.config(text=message)
        print(f"[STATUS] {message}")

    def connect_to_server(self):
        """Connect to the packet capture server using loaded configuration"""
        if not self.authenticated:
            self.update_status("Cannot connect - No configuration loaded")
            return

        if not AdminDashboardBackend:
            error_msg = "AdminDashboardBackend not available. Cannot connect to server."
            messagebox.showerror("Error", error_msg)
            self.update_status("Connection failed - Missing backend")
            return

        try:
            self.update_status("Connecting to capture server...")
            self.status_var.set("Connecting...")

            # Create backend with admin dashboard flag
            self.backend = AdminDashboardBackend(ui=self)

            # Configure the backend with loaded authentication
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

            # Connect to server in a separate thread
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
        self.reconnect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")

        self.update_status(f"✓ Connected to server as {self.username}")
        print(f"[DEBUG] Connected to server {self.server_host}:{self.server_port}")

        # Update fallback dashboard
        if hasattr(self, 'auth_details_label'):
            self.auth_details_label.config(text=f"✓ Connected to server | User: {self.username}")

        # Start requesting admin stats if dashboard supports it
        if self.dashboard and hasattr(self.dashboard, 'update_admin_data'):
            self.start_admin_stats_updates()

    def connection_failed(self, error_msg):
        """Handle connection failure"""
        full_error = f"Failed to connect to server: {error_msg}"
        print(f"[ERROR] {full_error}")

        # Don't show popup for connection errors in auto-mode
        self.status_var.set("Connection Failed")
        self.status_label.config(foreground="red")
        self.reconnect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")

        self.update_status(f"Connection failed: {error_msg}")

    def reconnect_to_server(self):
        """Reconnect to the server"""
        if self.connected:
            self.disconnect_from_server()

        # Wait a moment then reconnect
        self.root.after(1000, self.connect_to_server)

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
        self.reconnect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")

        self.update_status("Disconnected from capture server")
        print("[DEBUG] Disconnected from capture server")

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
        if self.connected:
            self.disconnect_from_server()

        # Clean up config file if it exists
        if self.config_file and os.path.exists(self.config_file):
            try:
                os.unlink(self.config_file)
                print(f"[DEBUG] Cleaned up config file: {self.config_file}")
            except Exception as e:
                print(f"[DEBUG] Could not clean up config file: {e}")

        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description='Admin Dashboard with Auto Login from Config File')
    parser.add_argument('--config', type=str, required=True, help='Path to user config file from base_gui')
    parser.add_argument('--server', type=str, default="localhost", help='Capture server hostname or IP')
    parser.add_argument('--port', type=int, default=9007, help='Capture server port')
    args = parser.parse_args()

    print("=" * 60)
    print("ADMIN DASHBOARD - AUTO LOGIN FROM CREDENTIAL MANAGER")
    print("=" * 60)
    print()

    if not args.config:
        print("[ERROR] No config file specified. This dashboard must be launched from the Credential Manager.")
        sys.exit(1)

    if not os.path.exists(args.config):
        print(f"[ERROR] Config file not found: {args.config}")
        sys.exit(1)

    # Create root window
    root = tk.Tk()

    # Create and run the dashboard
    app = NoLoginAdminDashboard(root, args.config, args.server, args.port)

    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    print(f"[DEBUG] Starting auto-login admin dashboard...")
    print(f"[DEBUG] Config file: {args.config}")
    print(f"[DEBUG] Capture server: {args.server}:{args.port}")
    print()

    # Start the main loop
    root.mainloop()


if __name__ == "__main__":
    main()