#!/usr/bin/env python3
"""
Standalone Admin Dashboard Application
This can be launched independently to monitor the packet capture network
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import sys
import threading
import time

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from proj3103.databaseV3.client.admin_dashboard import AdminDashboard
from proj3103.databaseV3.client.socket_client import StableSocketClient


class StandaloneAdminDashboard:
    """Standalone admin dashboard application"""

    def __init__(self, root):
        self.root = root
        self.root.title("Network Admin Dashboard")
        self.root.geometry("1200x800")

        # Try to load config
        self.username = None
        self.user_id = None
        self.is_admin = False
        self.environments = []
        self.load_config()

        # Socket client for server communication
        self.client = None
        self.connected = False

        # Setup UI
        self.setup_ui()

        # Setup window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start connection to server
        self.connect_to_server()

    def load_config(self):
        """Load user configuration"""
        config_paths = [
            "user_config.json",
            "client/user_config.json",
            "../client/user_config.json"
        ]

        config_path = None
        for path in config_paths:
            if os.path.exists(path):
                config_path = path
                break

        if config_path:
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)

                self.username = config.get('username', 'Unknown')
                self.user_id = config.get('user_id')

                # Check admin status
                environments = config.get('environments', [])
                for env in environments:
                    if env.get('is_admin', False):
                        self.is_admin = True
                        self.environments.append(env)

                print(f"Loaded config for user: {self.username} (Admin: {self.is_admin})")

            except Exception as e:
                print(f"Error loading config: {e}")

    def setup_ui(self):
        """Setup the UI"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Title and user info
        title_text = f"Network Admin Dashboard - {self.username}"
        if not self.is_admin:
            title_text += " (NOT ADMIN - Limited Access)"

        title_label = ttk.Label(header_frame, text=title_text,
                                font=("Helvetica", 14, "bold"))
        title_label.pack(side=tk.LEFT)

        # Connection status
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(header_frame, textvariable=self.status_var,
                                      font=("Helvetica", 10))
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # Control buttons
        control_frame = ttk.Frame(header_frame)
        control_frame.pack(side=tk.RIGHT)

        self.connect_btn = ttk.Button(control_frame, text="Connect",
                                      command=self.connect_to_server)
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        self.refresh_btn = ttk.Button(control_frame, text="Refresh Stats",
                                      command=self.request_stats, state="disabled")
        self.refresh_btn.pack(side=tk.LEFT, padx=5)

        # Create admin dashboard
        dashboard_frame = ttk.Frame(main_frame)
        dashboard_frame.pack(fill=tk.BOTH, expand=True)

        if self.is_admin:
            self.admin_dashboard = AdminDashboard(dashboard_frame, backend=self)
            self.admin_dashboard.pack(fill=tk.BOTH, expand=True)
        else:
            # Show limited access message
            msg_frame = ttk.Frame(dashboard_frame)
            msg_frame.pack(expand=True)

            ttk.Label(msg_frame, text="⚠️ Admin Access Required",
                      font=("Helvetica", 16, "bold")).pack(pady=20)

            ttk.Label(msg_frame,
                      text="You must be logged in as an admin user to access this dashboard.\n\n"
                           "Please login through the Credential Manager with an admin account.",
                      font=("Helvetica", 12)).pack(pady=10)

            ttk.Button(msg_frame, text="Open Credential Manager",
                       command=self.open_credential_manager).pack(pady=10)

    def connect_to_server(self):
        """Connect to the packet capture server"""
        if not self.is_admin:
            messagebox.showwarning("Not Admin",
                                   "You must be an admin user to connect to the server.")
            return

        # Server settings (you may want to make these configurable)
        server_host = "localhost"
        server_port = 9007

        try:
            self.update_status("Connecting...")

            # Create socket client
            self.client = StableSocketClient(server_host, server_port, self.log_message)

            # Set authentication
            account_info = {
                'user_id': self.user_id,
                'username': self.username,
                'is_admin': True
            }

            self.client.set_auth(self.environments, self.username, account_info)
            self.client.set_admin_stats_callback(self.update_admin_stats)

            # Start client
            self.client.start()

            # Wait a bit for connection
            threading.Timer(2.0, self.check_connection).start()

            self.connect_btn.config(text="Disconnect", command=self.disconnect_from_server)
            self.refresh_btn.config(state="normal")

        except Exception as e:
            self.update_status(f"Connection failed: {str(e)}")
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")

    def disconnect_from_server(self):
        """Disconnect from server"""
        if self.client:
            self.client.stop()
            self.client = None

        self.connected = False
        self.update_status("Disconnected")
        self.connect_btn.config(text="Connect", command=self.connect_to_server)
        self.refresh_btn.config(state="disabled")

    def check_connection(self):
        """Check if connection was successful"""
        if self.client and self.client.connected:
            self.connected = True
            self.update_status("Connected")
            # Request initial stats
            self.request_stats()
        else:
            self.update_status("Connection failed")

    def request_stats(self):
        """Request admin statistics from server"""
        if self.client and self.client.connected:
            self.client.request_admin_stats()
            self.log_message("Requested admin statistics")

    def update_admin_stats(self, admin_data):
        """Update admin dashboard with new data"""
        if hasattr(self, 'admin_dashboard'):
            self.admin_dashboard.update_admin_data(admin_data)

    def request_admin_stats(self):
        """Request admin stats (called by AdminDashboard)"""
        self.request_stats()

    def admin_disconnect_client(self, username):
        """Admin action to disconnect a client"""
        if self.client:
            # Send disconnect request to server
            msg = {
                'type': 'admin_disconnect',
                'target_username': username
            }
            self.client.send_packet(msg)
            self.log_message(f"Requested disconnection of user: {username}")

    def admin_clear_stats(self):
        """Admin action to clear statistics"""
        if self.client:
            msg = {
                'type': 'admin_clear_stats'
            }
            self.client.send_packet(msg)
            self.log_message("Requested clearing of all statistics")

    def update_status(self, status):
        """Update connection status display"""
        self.status_var.set(status)
        if status == "Connected":
            self.status_label.config(foreground="green")
        elif status == "Disconnected":
            self.status_label.config(foreground="red")
        else:
            self.status_label.config(foreground="orange")

    def log_message(self, message):
        """Log a message (could be enhanced with actual logging)"""
        print(f"[Admin Dashboard] {message}")

    def open_credential_manager(self):
        """Open the credential manager"""
        import subprocess
        try:
            subprocess.Popen([sys.executable, "main.py"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Credential Manager: {str(e)}")

    def on_closing(self):
        """Handle window closing"""
        if self.client:
            self.client.stop()
        self.root.destroy()


def main():
    """Main entry point"""
    root = tk.Tk()

    # Set icon if available
    try:
        root.iconbitmap('admin.ico')
    except:
        pass

    app = StandaloneAdminDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()