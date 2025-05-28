#!/usr/bin/env python3
"""
Simplified client that ensures admin dashboard is visible
"""

import tkinter as tk
from tkinter import ttk
import sys
import os
import json
import argparse

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from proj3103.client_side.client.client_dashboard import PacketCaptureClientUI
from proj3103.client_side.client.capture_backend import OptimizedPacketCaptureBackend
from admin_dashboard import AdminDashboard


class AdminEnabledClientUI(PacketCaptureClientUI):
    """Client UI with guaranteed admin dashboard"""

    def __init__(self, root, force_admin=False):
        super().__init__(root)
        self.force_admin = force_admin
        self.admin_dashboard = None

        # If force_admin is True, show admin dashboard immediately
        if self.force_admin:
            self.root.after(100, self.show_admin_dashboard_forced)

    def show_admin_dashboard_forced(self):
        """Force show the admin dashboard regardless of user status"""
        if self.admin_dashboard:
            return  # Already shown

        print("[UI] Force-showing admin dashboard...")

        # Create admin tab
        admin_frame = ttk.Frame(self.notebook)
        self.notebook.add(admin_frame, text="🔧 Admin Dashboard")

        # Create admin dashboard
        self.admin_dashboard = AdminDashboard(admin_frame, backend=self.backend)
        self.admin_dashboard.pack(fill=tk.BOTH, expand=True)

        # Make it the active tab
        self.notebook.select(admin_frame)

        self.log_message("Admin dashboard loaded (forced mode)")
        print("[UI] Admin dashboard created successfully")

    def set_backend(self, backend):
        """Override to ensure admin functionality"""
        super().set_backend(backend)

        # Check if admin based on backend
        if hasattr(backend, 'is_admin') and backend.is_admin:
            print(f"[UI] Backend reports admin status: {backend.is_admin}")
            self.is_admin = True
            # Show admin dashboard after a short delay
            self.root.after(500, self.show_admin_dashboard)

            # Set admin callback
            if hasattr(backend, 'set_admin_stats_callback'):
                backend.set_admin_stats_callback(self.update_admin_stats)
        elif self.force_admin:
            print("[UI] Admin forced via command line")
            self.is_admin = True

    def show_admin_dashboard(self):
        """Show the admin dashboard in a new tab"""
        if self.admin_dashboard:
            return  # Already shown

        print("[UI] Creating admin dashboard...")

        # Create admin tab
        admin_frame = ttk.Frame(self.notebook)
        self.notebook.add(admin_frame, text="🔧 Admin Dashboard")

        # Create admin dashboard
        self.admin_dashboard = AdminDashboard(admin_frame, backend=self.backend)
        self.admin_dashboard.pack(fill=tk.BOTH, expand=True)

        # Don't automatically switch to it
        self.log_message("Admin dashboard loaded successfully")
        print("[UI] Admin dashboard created")

        # Request initial stats if backend is available
        if self.backend:
            self.backend.request_admin_stats()

    def update_admin_stats(self, admin_data):
        """Update admin dashboard with new data"""
        if self.admin_dashboard:
            self.admin_dashboard.update_admin_data(admin_data)
        else:
            print("[UI] Admin stats received but no dashboard to display them")


class AdminDashboardBackend(OptimizedPacketCaptureBackend):
    """Backend specifically for admin dashboard - doesn't show up in client list"""

    def __init__(self, ui=None):
        super().__init__(ui)
        self.is_admin_dashboard_connection = True  # Flag this as admin dashboard

    def start(self):
        """Start admin dashboard backend - modified to use admin dashboard client"""
        if self.running:
            return

        self.running = True

        # Import socket client here to avoid circular imports
        from proj3103.client_side.client.socket_client import StableSocketClient

        # Create client with admin dashboard flag
        self.client = StableSocketClient(
            self.server_host,
            self.server_port,
            self.log,
            is_admin_dashboard=True  # NEW: Mark as admin dashboard connection
        )

        # Set admin callback if admin
        if self.is_admin and self.ui and hasattr(self.ui, 'update_admin_stats'):
            self.client.set_admin_stats_callback(self.ui.update_admin_stats)
            self.log("Admin stats callback configured")

        # Set authentication
        env_names = [env.get('env_name') for env in self.environments]
        self.log(f"Setting auth for environments: {env_names} as user: {self.username} (Admin Dashboard)")
        self.client.set_auth(self.environments, self.username, self.account_info)

        # Register protocol update callback
        self.client.set_protocol_update_callback(self.update_protocol_counts)

        # Note: We don't create packet handler for admin dashboard - it's monitoring only

        # Start the client
        self.client.start()

        # Start stats updates
        import threading
        stats_thread = threading.Thread(target=self.update_stats)
        stats_thread.daemon = True
        stats_thread.start()


def main():
    parser = argparse.ArgumentParser(description='Admin-Enabled Packet Capture Client')
    parser.add_argument('--config', type=str, help='Path to user config file')
    parser.add_argument('--force-admin', action='store_true',
                        help='Force show admin dashboard regardless of user status')
    parser.add_argument('--server', type=str, default="176.9.45.249", help='Server hostname or IP')
    parser.add_argument('--port', type=int, default=9007, help='Server port')
    parser.add_argument('--dashboard-only', action='store_true',
                        help='Run as admin dashboard only (will not appear in client list)')
    args = parser.parse_args()

    # Default settings
    username = "TestUser"
    environments = [{'env_name': 'default', 'env_password': 'default_password'}]
    account_info = None
    is_admin = args.force_admin  # Start with force_admin flag

    print(f"Starting client with force_admin={args.force_admin}, dashboard_only={args.dashboard_only}")

    # Load config if provided
    if args.config and os.path.exists(args.config):
        try:
            print(f"Loading config from: {args.config}")
            with open(args.config, 'r') as f:
                config = json.load(f)

            username = config.get('username', username)
            user_id = config.get('user_id')

            # Check for admin in environments
            config_environments = config.get('environments', [])
            if config_environments:
                environments = config_environments
                # Check if any environment has admin
                for env in config_environments:
                    if env.get('is_admin', False):
                        is_admin = True
                        print(f"User is admin of environment: {env.get('env_name')}")

            # Create account info
            if user_id:
                account_info = {
                    "user_id": user_id,
                    "username": username,
                    "is_admin": is_admin
                }

            print(f"Loaded user: {username} (Admin: {is_admin})")

        except Exception as e:
            print(f"Error loading config: {e}")

    # Create root window
    root = tk.Tk()
    window_title = f"Packet Capture - {username}"
    if is_admin or args.force_admin:
        window_title += " [ADMIN]"
    if args.dashboard_only:
        window_title += " - Dashboard Only"
    root.title(window_title)
    root.geometry("900x700")

    # Create UI with admin support
    print("Creating UI...")
    ui = AdminEnabledClientUI(root, force_admin=args.force_admin)

    # Create backend - use admin dashboard backend if dashboard_only
    print("Creating backend...")
    if args.dashboard_only:
        backend = AdminDashboardBackend(ui=ui)
        print("Using AdminDashboardBackend - will not appear in client list")
    else:
        backend = OptimizedPacketCaptureBackend(ui=ui)

    # Configure backend
    backend.configure(
        server_host=args.server,
        server_port=args.port,
        username=username,
        environments=environments,
        account_info=account_info
    )

    # Connect UI and backend
    ui.set_backend(backend)

    # Log startup info
    ui.log_message(f"Client started - User: {username}")
    if is_admin or args.force_admin:
        ui.log_message("*** ADMIN MODE ACTIVE ***")
        if args.force_admin:
            ui.log_message("(Admin dashboard forced via command line)")
    if args.dashboard_only:
        ui.log_message("*** DASHBOARD ONLY MODE - Will not appear in client list ***")
    ui.log_message(f"Server: {args.server}:{args.port}")

    # Start the main loop
    print("Starting main loop...")
    root.mainloop()


if __name__ == "__main__":
    main()