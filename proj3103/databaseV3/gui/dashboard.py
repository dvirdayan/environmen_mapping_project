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

    def __init__(self, parent, username, is_admin, logout_callback, user_id, db_client, start_client_callback=None, start_admin_dashboard_callback=None):
        self.parent = parent
        self.username = username
        self.is_admin = is_admin
        self.user_id = user_id
        self.db_client = db_client
        self.start_client_callback = start_client_callback
        self.start_admin_dashboard_callback = start_admin_dashboard_callback

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

        # Button layout based on admin status
        if self.is_admin:
            # For admin users, show only Admin Dashboard button
            admin_btn = ttk.Button(
                header_frame,
                text="Admin Dashboard",
                command=self.start_admin_dashboard_callback if self.start_admin_dashboard_callback else self.no_admin_dashboard_callback
            )
            admin_btn.pack(side=tk.RIGHT, padx=5)
        else:
            # For regular users, show only Start Client button
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

    def no_admin_dashboard_callback(self):
        """Fallback when no admin dashboard callback is provided."""
        messagebox.showwarning("No Admin Dashboard", "Admin dashboard functionality is not available.")

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