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

        # Header frame with title, logout and start client buttons
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

        # Add start client button
        if self.start_client_callback and not self.is_admin:
            start_client_btn = ttk.Button(header_frame, text="Start Client", command=self.start_client_callback)
            start_client_btn.pack(side=tk.RIGHT, padx=5)

        logout_btn = ttk.Button(header_frame, text="Logout", command=logout_callback)
        logout_btn.pack(side=tk.RIGHT, padx=10)

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