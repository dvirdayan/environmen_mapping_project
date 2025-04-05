import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import sys
from typing import Optional, Callable

# Import the database class from the main file
from cdatabase import CredentialDatabase

from proj3103.client.client import LivePacketCaptureClient

class CredentialManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Credential Manager")
        self.root.geometry("800x500")
        self.root.resizable(True, True)

        # Initialize database
        self.db = CredentialDatabase()

        # Current user state
        self.current_user_id = None
        self.current_username = None
        self.is_admin = False

        # Set up the main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create the initial login/register frame
        self.show_auth_frame()

        # Set up a protocol for when the window is closed
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Handle closing the application."""
        if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
            self.db.close()
            self.root.destroy()

    def clear_frame(self, frame):
        """Clear all widgets from a frame."""
        for widget in frame.winfo_children():
            widget.destroy()

    def show_auth_frame(self):
        """Display the authentication frame with login and register options."""
        self.clear_frame(self.main_frame)

        # Create and configure auth frame
        auth_frame = ttk.Frame(self.main_frame, padding="20")
        auth_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(auth_frame, text="Credential Manager", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=20)

        # Login button
        login_btn = ttk.Button(auth_frame, text="Login", command=self.show_login_form, width=20)
        login_btn.pack(pady=10)

        # Register button
        register_btn = ttk.Button(auth_frame, text="Register", command=self.show_register_form, width=20)
        register_btn.pack(pady=10)

        # Exit button
        exit_btn = ttk.Button(auth_frame, text="Exit", command=self.on_close, width=20)
        exit_btn.pack(pady=10)

    def show_login_form(self):
        """Display the login form."""
        self.clear_frame(self.main_frame)

        login_frame = ttk.Frame(self.main_frame, padding="20")
        login_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(login_frame, text="Login", font=("Helvetica", 14, "bold"))
        title_label.pack(pady=10)

        # Username field
        username_frame = ttk.Frame(login_frame)
        username_frame.pack(fill=tk.X, pady=5)

        username_label = ttk.Label(username_frame, text="Username:", width=15)
        username_label.pack(side=tk.LEFT, padx=5)

        username_entry = ttk.Entry(username_frame, width=30)
        username_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Password field
        password_frame = ttk.Frame(login_frame)
        password_frame.pack(fill=tk.X, pady=5)

        password_label = ttk.Label(password_frame, text="Password:", width=15)
        password_label.pack(side=tk.LEFT, padx=5)

        password_entry = ttk.Entry(password_frame, show="*", width=30)
        password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Buttons frame
        buttons_frame = ttk.Frame(login_frame)
        buttons_frame.pack(pady=20)

        back_btn = ttk.Button(buttons_frame, text="Back", command=self.show_auth_frame, width=10)
        back_btn.pack(side=tk.LEFT, padx=5)

        login_btn = ttk.Button(
            buttons_frame,
            text="Login",
            command=lambda: self.login_user(username_entry.get(), password_entry.get()),
            width=10
        )
        login_btn.pack(side=tk.LEFT, padx=5)

        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: self.login_user(username_entry.get(), password_entry.get()))

    def show_register_form(self):
        """Display the registration form."""
        self.clear_frame(self.main_frame)

        register_frame = ttk.Frame(self.main_frame, padding="20")
        register_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(register_frame, text="Register", font=("Helvetica", 14, "bold"))
        title_label.pack(pady=10)

        # Username field
        username_frame = ttk.Frame(register_frame)
        username_frame.pack(fill=tk.X, pady=5)

        username_label = ttk.Label(username_frame, text="Username:", width=17)
        username_label.pack(side=tk.LEFT, padx=5)

        username_entry = ttk.Entry(username_frame, width=30)
        username_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Password field
        password_frame = ttk.Frame(register_frame)
        password_frame.pack(fill=tk.X, pady=5)

        password_label = ttk.Label(password_frame, text="Password:", width=17)
        password_label.pack(side=tk.LEFT, padx=5)

        password_entry = ttk.Entry(password_frame, show="*", width=30)
        password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Confirm Password field
        confirm_frame = ttk.Frame(register_frame)
        confirm_frame.pack(fill=tk.X, pady=5)

        confirm_label = ttk.Label(confirm_frame, text="Confirm Password:", width=17)
        confirm_label.pack(side=tk.LEFT, padx=5)

        confirm_entry = ttk.Entry(confirm_frame, show="*", width=30)
        confirm_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Admin checkbox
        admin_frame = ttk.Frame(register_frame)
        admin_frame.pack(fill=tk.X, pady=5)

        # Create a variable to hold the checkbox state
        is_admin_var = tk.BooleanVar()
        admin_checkbox = ttk.Checkbutton(admin_frame, text="Register as Admin", variable=is_admin_var)
        admin_checkbox.pack(side=tk.LEFT, padx=20)

        # Buttons frame
        buttons_frame = ttk.Frame(register_frame)
        buttons_frame.pack(pady=20)

        back_btn = ttk.Button(buttons_frame, text="Back", command=self.show_auth_frame, width=10)
        back_btn.pack(side=tk.LEFT, padx=5)

        register_btn = ttk.Button(
            buttons_frame,
            text="Register",
            command=lambda: self.register_user(
                username_entry.get(),
                password_entry.get(),
                confirm_entry.get(),
                is_admin_var.get()  # Pass the admin checkbox state
            ),
            width=10
        )
        register_btn.pack(side=tk.LEFT, padx=5)


    def login_user(self, username: str, password: str):
        """Attempt to log in a user."""
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        result = self.db.authenticate_user(username, password)
        if result:
            user_id, is_admin = result
            self.current_user_id = user_id
            self.current_username = username
            self.is_admin = is_admin
            self.root.unbind('<Return>')  # Unbind the Enter key
            self.show_main_dashboard()

            # Start the client if the user is not an admin
            if not is_admin:
                self.start_client()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def start_client(self):
        """Start the LivePacketCaptureClient."""
        # Try to list interfaces
        print("Attempting to list network interfaces...")
        interfaces = LivePacketCaptureClient.list_interfaces()

        if not interfaces:
            print("\nFailed to automatically detect interfaces.")
            interface_name = input(
                "Please enter your network interface name manually (e.g., 'Wi-Fi', 'Ethernet', 'eth0'): ")
        else:
            while True:
                try:
                    choice = int(input("\nEnter the number of the interface you want to capture from: "))
                    if 1 <= choice <= len(interfaces):
                        interface_name = interfaces[choice - 1]
                        break
                    else:
                        print("Invalid choice. Please select a valid number.")
                except ValueError:
                    print("Please enter a valid number.")

        print(f"\nSelected interface: {interface_name}")

        # Make sure server is running
        input("Make sure the server is running and press Enter to continue...")

        use_env = input("\nDo you want to connect to a specific environment? (y/n): ").lower()
        env_name = None
        env_password = None

        if use_env == 'y' or use_env == 'yes':
            env_name = input("Enter environment name: ")
            env_password = input("Enter environment password: ")

        print(f"\nSelected interface: {interface_name}")
        if env_name:
            print(f"Using environment: {env_name}")

        # Make sure server is running
        input("Make sure the server is running and press Enter to continue...")

        client = LivePacketCaptureClient(
            capture_interface=interface_name,
            env_name=env_name,
            env_password=env_password
        )
        try:
            client.capture_and_send()
        except KeyboardInterrupt:
            print("\nStopping capture...")
            client.close()

    def register_user(self, username: str, password: str, confirm_password: str, is_admin: bool = False):
        """Register a new user."""
        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        if self.db.add_user(username, password, is_admin):
            messagebox.showinfo("Success",
                                f"User '{username}' registered successfully{' as Admin' if is_admin else ''}!")
            self.show_login_form()
        else:
            messagebox.showerror("Error", f"Username '{username}' already exists. Please choose another username.")

    def logout_user(self):
        """Log out the current user."""
        self.current_user_id = None
        self.current_username = None
        self.is_admin = False
        self.show_auth_frame()

    def show_main_dashboard(self):
        """Display the main dashboard after login."""
        self.clear_frame(self.main_frame)

        # Create the main dashboard frame
        dashboard_frame = ttk.Frame(self.main_frame)
        dashboard_frame.pack(fill=tk.BOTH, expand=True)

        # Header frame with title and logout button
        header_frame = ttk.Frame(dashboard_frame)
        header_frame.pack(fill=tk.X, pady=5)

        welcome_label = ttk.Label(
            header_frame,
            text=f"Welcome, {self.current_username}! {'(Admin)' if self.is_admin else ''}",
            font=("Helvetica", 14, "bold")
        )
        welcome_label.pack(side=tk.LEFT, padx=10)

        logout_btn = ttk.Button(header_frame, text="Logout", command=self.logout_user)
        logout_btn.pack(side=tk.RIGHT, padx=10)

        # Create a notebook (tabbed interface)
        notebook = ttk.Notebook(dashboard_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # My Environments tab (for all users)
        my_environments_frame = ttk.Frame(notebook)
        notebook.add(my_environments_frame, text="My Environments")

        # Show user's environments
        self.setup_my_environments_tab(my_environments_frame)

        # Create Admin tab if user is admin
        if self.is_admin:
            admin_frame = ttk.Frame(notebook)
            notebook.add(admin_frame, text="Admin Console")
            self.setup_admin_tab(admin_frame)

        # Join Environment tab (for non-admin users)
        join_frame = ttk.Frame(notebook)
        notebook.add(join_frame, text="Join Environment")
        self.setup_join_environment_tab(join_frame)

    def setup_my_environments_tab(self, parent_frame):
        """Setup the My Environments tab."""
        controls_frame = ttk.Frame(parent_frame)
        controls_frame.pack(fill=tk.X, pady=5)

        refresh_btn = ttk.Button(
            controls_frame,
            text="Refresh",
            command=lambda: self.populate_user_environments(env_tree)
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Create treeview for environments
        tree_frame = ttk.Frame(parent_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create scrollbar
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create treeview
        columns = ("Environment", "Password", "Role")
        env_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)

        # Configure columns
        env_tree.heading("Environment", text="Environment")
        env_tree.heading("Password", text="Password")
        env_tree.heading("Role", text="Role")
        env_tree.column("Environment", width=150)
        env_tree.column("Password", width=150)
        env_tree.column("Role", width=100)

        scrollbar.config(command=env_tree.yview)
        env_tree.pack(fill=tk.BOTH, expand=True)

        # Populate the treeview
        self.populate_user_environments(env_tree)

        # Add right-click menu to treeview
        self.create_user_environments_context_menu(env_tree)

    def setup_admin_tab(self, parent_frame):
        """Setup the Admin tab (for admin users only)."""
        buttons_frame = ttk.Frame(parent_frame)
        buttons_frame.pack(fill=tk.X, pady=10)

        add_btn = ttk.Button(
            buttons_frame,
            text="Create Environment",
            command=self.show_add_environment_dialog
        )
        add_btn.pack(side=tk.LEFT, padx=5)

        refresh_btn = ttk.Button(
            buttons_frame,
            text="Refresh",
            command=lambda: self.populate_admin_environments(env_tree)
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Create treeview for environments
        tree_frame = ttk.Frame(parent_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create scrollbar
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create treeview
        columns = ("Environment", "Password")
        env_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)

        # Configure columns // admin environment list
        env_tree.heading("Environment", text="Environment")
        env_tree.heading("Password", text="Password")
        env_tree.column("Environment", width=150)
        env_tree.column("Password", width=150)

        scrollbar.config(command=env_tree.yview)
        env_tree.pack(fill=tk.BOTH, expand=True)

        # Populate the treeview
        self.populate_admin_environments(env_tree)

        # Add right-click menu to treeview
        self.create_admin_environments_context_menu(env_tree)

    def setup_join_environment_tab(self, parent_frame):
        """Setup the Join Environment tab."""
        join_frame = ttk.Frame(parent_frame, padding="20")
        join_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(join_frame, text="Join an Environment", font=("Helvetica", 14, "bold"))
        title_label.pack(pady=10)

        # Environment name field
        name_frame = ttk.Frame(join_frame)
        name_frame.pack(fill=tk.X, pady=5)

        name_label = ttk.Label(name_frame, text="Environment Name:", width=18)
        name_label.pack(side=tk.LEFT, padx=5)

        name_entry = ttk.Entry(name_frame, width=30)
        name_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Environment password field
        pass_frame = ttk.Frame(join_frame)
        pass_frame.pack(fill=tk.X, pady=5)

        pass_label = ttk.Label(pass_frame, text="Password:", width=18)
        pass_label.pack(side=tk.LEFT, padx=5)

        pass_entry = ttk.Entry(pass_frame, show="*", width=30)
        pass_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Join button
        join_btn = ttk.Button(
            join_frame,
            text="Join Environment",
            command=lambda: self.join_environment(name_entry.get(), pass_entry.get())
        )
        join_btn.pack(pady=10)

        # Available environments section
        available_label = ttk.Label(join_frame, text="Available Environments:", font=("Helvetica", 12))
        available_label.pack(pady=(20, 10), anchor=tk.W)

        # Create treeview for available environments
        tree_frame = ttk.Frame(join_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Create scrollbar
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create treeview
        columns = ("Environment",)
        available_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)

        # Configure columns
        available_tree.heading("Environment", text="Environment Name")
        available_tree.column("Environment", width=200)

        scrollbar.config(command=available_tree.yview)
        available_tree.pack(fill=tk.BOTH, expand=True)

        # Populate available environments
        self.populate_available_environments(available_tree)

        # Refresh button
        refresh_btn = ttk.Button(
            join_frame,
            text="Refresh Available Environments",
            command=lambda: self.populate_available_environments(available_tree)
        )
        refresh_btn.pack(pady=10)

        # Add double-click event to select environment
        available_tree.bind("<Double-1>",
                            lambda event: self.select_environment_from_tree(event, available_tree, name_entry))

    def populate_user_environments(self, tree):
        """Populate the treeview with user's environments."""
        # Clear current items
        for item in tree.get_children():
            tree.delete(item)

        # Get environments for the current user
        environments = self.db.get_user_environments(self.current_user_id)

        # Add environments to the treeview
        for env in environments:
            tree.insert("", tk.END, values=(
                env["env_name"],
                env["env_password"],
                "Admin" if env["is_admin"] else "Member"
            ))

    def populate_admin_environments(self, tree):
        """Populate the treeview with admin's environments."""
        # Clear current items
        for item in tree.get_children():
            tree.delete(item)

        # Get environments created by this admin
        environments = self.db.get_admin_environments(self.current_user_id)

        # Add environments to the treeview
        for env in environments:
            tree.insert("", tk.END, values=(env["env_name"], env["env_password"]))

    def populate_available_environments(self, tree):
        """Populate the treeview with available environments."""
        # Clear current items
        for item in tree.get_children():
            tree.delete(item)

        # Get all available environments
        environments = self.db.get_available_environments()

        # Add environments to the treeview
        for env in environments:
            tree.insert("", tk.END, values=(env["env_name"],))

    def select_environment_from_tree(self, event, tree, entry):
        """Select an environment from the treeview and insert into entry field."""
        selected_item = tree.selection()
        if selected_item:
            item = tree.item(selected_item[0])
            env_name = item['values'][0]
            entry.delete(0, tk.END)
            entry.insert(0, env_name)

    def create_user_environments_context_menu(self, tree):
        """Create a right-click context menu for the user environments treeview."""
        context_menu = tk.Menu(tree, tearoff=0)

        # Add copy password option
        context_menu.add_command(label="Copy Password",
                                 command=lambda: self.copy_password_to_clipboard(tree))

        # Add leave environment option
        context_menu.add_command(label="Leave Environment",
                                 command=lambda: self.leave_selected_environment(tree))

        # Bind right-click event
        tree.bind("<Button-3>", lambda event: self.show_context_menu(event, context_menu))

    def create_admin_environments_context_menu(self, tree):
        """Create a right-click context menu for the admin environments treeview."""
        context_menu = tk.Menu(tree, tearoff=0)

        # Add edit password option
        context_menu.add_command(label="Edit Password",
                                 command=lambda: self.edit_environment_password(tree))

        # Add delete environment option
        context_menu.add_command(label="Delete Environment",
                                 command=lambda: self.delete_selected_environment(tree))

        # Bind right-click event
        tree.bind("<Button-3>", lambda event: self.show_context_menu(event, context_menu))

    def show_context_menu(self, event, menu):
        """Show the context menu at the current mouse position."""
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_password_to_clipboard(self, tree):
        """Copy the password of the selected environment to clipboard."""
        selected_item = tree.selection()
        if not selected_item:
            return

        item = tree.item(selected_item[0])
        password = item['values'][1]

        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Copy Password", "Password copied to clipboard!")

    def leave_selected_environment(self, tree):
        """Leave the selected environment."""
        selected_item = tree.selection()
        if not selected_item:
            return

        item = tree.item(selected_item[0])
        env_name = item['values'][0]
        role = item['values'][2]

        # If user is admin of this environment, they cannot leave
        if role == "Admin":
            messagebox.showerror("Error", "You cannot leave an environment you created. You must delete it instead.")
            return

        if messagebox.askyesno("Leave Environment", f"Are you sure you want to leave '{env_name}'?"):
            if self.db.leave_environment(self.current_user_id, env_name):
                messagebox.showinfo("Success", f"You have left '{env_name}'.")
                self.populate_user_environments(tree)
            else:
                messagebox.showerror("Error", f"Failed to leave '{env_name}'.")

    def edit_environment_password(self, tree):
        """Edit the password of the selected environment."""
        selected_item = tree.selection()
        if not selected_item:
            return

        item = tree.item(selected_item[0])
        env_name = item['values'][0]

        # Ask for new password
        new_password = simpledialog.askstring("Edit Password",
                                              f"Enter new password for '{env_name}':",
                                              show='*')

        if new_password:
            if self.db.update_environment(self.current_user_id, env_name, new_password):
                messagebox.showinfo("Success", f"Password for '{env_name}' updated successfully.")
                self.populate_admin_environments(tree)
            else:
                messagebox.showerror("Error", f"Failed to update password for '{env_name}'.")

    def delete_selected_environment(self, tree):
        """Delete the selected environment."""
        selected_item = tree.selection()
        if not selected_item:
            return

        item = tree.item(selected_item[0])
        env_name = item['values'][0]

        if messagebox.askyesno("Delete Environment",
                               f"Are you sure you want to delete '{env_name}'? This will remove access for all users."):
            if self.db.delete_environment(self.current_user_id, env_name):
                messagebox.showinfo("Success", f"Environment '{env_name}' deleted successfully.")
                self.populate_admin_environments(tree)
            else:
                messagebox.showerror("Error", f"Failed to delete environment '{env_name}'.")

    def show_add_environment_dialog(self):
        """Show dialog to add a new environment."""
        # Create a new toplevel window
        add_window = tk.Toplevel(self.root)
        add_window.title("Create Environment")
        add_window.geometry("400x200")
        add_window.resizable(False, False)
        add_window.transient(self.root)  # Set as transient to main window
        add_window.grab_set()  # Modal dialog

        # Center the window
        add_window.update_idletasks()
        width = add_window.winfo_width()
        height = add_window.winfo_height()
        x = (add_window.winfo_screenwidth() // 2) - (width // 2)
        y = (add_window.winfo_screenheight() // 2) - (height // 2)
        add_window.geometry(f'{width}x{height}+{x}+{y}')

        # Create frame
        frame = ttk.Frame(add_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        # Environment name field
        name_frame = ttk.Frame(frame)
        name_frame.pack(fill=tk.X, pady=5)

        name_label = ttk.Label(name_frame, text="Environment Name:", width=15)
        name_label.pack(side=tk.LEFT, padx=5)

        name_entry = ttk.Entry(name_frame, width=30)
        name_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Environment password field
        pass_frame = ttk.Frame(frame)
        pass_frame.pack(fill=tk.X, pady=5)

        pass_label = ttk.Label(pass_frame, text="Password:", width=15)
        pass_label.pack(side=tk.LEFT, padx=5)

        pass_entry = ttk.Entry(pass_frame, width=30, show="*")
        pass_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Buttons
        buttons_frame = ttk.Frame(frame)
        buttons_frame.pack(pady=20)

        cancel_btn = ttk.Button(buttons_frame, text="Cancel",
                                command=add_window.destroy, width=10)
        cancel_btn.pack(side=tk.LEFT, padx=5)

        create_btn = ttk.Button(buttons_frame, text="Create",
                                command=lambda: self.create_environment(name_entry.get(),
                                                                        pass_entry.get(),
                                                                        add_window),
                                width=10)
        create_btn.pack(side=tk.LEFT, padx=5)

    def create_environment(self, env_name, env_password, window=None):
        """Create a new environment."""
        if not env_name or not env_password:
            messagebox.showerror("Error", "Please enter both environment name and password.")
            return

        if self.db.add_environment(self.current_user_id, env_name, env_password):
            messagebox.showinfo("Success", f"Environment '{env_name}' created successfully!")
            if window:
                window.destroy()

            # Refresh the admin environments view
            for child in self.main_frame.winfo_children():
                if isinstance(child, ttk.Frame):
                    for notebook in child.winfo_children():
                        if isinstance(notebook, ttk.Notebook):
                            for tab in notebook.tabs():
                                tab_name = notebook.tab(tab, "text")
                                if tab_name == "Admin Console":
                                    for widget in notebook.nametowidget(tab).winfo_children():
                                        if isinstance(widget, ttk.Frame):
                                            for tree_frame in widget.winfo_children():
                                                if isinstance(tree_frame, ttk.Frame):
                                                    for tree in tree_frame.winfo_children():
                                                        if isinstance(tree, ttk.Treeview):
                                                            self.populate_admin_environments(tree)
        else:
            messagebox.showerror("Error",
                                 f"Environment name '{env_name}' already exists or you do not have permission.")

    def join_environment(self, env_name, env_password):
        """Join an existing environment."""
        if not env_name or not env_password:
            messagebox.showerror("Error", "Please enter both environment name and password.")
            return

        if self.db.join_environment(self.current_user_id, env_name, env_password):
            messagebox.showinfo("Success", f"You have joined environment '{env_name}'!")

            # Refresh the user environments view
            for child in self.main_frame.winfo_children():
                if isinstance(child, ttk.Frame):
                    for notebook in child.winfo_children():
                        if isinstance(notebook, ttk.Notebook):
                            for tab in notebook.tabs():
                                tab_name = notebook.tab(tab, "text")
                                if tab_name == "My Environments":
                                    for widget in notebook.nametowidget(tab).winfo_children():
                                        if isinstance(widget, ttk.Frame):
                                            for tree_frame in widget.winfo_children():
                                                if isinstance(tree_frame, ttk.Frame):
                                                    for tree in tree_frame.winfo_children():
                                                        if isinstance(tree, ttk.Treeview):
                                                            self.populate_user_environments(tree)
        else:
            messagebox.showerror("Error", "Failed to join environment. Check the environment name and password.")