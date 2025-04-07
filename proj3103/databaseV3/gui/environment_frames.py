import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from gui.dialogs import AddEnvironmentDialog


class MyEnvironmentsTab:
    """Tab for managing user's environments."""

    def __init__(self, parent, user_id, db):
        self.parent = parent
        self.user_id = user_id
        self.db = db

        # Create controls
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill=tk.X, pady=5)

        # Create treeview
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create the environments treeview
        self.env_tree = self.create_tree(tree_frame)

        # Add refresh button
        refresh_btn = ttk.Button(
            controls_frame,
            text="Refresh",
            command=lambda: self.populate_user_environments()
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Initially populate the tree
        self.populate_user_environments()

        # Add context menu
        self.create_context_menu()

    def create_tree(self, parent):
        """Create the treeview for environments."""
        # Create scrollbar
        scrollbar = ttk.Scrollbar(parent)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create treeview
        columns = ("Environment", "Password", "Role")
        env_tree = ttk.Treeview(parent, columns=columns, show="headings", yscrollcommand=scrollbar.set)

        # Configure columns
        env_tree.heading("Environment", text="Environment")
        env_tree.heading("Password", text="Password")
        env_tree.heading("Role", text="Role")
        env_tree.column("Environment", width=150)
        env_tree.column("Password", width=150)
        env_tree.column("Role", width=100)

        scrollbar.config(command=env_tree.yview)
        env_tree.pack(fill=tk.BOTH, expand=True)

        return env_tree

    def populate_user_environments(self):
        """Populate the treeview with user's environments."""
        # Clear current items
        for item in self.env_tree.get_children():
            self.env_tree.delete(item)

        # Get environments for the current user
        environments = self.db.get_user_environments(self.user_id)

        # Add environments to the treeview
        for env in environments:
            self.env_tree.insert("", tk.END, values=(
                env["env_name"],
                env["env_password"],
                "Admin" if env["is_admin"] else "Member"
            ))

    def create_context_menu(self):
        """Create a right-click context menu for the user environments treeview."""
        context_menu = tk.Menu(self.env_tree, tearoff=0)

        # Add copy password option
        context_menu.add_command(label="Copy Password",
                                 command=self.copy_password_to_clipboard)

        # Add leave environment option
        context_menu.add_command(label="Leave Environment",
                                 command=self.leave_selected_environment)

        # Bind right-click event
        self.env_tree.bind("<Button-3>", lambda event: self.show_context_menu(event, context_menu))

    def show_context_menu(self, event, menu):
        """Show the context menu at the current mouse position."""
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_password_to_clipboard(self):
        """Copy the password of the selected environment to clipboard."""
        selected_item = self.env_tree.selection()
        if not selected_item:
            return

        item = self.env_tree.item(selected_item[0])
        password = item['values'][1]

        self.parent.clipboard_clear()
        self.parent.clipboard_append(password)
        messagebox.showinfo("Copy Password", "Password copied to clipboard!")

    def leave_selected_environment(self):
        """Leave the selected environment."""
        selected_item = self.env_tree.selection()
        if not selected_item:
            return

        item = self.env_tree.item(selected_item[0])
        env_name = item['values'][0]
        role = item['values'][2]

        # If user is admin of this environment, they cannot leave
        if role == "Admin":
            messagebox.showerror("Error", "You cannot leave an environment you created. You must delete it instead.")
            return

        if messagebox.askyesno("Leave Environment", f"Are you sure you want to leave '{env_name}'?"):
            if self.db.leave_environment(self.user_id, env_name):
                messagebox.showinfo("Success", f"You have left '{env_name}'.")
                self.populate_user_environments()
            else:
                messagebox.showerror("Error", f"Failed to leave '{env_name}'.")


class AdminConsoleTab:
    """Tab for admin users to manage environments."""

    def __init__(self, parent, user_id, db):
        self.parent = parent
        self.user_id = user_id
        self.db = db

        # Create buttons frame
        buttons_frame = ttk.Frame(parent)
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
            command=self.populate_admin_environments
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Create treeview
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.env_tree = self.create_tree(tree_frame)

        # Initially populate the tree
        self.populate_admin_environments()

        # Add context menu
        self.create_context_menu()

    def create_tree(self, parent):
        """Create the treeview for environments."""
        # Create scrollbar
        scrollbar = ttk.Scrollbar(parent)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create treeview
        columns = ("Environment", "Password")
        env_tree = ttk.Treeview(parent, columns=columns, show="headings", yscrollcommand=scrollbar.set)

        # Configure columns
        env_tree.heading("Environment", text="Environment")
        env_tree.heading("Password", text="Password")
        env_tree.column("Environment", width=150)
        env_tree.column("Password", width=150)

        scrollbar.config(command=env_tree.yview)
        env_tree.pack(fill=tk.BOTH, expand=True)

        return env_tree

    def show_add_environment_dialog(self):
        """Show dialog to add a new environment."""
        dialog = AddEnvironmentDialog(self.parent, self.user_id, self.db, self.populate_admin_environments)

    def populate_admin_environments(self):
        """Populate the treeview with admin's environments."""
        # Clear current items
        for item in self.env_tree.get_children():
            self.env_tree.delete(item)

        # Get environments created by this admin
        environments = self.db.get_admin_environments(self.user_id)

        # Add environments to the treeview
        for env in environments:
            self.env_tree.insert("", tk.END, values=(env["env_name"], env["env_password"]))

    def create_context_menu(self):
        """Create a right-click context menu for the admin environments treeview."""
        context_menu = tk.Menu(self.env_tree, tearoff=0)

        # Add edit password option
        context_menu.add_command(label="Edit Password",
                                 command=self.edit_environment_password)

        # Add delete environment option
        context_menu.add_command(label="Delete Environment",
                                 command=self.delete_selected_environment)

        # Bind right-click event
        self.env_tree.bind("<Button-3>", lambda event: self.show_context_menu(event, context_menu))

    def show_context_menu(self, event, menu):
        """Show the context menu at the current mouse position."""
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def edit_environment_password(self):
        """Edit the password of the selected environment."""
        selected_item = self.env_tree.selection()
        if not selected_item:
            return

        item = self.env_tree.item(selected_item[0])
        env_name = item['values'][0]

        # Ask for new password
        new_password = simpledialog.askstring("Edit Password",
                                              f"Enter new password for '{env_name}':",
                                              show='*')

        if new_password:
            if self.db.update_environment(self.user_id, env_name, new_password):
                messagebox.showinfo("Success", f"Password for '{env_name}' updated successfully.")
                self.populate_admin_environments()
            else:
                messagebox.showerror("Error", f"Failed to update password for '{env_name}'.")

    def delete_selected_environment(self):
        """Delete the selected environment."""
        selected_item = self.env_tree.selection()
        if not selected_item:
            return

        item = self.env_tree.item(selected_item[0])
        env_name = item['values'][0]

        if messagebox.askyesno("Delete Environment",
                               f"Are you sure you want to delete '{env_name}'? This will remove access for all users."):
            if self.db.delete_environment(self.user_id, env_name):
                messagebox.showinfo("Success", f"Environment '{env_name}' deleted successfully.")
                self.populate_admin_environments()
            else:
                messagebox.showerror("Error", f"Failed to delete environment '{env_name}'.")


class JoinEnvironmentTab:
    """Tab for joining existing environments."""

    def __init__(self, parent, user_id, db, on_join_success=None):
        self.parent = parent
        self.user_id = user_id
        self.db = db
        self.on_join_success = on_join_success

        # Create join frame
        join_frame = ttk.Frame(parent, padding="20")
        join_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(join_frame, text="Join an Environment", font=("Helvetica", 14, "bold"))
        title_label.pack(pady=10)

        # Environment name field
        name_frame = ttk.Frame(join_frame)
        name_frame.pack(fill=tk.X, pady=5)

        name_label = ttk.Label(name_frame, text="Environment Name:", width=18)
        name_label.pack(side=tk.LEFT, padx=5)

        self.name_entry = ttk.Entry(name_frame, width=30)
        self.name_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Environment password field
        pass_frame = ttk.Frame(join_frame)
        pass_frame.pack(fill=tk.X, pady=5)

        pass_label = ttk.Label(pass_frame, text="Password:", width=18)
        pass_label.pack(side=tk.LEFT, padx=5)

        self.pass_entry = ttk.Entry(pass_frame, show="*", width=30)
        self.pass_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Join button
        join_btn = ttk.Button(
            join_frame,
            text="Join Environment",
            command=self.join_environment
        )
        join_btn.pack(pady=10)

        # Available environments section
        available_label = ttk.Label(join_frame, text="Available Environments:", font=("Helvetica", 12))
        available_label.pack(pady=(20, 10), anchor=tk.W)

        # Create treeview for available environments
        tree_frame = ttk.Frame(join_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.available_tree = self.create_tree(tree_frame)

        # Refresh button
        refresh_btn = ttk.Button(
            join_frame,
            text="Refresh Available Environments",
            command=self.populate_available_environments
        )
        refresh_btn.pack(pady=10)

        # Initially populate the available environments
        self.populate_available_environments()

        # Add double-click event
        self.available_tree.bind("<Double-1>", self.select_environment_from_tree)

    def create_tree(self, parent):
        """Create the treeview for available environments."""
        # Create scrollbar
        scrollbar = ttk.Scrollbar(parent)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create treeview
        columns = ("Environment",)
        tree = ttk.Treeview(parent, columns=columns, show="headings", yscrollcommand=scrollbar.set)

        # Configure columns
        tree.heading("Environment", text="Environment Name")
        tree.column("Environment", width=200)

        scrollbar.config(command=tree.yview)
        tree.pack(fill=tk.BOTH, expand=True)

        return tree

    def populate_available_environments(self):
        """Populate the treeview with available environments."""
        # Clear current items
        for item in self.available_tree.get_children():
            self.available_tree.delete(item)

        # Get all available environments
        environments = self.db.get_available_environments()

        # Add environments to the treeview
        for env in environments:
            self.available_tree.insert("", tk.END, values=(env["env_name"],))

    def select_environment_from_tree(self, event):
        """Select an environment from the treeview and insert into entry field."""
        selected_item = self.available_tree.selection()
        if selected_item:
            item = self.available_tree.item(selected_item[0])
            env_name = item['values'][0]
            self.name_entry.delete(0, tk.END)
            self.name_entry.insert(0, env_name)

    def join_environment(self):
        """Join an existing environment."""
        env_name = self.name_entry.get()
        env_password = self.pass_entry.get()

        if not env_name or not env_password:
            messagebox.showerror("Error", "Please enter both environment name and password.")
            return

        if self.db.join_environment(self.user_id, env_name, env_password):
            messagebox.showinfo("Success", f"You have joined environment '{env_name}'!")

            # Call the callback if provided
            if self.on_join_success:
                self.on_join_success()
        else:
            messagebox.showerror("Error", "Failed to join environment. Check the environment name and password.")