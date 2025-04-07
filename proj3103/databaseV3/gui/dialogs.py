import tkinter as tk
from tkinter import ttk, messagebox


class AddEnvironmentDialog:
    """Dialog for adding a new environment."""

    def __init__(self, parent, user_id, db, on_success=None):
        self.parent = parent
        self.user_id = user_id
        self.db = db
        self.on_success = on_success

        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Create Environment")
        self.dialog.geometry("400x200")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)  # Set as transient to main window
        self.dialog.grab_set()  # Modal dialog

        # Center the window
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f'{width}x{height}+{x}+{y}')

        # Create frame
        frame = ttk.Frame(self.dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        # Environment name field
        name_frame = ttk.Frame(frame)
        name_frame.pack(fill=tk.X, pady=5)

        name_label = ttk.Label(name_frame, text="Environment Name:", width=15)
        name_label.pack(side=tk.LEFT, padx=5)

        self.name_entry = ttk.Entry(name_frame, width=30)
        self.name_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Environment password field
        pass_frame = ttk.Frame(frame)
        pass_frame.pack(fill=tk.X, pady=5)

        pass_label = ttk.Label(pass_frame, text="Password:", width=15)
        pass_label.pack(side=tk.LEFT, padx=5)

        self.pass_entry = ttk.Entry(pass_frame, width=30, show="*")
        self.pass_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Buttons
        buttons_frame = ttk.Frame(frame)
        buttons_frame.pack(pady=20)

        cancel_btn = ttk.Button(buttons_frame, text="Cancel",
                                command=self.dialog.destroy, width=10)
        cancel_btn.pack(side=tk.LEFT, padx=5)

        create_btn = ttk.Button(buttons_frame, text="Create",
                                command=self.create_environment,
                                width=10)
        create_btn.pack(side=tk.LEFT, padx=5)

    def create_environment(self):
        """Create a new environment."""
        env_name = self.name_entry.get()
        env_password = self.pass_entry.get()

        if not env_name or not env_password:
            messagebox.showerror("Error", "Please enter both environment name and password.")
            return

        if self.db.add_environment(self.user_id, env_name, env_password):
            messagebox.showinfo("Success", f"Environment '{env_name}' created successfully!")
            self.dialog.destroy()

            # Call the success callback if provided
            if self.on_success:
                self.on_success()
        else:
            messagebox.showerror("Error",
                                 f"Environment name '{env_name}' already exists or you do not have permission.")