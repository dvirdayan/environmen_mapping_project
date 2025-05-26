import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Frame


class EnvironmentDisplayFrame(ttk.LabelFrame):
    """Frame for displaying available environments (no selection)"""

    def __init__(self, parent, environments=None):
        """Initialize the environment display

        Args:
            parent: Parent widget
            environments: List of environment names
        """
        super().__init__(parent, text="Your Environments", padding="10")

        self.environments = environments or []

        # Create the main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create a label to show available environments
        ttk.Label(main_frame, text="Available environments:").pack(side=tk.LEFT, padx=5)

        # Environment list display
        self.env_list_var = tk.StringVar(value="None")
        ttk.Label(main_frame, textvariable=self.env_list_var, font=("Helvetica", 10, "bold")).pack(side=tk.LEFT, padx=5)

        # Add note about all environments being used
        note_frame = ttk.Frame(self)
        note_frame.pack(fill=tk.X, pady=5)

        ttk.Label(note_frame,
                  text="Note: Packets will be sent to all environments automatically",
                  font=("Helvetica", 9, "italic")).pack(fill=tk.X, padx=5)

    def update_environments(self, environments):
        """Update the list of available environments

        Args:
            environments: List of environment names
        """
        self.environments = environments or []

        if self.environments:
            self.env_list_var.set(", ".join(self.environments))
        else:
            self.env_list_var.set("None")


def enhance_client_ui_with_environment_selector(ui_class):
    """Enhance the client UI with an environment display (no selection)

    Args:
        ui_class: The UI class to enhance

    Returns:
        Enhanced UI class
    """
    # Store original setup_ui method
    original_setup_ui = ui_class.setup_ui

    # Store the original set_backend method OUTSIDE the enhanced method to avoid recursion
    original_set_backend = None
    if hasattr(ui_class, 'set_backend'):
        original_set_backend = ui_class.set_backend

    def enhanced_setup_ui(self):
        """Enhanced version of setup_ui with environment display (no selection)"""
        # Call original setup method
        original_setup_ui(self)

        # Find root frame - this should be the parent for all UI components
        root = self.root

        # Find the connection_frame and control_frame
        connection_frame = None
        control_frame = None
        stats_frame = None

        # Search through root's children
        for child in root.winfo_children():
            if isinstance(child, ttk.Frame) or isinstance(child, ttk.LabelFrame):
                # Check if this is the main frame that contains our other frames
                for sub_child in child.winfo_children():
                    if isinstance(sub_child, ttk.LabelFrame):
                        # Look for frames with specific titles
                        if sub_child.cget("text") == "Connection Settings":
                            connection_frame = sub_child
                        elif sub_child.cget("text") == "Statistics":
                            stats_frame = sub_child

                    # Look for the control frame with buttons
                    if isinstance(sub_child, ttk.Frame):
                        for btn in sub_child.winfo_children():
                            if isinstance(btn, ttk.Button) and btn.cget("text") in ["Start Capture", "Stop Capture"]:
                                control_frame = sub_child
                                break

        if not connection_frame and not control_frame:
            print("Warning: Could not find connection or control frames")
            return

        # Find the main_frame that contains all these frames
        main_frame = None
        if connection_frame:
            main_frame = connection_frame.master
        elif control_frame:
            main_frame = control_frame.master
        elif stats_frame:
            main_frame = stats_frame.master

        if not main_frame:
            print("Warning: Could not find main frame")
            return

        # Create the environment display frame (no selection functionality)
        self.env_display = EnvironmentDisplayFrame(main_frame, [])

        # Insert after connection settings but before control buttons
        if connection_frame and control_frame:
            self.env_display.pack(fill=tk.X, pady=5, after=connection_frame, before=control_frame)
        elif connection_frame:
            self.env_display.pack(fill=tk.X, pady=5, after=connection_frame)
        elif control_frame:
            self.env_display.pack(fill=tk.X, pady=5, before=control_frame)
        else:
            self.env_display.pack(fill=tk.X, pady=5)

    def enhanced_set_backend(self, backend):
        """Enhanced set_backend method to display environments"""
        # Call original method if it exists
        if original_set_backend:
            original_set_backend(self, backend)
        else:
            # Basic implementation if original doesn't exist
            self.backend = backend

        # Update environment display with available environments
        if hasattr(self, 'env_display') and hasattr(backend, 'get_environments'):
            environments = backend.get_environments()
            self.env_display.update_environments(environments)

    def on_environment_selection_change(self, environments, strategy):
        """This method is no longer needed but kept for compatibility"""
        pass

    # Add new methods to the class
    ui_class.setup_ui = enhanced_setup_ui
    ui_class.set_backend = enhanced_set_backend
    ui_class.on_environment_selection_change = on_environment_selection_change

    return ui_class
