#!/usr/bin/env python3
import tkinter as tk
import os
import sys

# Ensure the current directory is in the path so imports work correctly
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import our modules
try:
    from cdatabase import CredentialDatabase  # Changed from credential_database to cdatabase
    from logingui import CredentialManagerGUI
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure both cdatabase.py and logingui.py are in the same directory.")  # Updated file names
    sys.exit(1)


def main():
    """Main entry point for the application."""
    # Create the main Tkinter window
    root = tk.Tk()

    # Set the icon and title
    root.title("Credential Manager")

    try:
        root.iconbitmap("tree.ico")  # Ensure the icon file is in the same directory
    except:
        pass

    # Initialize the GUI with the root window
    app = CredentialManagerGUI(root)

    # Start the Tkinter event loop
    root.mainloop()


if __name__ == "__main__":
    main()
