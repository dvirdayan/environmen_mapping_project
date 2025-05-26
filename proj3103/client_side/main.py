import tkinter as tk
from gui.base_gui import CredentialManagerGUI


def main():
    """Main entry point for the Credential Manager application."""
    root = tk.Tk()
    root.iconbitmap('tree.ico')
    app = CredentialManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
