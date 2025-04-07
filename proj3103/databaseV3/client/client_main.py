import tkinter as tk
import sys
import os

# Add the current directory to the path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from client_front import PacketCaptureClientUI
from client_back import PacketCaptureBackend, ScapyPacketCaptureBackend


def main():
    # Choose which backend implementation to use
    use_scapy = False  # Set to True to use Scapy instead of PyShark

    # Create the root window
    root = tk.Tk()

    # Create the UI
    ui = PacketCaptureClientUI(root)

    # Create the backend
    if use_scapy:
        backend = ScapyPacketCaptureBackend(ui)
    else:
        backend = PacketCaptureBackend(ui)

    # Connect UI and backend
    ui.set_backend(backend)

    # Start the main loop
    root.mainloop()


if __name__ == "__main__":
    main()
