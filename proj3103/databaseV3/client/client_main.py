import tkinter as tk
import sys
import os

# Add the current directory to the path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the UI
from client_front import PacketCaptureClientUI
# Import only from stable_client.py for the stable backend
from stable_client import StablePacketCaptureBackend, upgrade_to_real_capture, SimplePacketHandler


# Define this class here or import properly if it exists elsewhere
class ScapyPacketCaptureBackend:
    def __init__(self, ui=None):
        self.ui = ui
        # Add necessary implementation or pass if this is just a placeholder


def main():
    # Choose which backend implementation to use
    use_stable = True  # Set to True to use the new stable backend
    use_scapy = False  # Only used if use_stable is False

    # Create the root window
    root = tk.Tk()

    # Create the UI
    ui = PacketCaptureClientUI(root)

    # Create the backend
    if use_stable:
        # FIXED: Pass the UI to the backend constructor
        backend = StablePacketCaptureBackend(ui=ui)
        backend.configure(capture_interface="Ethernet",
                          server_host="localhost",
                          server_port=65432,
                          env_name="test",  # Must match a valid environment on server
                          env_password="test_password")  # Must be correct password
        # Connect UI and backend
        ui.set_backend(backend)

        # Optional: Set a timer to upgrade to real packet capture after connection stability is confirmed
        # This will switch from test packets to real packet capture after 10 seconds
        root.after(10000, lambda: upgrade_to_real_capture(backend))
    else:
        # Use the original backends - these need proper implementations
        if use_scapy:
            backend = ScapyPacketCaptureBackend(ui)
        else:
            # This should be replaced with your actual backup implementation
            backend = StablePacketCaptureBackend(ui=ui)  # Fallback to stable anyway
        # Connect UI and backend
        ui.set_backend(backend)

    # ADDED: Start processing packets in the UI
    ui.start_log_consumer()
    ui.start_processing_packets()

    # Start the main loop
    root.mainloop()


if __name__ == "__main__":
    main()