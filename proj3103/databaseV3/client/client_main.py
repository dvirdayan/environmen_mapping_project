import tkinter as tk
import sys
import os

# Import the UI and the pie chart integration
from client_front import PacketCaptureClientUI
from pie_chart import integrate_pie_chart_to_ui
from stable_client import StablePacketCaptureBackend, upgrade_to_real_capture, SimplePacketHandler

# Add the current directory to the path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def main():
    # Choose which backend implementation to use
    use_stable = True

    # Create the root window
    root = tk.Tk()

    # Enhance the UI class with pie chart
    EnhancedPacketCaptureClientUI = integrate_pie_chart_to_ui(PacketCaptureClientUI)

    # Create the enhanced UI
    ui = EnhancedPacketCaptureClientUI(root)

    # Create the backend
    if use_stable:
        # Pass the UI to the backend constructor
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
        # Fallback to stable backend
        backend = StablePacketCaptureBackend(ui=ui)
        ui.set_backend(backend)

    # Start processing packets in the UI
    ui.start_log_consumer()
    ui.start_processing_packets()

    # Start the main loop
    root.mainloop()


if __name__ == "__main__":
    main()