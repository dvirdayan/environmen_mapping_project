import tkinter as tk
import sys
import os
import json
import argparse

# Import the UI and the pie chart integration
from client_front import PacketCaptureClientUI
from pie_chart import integrate_pie_chart_to_ui
from capture_backend import StablePacketCaptureBackend
from capture_upgrades import upgrade_to_real_capture
from packet_handler import SimplePacketHandler

# Add the current directory to the path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def main():
    # Parse command line arguments for config
    parser = argparse.ArgumentParser(description='Packet Capture Client')
    parser.add_argument('--config', type=str, help='Path to user config file')
    args = parser.parse_args()

    # Default settings
    username = None
    env_name = None
    env_password = None
    user_id = None

    # If config file is provided, load settings from it
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
                username = config.get('username')
                user_id = config.get('user_id')

                # Get the first environment from the config if available
                environments = config.get('environments', [])
                if environments and len(environments) > 0:
                    env_name = environments[0].get('env_name')
                    env_password = environments[0].get('env_password')
                    print(f"Using environment '{env_name}' for user '{username}'")
                else:
                    print(f"No environments found for user '{username}', using defaults")
                    env_name = "default"
                    env_password = "default_password"
        except Exception as e:
            print(f"Error loading config: {e}")
            # Set defaults if config loading fails
            env_name = "default"
            env_password = "default_password"
    else:
        # Set defaults if no config
        env_name = "default"
        env_password = "default_password"
        print("No config file provided, using default environment")

    print(f"Configuration: Username={username}, Environment={env_name}")

    # Create the root window
    root = tk.Tk()

    # Enhance the UI class with pie chart
    EnhancedPacketCaptureClientUI = integrate_pie_chart_to_ui(PacketCaptureClientUI)

    # Create the enhanced UI
    ui = EnhancedPacketCaptureClientUI(root)

    # Create the backend
    backend = StablePacketCaptureBackend(ui=ui)

    # Configure with the environment info
    backend.configure(
        capture_interface=None,  # Will be selected in UI
        server_host="localhost",
        server_port=9007,
        username=username,
        env_name=env_name,
        env_password=env_password
    )

    # Connect UI and backend
    ui.set_backend(backend)

    # Optional: Set a timer to upgrade to real packet capture after connection stability is confirmed
    # This will switch from test packets to real packet capture after 10 seconds
    root.after(10000, lambda: upgrade_to_real_capture(backend))

    # Start the main loop
    root.mainloop()


if __name__ == "__main__":
    main()
