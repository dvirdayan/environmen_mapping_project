#!/usr/bin/env python3

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
    parser.add_argument('--server', type=str, default="localhost", help='Server hostname or IP')
    parser.add_argument('--port', type=int, default=9007, help='Server port')
    args = parser.parse_args()

    # Default settings
    username = None
    env_name = None
    env_password = None
    account_info = None
    server_host = args.server
    server_port = args.port

    # If config file is provided, load settings from it
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
                username = config.get('username')
                user_id = config.get('user_id')

                # Create account_info dictionary
                if user_id:
                    account_info = {
                        "user_id": user_id,
                        "username": username
                    }

                # Get the first environment from the config if available
                environments = config.get('environments', [])
                if environments and len(environments) > 0:
                    env = environments[0]
                    env_name = env.get('env_name')
                    env_password = env.get('env_password')

                    # Add environment info to account_info
                    if account_info:
                        account_info["environment"] = env_name
                        account_info["is_admin"] = env.get('is_admin', False)

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
            account_info = None
    else:
        # Set defaults if no config
        env_name = "default"
        env_password = "default_password"
        print("No config file provided, using default environment")

    print(f"Configuration: Username={username}, Environment={env_name}")
    if account_info:
        print(f"Account info: {account_info}")

    # Create the root window
    root = tk.Tk()
    root.title(f"Network Packet Capture - {username or 'Anonymous'}")

    # Enhance the UI class with pie chart
    EnhancedPacketCaptureClientUI = integrate_pie_chart_to_ui(PacketCaptureClientUI)

    # Create the enhanced UI
    ui = EnhancedPacketCaptureClientUI(root)

    # Create the backend
    backend = StablePacketCaptureBackend(ui=ui)

    # Configure with the environment info and account info
    backend.configure(
        capture_interface=None,  # Will be selected in UI
        server_host=server_host,
        server_port=server_port,
        username=username,  # Make sure username is passed correctly
        env_name=env_name,
        env_password=env_password,
        account_info=account_info  # Make sure account_info is passed correctly
    )

    # Log the configuration details
    print(f"Configured backend with: username={username}, env={env_name}, account_info={account_info}")

    # Connect UI and backend
    ui.set_backend(backend)

    # Optional: Set a timer to upgrade to real packet capture after connection stability is confirmed
    # This will switch from test packets to real packet capture after 10 seconds
    root.after(10000, lambda: upgrade_to_real_capture(backend))

    # Log startup information
    if ui:
        ui.log_message(f"Application started - User: {username}, Environment: {env_name}")
        ui.log_message(f"Connecting to server: {server_host}:{server_port}")

    # Start the main loop
    root.mainloop()


if __name__ == "__main__":
    main()
