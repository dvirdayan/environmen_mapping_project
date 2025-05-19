#!/usr/bin/env python3
"""
Main entry point for the Packet Server application.
This script starts both the server backend and the UI frontend.
"""

from packet_server import PacketServer
from packet_server_ui import start_ui


def main():
    # Create and start the server
    print("Starting Packet Server...")
    server = PacketServer()

    # Load environments from the credential database
    server.load_environments_from_db()

    server.start()

    # Start the UI with a reference to the server
    print("Starting Packet Monitor UI...")
    start_ui(server)

    print("Application terminated.")


if __name__ == "__main__":
    main()
