#!/usr/bin/env python3
"""
Main entry point for the Packet Server application with encryption support.
This script starts both the server backend and the UI frontend.
"""

import sys
import os

# Try to import encrypted version, fall server_side to regular version
try:
    from encrypted_packet_server import EncryptedPacketServer as PacketServer
    from crypto_handler import CRYPTO_AVAILABLE

    ENCRYPTION_AVAILABLE = True
except ImportError:
    from packet_server import PacketServer

    ENCRYPTION_AVAILABLE = False
    CRYPTO_AVAILABLE = False

from packet_server_ui import start_ui


def main():
    # Parse command line arguments
    enable_encryption = '--no-encryption' not in sys.argv
    show_help = '--help' in sys.argv or '-h' in sys.argv

    if show_help:
        print("Packet Server - Network Packet Monitoring System")
        print("\nUsage: python runserver.py [options]")
        print("\nOptions:")
        print("  --no-encryption    Disable encryption (run in plain text mode)")
        print("  --help, -h         Show this help message")
        print("\nEncryption status:")
        if ENCRYPTION_AVAILABLE and CRYPTO_AVAILABLE:
            print("  ✓ Encryption module available")
            print("  ✓ Cryptography library installed")
            print("  → Encryption ENABLED by default")
        elif ENCRYPTION_AVAILABLE and not CRYPTO_AVAILABLE:
            print("  ✓ Encryption module available")
            print("  ✗ Cryptography library NOT installed")
            print("  → Run: pip install pycryptodome")
        else:
            print("  ✗ Encryption module not found")
            print("  → Add encrypted_packet_server.py and crypto_handler.py")
        sys.exit(0)

    # Check encryption availability
    if enable_encryption and not ENCRYPTION_AVAILABLE:
        print("=" * 60)
        print("WARNING: Encryption module not found!")
        print("The server will run in UNENCRYPTED mode.")
        print("\nTo enable encryption:")
        print("1. Add crypto_handler.py to your project")
        print("2. Add encrypted_packet_server.py to your project")
        print("3. Install pycryptodome: pip install pycryptodome")
        print("=" * 60)
        print()
        enable_encryption = False

    elif enable_encryption and ENCRYPTION_AVAILABLE and not CRYPTO_AVAILABLE:
        print("=" * 60)
        print("WARNING: Cryptography library not installed!")
        print("The server will run in UNENCRYPTED mode.")
        print("\nTo enable encryption:")
        print("Run: pip install pycryptodome")
        print("=" * 60)
        print()
        enable_encryption = False

    # Create and start the server
    print("Starting Packet Server...")

    if ENCRYPTION_AVAILABLE and enable_encryption:
        print("→ Encryption: ENABLED (RSA + AES)")
        server = PacketServer(enable_encryption=True)
    else:
        if enable_encryption:
            print("→ Encryption: DISABLED (not available)")
        else:
            print("→ Encryption: DISABLED (by user request)")
        server = PacketServer()

    # Show server info
    print(f"→ Server Address: {server.host}:{server.port}")

    # Load environments from the credential database
    print("→ Loading environments from database...")
    server.load_environments_from_db()

    # Start the server
    server.start()

    # Start the UI with a reference to the server
    print("→ Starting Packet Monitor UI...")
    print("\nServer is ready and listening for connections.")

    if ENCRYPTION_AVAILABLE and enable_encryption:
        print("\nClients will connect using encrypted communication.")
        print("RSA key exchange will happen during connection setup.")
        print("All packet data will be encrypted with AES-256.")
    else:
        print("\nWARNING: Communication is NOT encrypted!")
        print("Consider enabling encryption for production use.")

    print("\nPress Ctrl+C in the UI window to stop the server.")
    print("-" * 60)

    # Start UI (this will block until window is closed)
    start_ui(server)

    print("\nApplication terminated.")


if __name__ == "__main__":
    main()