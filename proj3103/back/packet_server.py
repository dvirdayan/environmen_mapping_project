import socket
import threading
import json
import time
from datetime import datetime


class PacketServer:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server listening on {self.host}:{self.port}")

        # Dictionary to store client information: {client_addr: packet_count}
        self.clients = {}
        # Add environment tracking
        self.environments = {}  # Dictionary to store env data: {env_name: {clients, packets}}
        self.environment_lock = threading.Lock()

        # Add environment credential validation
        self.env_credentials = {
            # Default environment for backward compatibility
            "default": "default_password"
        }
        # Dictionary to store protocol counts: {protocol_name: count}
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'FTP': 0,
            'SMTP': 0,
            'Other': 0
        }

        # Lock for thread safety when accessing clients dictionary
        self.clients_lock = threading.Lock()

        # Lock for thread safety when accessing protocol counts
        self.protocol_lock = threading.Lock()

        # Flag to control server running state
        self.running = True

        # UI callbacks
        self.ui_update_callback = None

    def register_ui_callback(self, callback):
        """Register a callback function that will be called when data changes"""
        self.ui_update_callback = callback

    def get_clients_data(self):
        """Get a copy of the current clients data"""
        with self.clients_lock:
            return self.clients.copy()

    def get_protocol_data(self):
        """Get a copy of the current protocol data"""
        with self.protocol_lock:
            return self.protocol_counts.copy()

    def determine_protocol(self, packet):
        """Determine the protocol of a packet"""
        protocol = packet.get('protocol', '').upper()
        highest_layer = packet.get('highest_layer', '').upper()
        src_port = packet.get('source_port')
        dst_port = packet.get('destination_port')

        # Check for specific application protocols
        if highest_layer == 'HTTP' or src_port == '80' or dst_port == '80':
            return 'HTTP'
        elif highest_layer == 'TLS' or src_port == '443' or dst_port == '443':
            return 'HTTPS'
        elif highest_layer == 'FTP' or src_port == '21' or dst_port == '21':
            return 'FTP'
        elif highest_layer == 'SMTP' or src_port == '25' or dst_port == '25':
            return 'SMTP'
        # Check for transport protocols
        elif protocol == 'TCP':
            return 'TCP'
        elif protocol == 'UDP':
            return 'UDP'
        else:
            return 'Other'

    def print_packet_info(self, packet_data, client_addr):
        """Pretty print packet information"""
        try:
            packet = json.loads(packet_data)

            # Get environment for this client
            env_name = "default"
            with self.clients_lock:
                if client_addr in self.clients:
                    env_name = self.clients[client_addr].get('environment', 'default')

            # Use environment from packet if available (for newer clients)
            packet_env = packet.get('env_name')
            if packet_env:
                env_name = packet_env

            # Determine and update protocol count
            protocol = self.determine_protocol(packet)

            # Update global protocol counts
            with self.protocol_lock:
                if protocol in self.protocol_counts:
                    self.protocol_counts[protocol] += 1
                else:
                    self.protocol_counts['Other'] += 1

            # Update environment-specific protocol counts
            with self.environment_lock:
                if env_name in self.environments:
                    if protocol in self.environments[env_name]['protocol_counts']:
                        self.environments[env_name]['protocol_counts'][protocol] += 1
                    else:
                        self.environments[env_name]['protocol_counts']['Other'] += 1

                    # Increment environment packet count
                    self.environments[env_name]['packet_count'] += 1

            # Print packet info with environment
            print("\n" + "=" * 50)
            print(f"Environment: {env_name}")
            print(f"Client: {client_addr[0]}:{client_addr[1]}")
            print(f"Timestamp: {packet.get('timestamp', 'N/A')}")
            print(f"Highest Layer: {packet.get('highest_layer', 'N/A')}")
            print(f"Protocol: {packet.get('protocol', 'N/A')}")

            # Print IP information if available
            print(f"Source IP: {packet.get('source_ip', 'N/A')}")
            print(f"Destination IP: {packet.get('destination_ip', 'N/A')}")
            print(f"Source Port: {packet.get('source_port', 'N/A')}")
            print(f"Destination Port: {packet.get('destination_port', 'N/A')}")
            print(f"Packet Length: {packet.get('packet_length', 'N/A')} bytes")
            print("=" * 50 + "\n")

            # Notify UI if callback is registered
            if self.ui_update_callback:
                self.ui_update_callback()

        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            print(f"Received data: {packet_data}")
        except Exception as e:
            print(f"Error processing packet: {e}")

    # Add method to verify environment credentials
    def verify_environment(self, env_name, env_password):
        """Verify environment credentials"""
        if not env_name:
            return True  # Allow legacy clients without environment

        if env_name in self.env_credentials and self.env_credentials[env_name] == env_password:
            return True
        return False

    # Add method to add/register environments
    def add_environment(self, env_name, env_password):
        """Add or update an environment"""
        self.env_credentials[env_name] = env_password

        # Initialize environment tracking if needed
        with self.environment_lock:
            if env_name not in self.environments:
                self.environments[env_name] = {
                    'clients': {},
                    'protocol_counts': {
                        'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
                        'FTP': 0, 'SMTP': 0, 'Other': 0
                    },
                    'packet_count': 0
                }
        return True

    def get_environment_data(self):
        """Get a copy of the current environment data"""
        with self.environment_lock:
            return self.environments.copy()

    def get_environment_clients(self, env_name):
        """Get clients for a specific environment"""
        with self.environment_lock:
            if env_name in self.environments:
                return self.environments[env_name]['clients'].copy()
            return {}

    def get_environment_protocol_data(self, env_name):
        """Get protocol data for a specific environment"""
        with self.environment_lock:
            if env_name in self.environments:
                return self.environments[env_name]['protocol_counts'].copy()
            return {}

    def handle_client(self, conn, addr):
        print(f"New client connected from {addr}")

        env_name = "default"  # Default environment for backward compatibility
        authenticated = False
        buffer = ""

        # Wait for authentication message
        auth_data = conn.recv(4096).decode('utf-8')
        if auth_data:
            try:
                auth_json = json.loads(auth_data)
                if auth_json.get('type') == 'auth':
                    client_env_name = auth_json.get('env_name')
                    env_password = auth_json.get('env_password')
                    account_info = auth_json.get('account_info')  # Get account information
                    print(f"Client {addr} authenticated for environment: {client_env_name}")

                    if self.verify_environment(client_env_name, env_password):
                        env_name = client_env_name if client_env_name else "default"
                        authenticated = True

                        # Initialize environment if it doesn't exist
                        with self.environment_lock:
                            if env_name not in self.environments:
                                self.environments[env_name] = {
                                    'clients': {},
                                    'protocol_counts': {
                                        'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
                                        'FTP': 0, 'SMTP': 0, 'Other': 0
                                    },
                                    'packet_count': 0
                                }

                        # Register the new client with environment and account info
                        with self.clients_lock:
                            self.clients[addr] = {
                                'packet_count': 0,
                                'connected': True,
                                'environment': env_name,
                                'account_info': account_info  # Store account information
                            }

                        # Also register in the environment tracking
                        with self.environment_lock:
                            if env_name in self.environments:
                                self.environments[env_name]['clients'][addr] = {
                                    'packet_count': 0,
                                    'connected': True,
                                    'account_info': account_info  # Store account information
                                }

                        # Send success response
                        conn.sendall(json.dumps({
                            'status': 'authenticated',
                            'message': f'Connected to environment: {env_name}'
                        }).encode('utf-8'))
                    else:
                        # Send failure response
                        conn.sendall(json.dumps({
                            'status': 'error',
                            'message': 'Invalid environment credentials'
                        }).encode('utf-8'))
                        return
            except json.JSONDecodeError:
                # Backward compatibility - assume it's a packet
                buffer = auth_data
                authenticated = True

            # Notify UI of new client
            if self.ui_update_callback:
                self.ui_update_callback()

        buffer = ""
        try:
            while self.running:
                data = conn.recv(8192).decode('utf-8', errors='ignore')
                if not data:
                    break

                buffer += data

                # Try to find complete JSON objects
                while buffer:
                    try:
                        # Try to parse the buffer as JSON
                        json.loads(buffer)
                        self.print_packet_info(buffer, addr)
                        buffer = ""  # Clear buffer after successful parsing

                        # Send acknowledgment back to client with packet count
                        try:
                            # Increment packet count
                            with self.clients_lock:
                                self.clients[addr]['packet_count'] += 1
                                current_count = self.clients[addr]['packet_count']

                            # Send packet count with acknowledgment
                            ack_with_count = f"Packet received|{current_count}\n"
                            conn.sendall(ack_with_count.encode('utf-8'))
                        except socket.error:
                            print("Error sending acknowledgment")
                            return
                        break
                    except json.JSONDecodeError as e:
                        if "Extra data" in str(e):
                            # Find the position of the first complete JSON object
                            pos = str(e).find('Extra data')
                            if pos != -1:
                                try:
                                    valid_json = buffer[:pos]
                                    self.print_packet_info(valid_json, addr)
                                    buffer = buffer[pos:]

                                    # Increment packet count and send count to client
                                    with self.clients_lock:
                                        self.clients[addr]['packet_count'] += 1
                                        current_count = self.clients[addr]['packet_count']

                                    # Send packet count with acknowledgment
                                    ack_with_count = f"Packet received|{current_count}\n"
                                    conn.sendall(ack_with_count.encode('utf-8'))
                                except Exception as e:
                                    print(f"Error processing partial JSON: {e}")
                                    buffer = ""
                        else:
                            # If we can't parse the JSON yet, wait for more data
                            break

        except socket.error as e:
            print(f"Socket error with client {addr}: {e}")
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
            print(f"Connection from {addr} closed")

            # Mark client as disconnected
            with self.clients_lock:
                if addr in self.clients:
                    self.clients[addr]['connected'] = False

            # Notify UI of client disconnect
            if self.ui_update_callback:
                self.ui_update_callback()

    def load_environments_from_db(self, db_file="credentials.db"):
        """Load environments from the credential database"""
        try:
            import sqlite3
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()

            # Query all unique environment names and passwords
            cursor.execute("""
                SELECT DISTINCT env_name, env_password 
                FROM environments
            """)

            for row in cursor.fetchall():
                env_name, env_password = row
                self.add_environment(env_name, env_password)

            conn.close()
            print(f"Loaded {len(self.env_credentials)} environments from database")
        except Exception as e:
            print(f"Error loading environments from database: {e}")
            print("Using default environment only")

    def start(self):
        accept_thread = threading.Thread(target=self._accept_connections)
        accept_thread.daemon = True
        accept_thread.start()

    def _accept_connections(self):
        """Accept connections in a separate thread"""
        try:
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
        except Exception as e:
            if self.running:  # Only log error if not intentionally shutting down
                print(f"Error accepting connections: {e}")
        finally:
            print("Connection acceptor thread stopped")

    def stop(self):
        """Stop the server"""
        print("\nServer shutting down...")
        self.running = False
        self.server_socket.close()


if __name__ == "__main__":
    # If this file is run directly, import and start the UI
    from packet_server_ui import start_ui

    server = PacketServer()
    server.start()

    # Start the UI with a reference to the server
    start_ui(server)