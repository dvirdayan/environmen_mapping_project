import socket
import threading
import json
import time
import select
from datetime import datetime


class PacketServer:
    def __init__(self, host='0.0.0.0', port=9007):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server listening on {self.host}:{self.port}")

        # Dictionary to store client information by username: {username: client_info}
        self.clients_by_username = {}

        # Dictionary to track active connections: {client_addr: username}
        self.active_connections = {}

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

        # Create stats sender thread
        self.stats_thread = threading.Thread(target=self._send_stats_periodically)
        self.stats_thread.daemon = True

        self.received_packet_ids = set()
        self.packet_id_lock = threading.Lock()

    def _send_stats_periodically(self):
        """Send protocol statistics to all connected clients periodically"""
        while self.running:
            time.sleep(5)  # Send stats every 5 seconds

            # Clear old packet IDs to prevent memory issues
            # Only keep IDs from the last hour
            current_time = time.time()
            if current_time - self.last_packet_id_cleanup > 3600:
                with self.packet_id_lock:
                    if len(self.received_packet_ids) > 10000:
                        print(f"Clearing packet ID cache. Size before: {len(self.received_packet_ids)}")
                        # This is a simplistic approach - ideally you'd use timestamps
                        self.received_packet_ids = set(list(self.received_packet_ids)[-5000:])
                        print(f"New packet ID cache size: {len(self.received_packet_ids)}")
                self.last_packet_id_cleanup = current_time
            # Get a list of connected clients
            connected_clients = {}
            with self.clients_lock:
                for addr, username in self.active_connections.items():
                    if username in self.clients_by_username and self.clients_by_username[username].get('connected',
                                                                                                       False):
                        connected_clients[addr] = self.clients_by_username[username]

            if not connected_clients:
                continue

            # Send stats to each connected client
            for addr, client_info in connected_clients.items():
                try:
                    # Get environment for this client
                    env_name = client_info.get('environment', 'default')

                    # Get protocol counts for this environment
                    env_protocol_counts = {}
                    with self.environment_lock:
                        if env_name in self.environments:
                            env_protocol_counts = self.environments[env_name]['protocol_counts'].copy()
                        else:
                            env_protocol_counts = self.protocol_counts.copy()

                    # Create stats message
                    stats_message = {
                        'type': 'stats',
                        'protocol_counts': env_protocol_counts,
                        'timestamp': datetime.now().isoformat()
                    }

                    # Get client socket from addr
                    socket_conn = client_info.get('socket')
                    if socket_conn:
                        try:
                            socket_conn.sendall((json.dumps(stats_message) + '\n').encode('utf-8'))
                        except Exception as e:
                            print(f"Error sending stats to {client_info['username']}: {e}")
                            # Mark client as disconnected if we can't send to it
                            with self.clients_lock:
                                if client_info['username'] in self.clients_by_username:
                                    self.clients_by_username[client_info['username']]['connected'] = False
                except Exception as e:
                    print(f"Error preparing stats for {client_info['username']}: {e}")

    def register_ui_callback(self, callback):
        """Register a callback function that will be called when data changes"""
        self.ui_update_callback = callback

    def get_clients_data(self):
        """Get a copy of the current clients data"""
        with self.clients_lock:
            # Create a dictionary that maps active connections to client info
            result = {}
            for addr, username in self.active_connections.items():
                if username in self.clients_by_username:
                    result[addr] = self.clients_by_username[username].copy()
            return result

    def get_all_clients_data(self):
        """Get all clients data including disconnected clients"""
        with self.clients_lock:
            return self.clients_by_username.copy()

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
        """Pretty print packet information and update counts if unique"""
        try:
            packet = json.loads(packet_data)

            # Skip system/heartbeat messages
            if packet.get('type') in ['heartbeat', 'stats', 'ack']:
                return False

            # Check for a unique packet ID
            packet_id = packet.get('packet_id')
            if not packet_id:
                print(f"[SERVER] Missing packet_id from {client_addr}, ignoring")
                return False

            # Get username for this client connection
            username = None
            with self.clients_lock:
                username = self.active_connections.get(client_addr)

            if not username:
                print(f"[SERVER] Unknown client {client_addr}, ignoring packet")
                return False

            # Deduplication: skip if already processed
            with self.packet_id_lock:
                if packet_id in self.received_packet_ids:
                    print(f"[SERVER] Duplicate packet ignored from user {username}: {packet_id}")
                    return False
                self.received_packet_ids.add(packet_id)

            # Add debugging to track packet counts
            print(f"[SERVER] Processing new packet_id from user {username}: {packet_id}")

            # Determine environment
            env_name = "default"
            # Override with packet's environment if available
            packet_env = packet.get('env_name')
            if packet_env:
                env_name = packet_env

            # Determine protocol
            protocol = self.determine_protocol(packet)

            # Update client protocol counts
            with self.clients_lock:
                if username in self.clients_by_username:
                    if protocol in self.clients_by_username[username]['protocol_counts']:
                        self.clients_by_username[username]['protocol_counts'][protocol] += 1
                    else:
                        self.clients_by_username[username]['protocol_counts']['Other'] += 1

            # Update global protocol counts
            with self.protocol_lock:
                if protocol in self.protocol_counts:
                    self.protocol_counts[protocol] += 1
                else:
                    self.protocol_counts['Other'] += 1

            # Update environment-specific counts
            with self.environment_lock:
                if env_name in self.environments:
                    if protocol in self.environments[env_name]['protocol_counts']:
                        self.environments[env_name]['protocol_counts'][protocol] += 1
                    else:
                        self.environments[env_name]['protocol_counts']['Other'] += 1

                    self.environments[env_name]['packet_count'] += 1

            # Notify UI if callback is registered
            if self.ui_update_callback:
                self.ui_update_callback()

            return True

        except json.JSONDecodeError as e:
            print(f"[SERVER] Error decoding JSON: {e}")
            print(f"[SERVER] Received data: {packet_data}")
        except Exception as e:
            print(f"[SERVER] Error processing packet: {e}")

        return False

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
        print(f"New connection from {addr}")

        env_name = "default"  # Default environment for backward compatibility
        authenticated = False
        buffer = ""
        username = None

        try:
            # Make socket non-blocking for timeout handling
            conn.settimeout(10)

            # Wait for authentication message
            auth_data = conn.recv(4096).decode('utf-8')

            if auth_data:
                try:
                    auth_lines = auth_data.strip().split('\n')

                    for i, line in enumerate(auth_lines):
                        if not line.strip():
                            continue
                        try:
                            auth_json = json.loads(line)

                            if auth_json.get('type') == 'auth':
                                client_env_name = auth_json.get('env_name')
                                env_password = auth_json.get('env_password')
                                account_info = auth_json.get('account_info', {})

                                # Extract username from auth data
                                username = auth_json.get('username')
                                if not username and isinstance(account_info, dict):
                                    username = account_info.get('username')
                                if not username and isinstance(account_info, str):
                                    username = account_info
                                if not username:
                                    username = f"user_{addr[0]}_{addr[1]}"  # Fallback username

                                print(f"Client {addr} attempting authentication as user: {username}")

                                if self.verify_environment(client_env_name, env_password):
                                    env_name = client_env_name if client_env_name else "default"
                                    authenticated = True

                                    # Initialize environment if needed
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

                                    # Register or update the client
                                    with self.clients_lock:
                                        # If user exists, update connection info but keep counts
                                        if username in self.clients_by_username:
                                            # Update with new connection details
                                            self.clients_by_username[username]['connected'] = True
                                            self.clients_by_username[username]['environment'] = env_name
                                            self.clients_by_username[username]['account_info'] = account_info
                                            self.clients_by_username[username]['socket'] = conn
                                            self.clients_by_username[username]['last_addr'] = addr
                                            print(f"User {username} reconnected, preserving packet count: {self.clients_by_username[username]['packet_count']}")
                                        else:
                                            # Create new user entry
                                            self.clients_by_username[username] = {
                                                'username': username,
                                                'packet_count': 0,  # Start with 0 for new users
                                                'protocol_counts': {
                                                    'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
                                                    'FTP': 0, 'SMTP': 0, 'Other': 0
                                                },
                                                'connected': True,
                                                'environment': env_name,
                                                'account_info': account_info,
                                                'socket': conn,
                                                'last_addr': addr
                                            }
                                            print(f"New user {username} registered")

                                        # Map this connection to the username
                                        self.active_connections[addr] = username
                                    # Properly handle account_info
                                    account_info = auth_json.get('account_info')
                                    # If account_info is a string, keep it as is
                                    # If it's empty or None, set to a more helpful value
                                    if account_info in [None, "", {}, "null", "undefined"]:
                                        account_info = "No account info"
                                    with self.environment_lock:
                                        self.environments[env_name]['clients'][username] = {
                                            'username': username,
                                            'packet_count': self.clients_by_username[username]['packet_count'],
                                            'connected': True,
                                            'account_info': account_info
                                        }

                                    # Send auth success response
                                    response = {
                                        'status': 'authenticated',
                                        'message': f'Connected as user: {username}'
                                    }
                                    conn.sendall((json.dumps(response) + '\n').encode('utf-8'))

                                    # Capture any additional data (like packet lines)
                                    remaining_lines = auth_lines[i + 1:]
                                    buffer = '\n'.join(remaining_lines)
                                else:
                                    # Invalid credentials
                                    response = {
                                        'status': 'error',
                                        'message': 'Invalid credentials'
                                    }
                                    conn.sendall((json.dumps(response) + '\n').encode('utf-8'))
                                    return
                                break  # stop after handling one valid auth
                        except json.JSONDecodeError as e:
                            print(f"Error parsing JSON line: {line} - {e}")

                    if self.ui_update_callback:
                        self.ui_update_callback()

                except Exception as e:
                    print(f"Error during authentication: {e}")
                    return

            # Make socket non-blocking for the packet processing loop
            conn.setblocking(False)

            # Process remaining data in buffer
            if buffer and authenticated:
                for line in buffer.strip().split('\n'):
                    if line.strip():
                        success = self.print_packet_info(line, addr)
                        if success:
                            with self.clients_lock:
                                if username in self.clients_by_username:
                                    self.clients_by_username[username]['packet_count'] += 1

                                    # Get protocol counts for this environment
                                    env_protocol_counts = {}
                                    with self.environment_lock:
                                        if env_name in self.environments:
                                            env_protocol_counts = self.environments[env_name]['protocol_counts'].copy()

                                    # Send ACK
                                    try:
                                        ack_message = json.dumps({
                                            'type': 'ack',
                                            'protocol_counts': env_protocol_counts
                                        }) + '\n'
                                        conn.sendall(ack_message.encode('utf-8'))
                                    except Exception as e:
                                        print(f"Error sending ACK: {e}")

            # Enter main processing loop for this client
            while self.running and authenticated:
                try:
                    # Use select to check for data with a timeout
                    readable, _, _ = select.select([conn], [], [], 0.5)

                    if conn in readable:
                        data = conn.recv(4096).decode('utf-8')
                        if not data:  # Connection closed
                            print(f"Client {username} disconnected")
                            break

                        # Process packets
                        buffer += data

                        # Process complete lines (packets)
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            if line.strip():
                                success = self.print_packet_info(line, addr)
                                if success:
                                    with self.clients_lock:
                                        if username in self.clients_by_username:
                                            self.clients_by_username[username]['packet_count'] += 1

                                            # Send acknowledgment with protocol counts
                                            try:
                                                # Get protocol counts for this environment
                                                env_protocol_counts = {}
                                                with self.environment_lock:
                                                    if env_name in self.environments:
                                                        env_protocol_counts = self.environments[env_name]['protocol_counts'].copy()

                                                # Send ACK
                                                ack_message = json.dumps({
                                                    'type': 'ack',
                                                    'protocol_counts': env_protocol_counts
                                                }) + '\n'
                                                conn.sendall(ack_message.encode('utf-8'))
                                            except Exception as e:
                                                print(f"Error sending ACK: {e}")
                except (ConnectionResetError, BrokenPipeError) as e:
                    print(f"Connection with {username} was reset: {e}")
                    break
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error processing data from {username}: {e}")
                    break

        except Exception as e:
            print(f"Client handler error for {addr}: {e}")
        finally:
            # Update client status
            with self.clients_lock:
                if addr in self.active_connections:
                    username = self.active_connections[addr]
                    if username in self.clients_by_username:
                        self.clients_by_username[username]['connected'] = False
                        self.clients_by_username[username]['socket'] = None  # Remove socket reference

                    # Remove from active connections
                    del self.active_connections[addr]

            with self.environment_lock:
                if env_name in self.environments and username and username in self.environments[env_name]['clients']:
                    self.environments[env_name]['clients'][username]['connected'] = False

            # Notify UI if registered
            if self.ui_update_callback:
                self.ui_update_callback()

            # Close the connection
            try:
                conn.close()
            except:
                pass
            print(f"Connection with {username or addr} closed")

    def load_environments_from_db(self, db_file="../databaseV3/credentials.db"):
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
        # Set socket to non-blocking mode with a timeout
        self.server_socket.settimeout(1.0)

        # Start the stats sender thread
        self.stats_thread.start()

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
                    print(f"Error accepting connection: {e}")
                    time.sleep(0.1)  # Brief pause to avoid CPU hogging on repeated errors
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
    from packet_server_ui import start_ui

    server = PacketServer()
    server.load_environments_from_db()
    server.start()
    start_ui(server)
