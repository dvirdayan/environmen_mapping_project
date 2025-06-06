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
        # NEW: Track admin dashboard connections separately
        self.admin_dashboard_connections = {}  # {client_addr: username}
        self.admin_dashboard_clients = set()  # usernames of admin dashboard connections
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
        # Track processed packet IDs to prevent duplicate counting globally
        self.processed_packet_ids = set()
        self.processed_packets_lock = threading.Lock()
        self.last_packet_id_cleanup = time.time()
        # Admin tracking
        self.admin_clients = set()
        self.client_connect_times = {}

    def _send_stats_periodically(self):
        """Send protocol statistics to all connected clients periodically"""
        while self.running:
            time.sleep(20)  # **LAG FIX: Send stats every 20 seconds instead of 5**

            # Clear old packet IDs to prevent memory issues
            current_time = time.time()
            if current_time - self.last_packet_id_cleanup > 3600:  # 1 hour
                with self.processed_packets_lock:
                    if len(self.processed_packet_ids) > 10000:
                        print(f"[SERVER] Clearing packet ID cache. Size before: {len(self.processed_packet_ids)}")
                        # Keep only the most recent half
                        self.processed_packet_ids = set(list(self.processed_packet_ids)[-5000:])
                        print(f"[SERVER] New packet ID cache size: {len(self.processed_packet_ids)}")
                self.last_packet_id_cleanup = current_time

            # Get a list of connected clients (excluding admin dashboards)
            connected_clients = {}
            with self.clients_lock:
                for addr, username in self.active_connections.items():
                    # NEW: Skip admin dashboard connections
                    if addr in self.admin_dashboard_connections:
                        continue

                    if username in self.clients_by_username and self.clients_by_username[username].get('connected',
                                                                                                       False):
                        connected_clients[addr] = self.clients_by_username[username]

            # NEW: Also send stats to admin dashboard connections
            admin_dashboard_clients = {}
            with self.clients_lock:
                for addr, username in self.admin_dashboard_connections.items():
                    if username in self.clients_by_username and self.clients_by_username[username].get('connected',
                                                                                                       False):
                        admin_dashboard_clients[addr] = self.clients_by_username[username]

            # Combine all clients that should receive stats
            all_clients_for_stats = {**connected_clients, **admin_dashboard_clients}

            if not all_clients_for_stats:
                continue

            # Send global stats to each connected client (including admin dashboards)
            for addr, client_info in all_clients_for_stats.items():
                try:
                    # Get global protocol counts
                    with self.protocol_lock:
                        global_protocol_counts = self.protocol_counts.copy()

                    # Create global stats message
                    global_stats_message = {
                        'type': 'stats',
                        'protocol_counts': global_protocol_counts,
                        'timestamp': datetime.now().isoformat()
                    }

                    # Get client socket from addr
                    socket_conn = client_info.get('socket')
                    if socket_conn:
                        try:
                            socket_conn.sendall((json.dumps(global_stats_message) + '\n').encode('utf-8'))
                        except Exception as e:
                            print(f"[SERVER] Error sending global stats to {client_info['username']}: {e}")
                            # Mark client as disconnected if we can't send to it
                            with self.clients_lock:
                                if client_info['username'] in self.clients_by_username:
                                    self.clients_by_username[client_info['username']]['connected'] = False

                    # Now send environment-specific stats for each client's environments
                    client_environments = client_info.get('environments', [])
                    for env_name in client_environments:
                        # Get protocol counts for this environment
                        with self.environment_lock:
                            if env_name in self.environments:
                                env_protocol_counts = self.environments[env_name]['protocol_counts'].copy()
                            else:
                                continue  # Skip if no data for this environment

                        # Create environment-specific stats message
                        env_stats_message = {
                            'type': 'stats',
                            'environment': env_name,
                            'protocol_counts': env_protocol_counts,
                            'timestamp': datetime.now().isoformat()
                        }

                        # Send environment stats
                        if socket_conn:
                            try:
                                socket_conn.sendall((json.dumps(env_stats_message) + '\n').encode('utf-8'))
                            except Exception as e:
                                print(f"[SERVER] Error sending {env_name} stats to {client_info['username']}: {e}")
                except Exception as e:
                    print(f"[SERVER] Error preparing stats for {client_info['username']}: {e}")

            # Send admin stats to admin clients every 2 seconds
            if int(time.time()) % 2 == 0:  # Every 2 seconds
                for username in list(self.admin_clients):
                    try:
                        # Find client address (check both regular and dashboard connections)
                        client_addr = None
                        with self.clients_lock:
                            # Check regular connections first
                            for addr, uname in self.active_connections.items():
                                if uname == username:
                                    client_addr = addr
                                    break

                            # If not found, check admin dashboard connections
                            if not client_addr:
                                for addr, uname in self.admin_dashboard_connections.items():
                                    if uname == username:
                                        client_addr = addr
                                        break

                        if client_addr:
                            request_data = {'type': 'admin_stats_request'}
                            self.handle_admin_request(request_data, client_addr)
                    except Exception as e:
                        print(f"[SERVER] Error sending admin stats to {username}: {e}")

    def register_ui_callback(self, callback):
        """Register a callback function that will be called when data changes"""
        self.ui_update_callback = callback

    def get_clients_data(self):
        """Get a copy of the current clients data (excluding admin dashboards)"""
        with self.clients_lock:
            # Create a dictionary that maps active connections to client info
            # NEW: Exclude admin dashboard connections
            result = {}
            for addr, username in self.active_connections.items():
                # Skip admin dashboard connections
                if addr in self.admin_dashboard_connections:
                    continue

                if username in self.clients_by_username:
                    result[addr] = self.clients_by_username[username].copy()
            return result

    def get_all_clients_data(self):
        """Get all clients data including disconnected clients (excluding admin dashboards)"""
        with self.clients_lock:
            # NEW: Filter out admin dashboard clients from the result
            result = {}
            for username, client_info in self.clients_by_username.items():
                # Skip if this is an admin dashboard client
                if username in self.admin_dashboard_clients:
                    continue
                result[username] = client_info.copy()
            return result

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

    def handle_admin_request(self, request_data, client_addr):
        """Handle admin statistics requests"""
        username = None
        with self.clients_lock:
            # Check both regular and admin dashboard connections
            username = self.active_connections.get(client_addr)
            if not username:
                username = self.admin_dashboard_connections.get(client_addr)

        if not username or username not in self.admin_clients:
            return  # Not an admin

        # Prepare admin data
        admin_data = {
            'type': 'admin_stats',
            'data': {
                'clients': {},
                'global_protocols': {},
                'environments': {}
            }
        }

        # NEW: Gather client data (excluding admin dashboard connections)
        with self.clients_lock:
            for addr, uname in self.active_connections.items():
                # Skip admin dashboard connections
                if addr in self.admin_dashboard_connections:
                    continue

                if uname in self.clients_by_username:
                    client_info = self.clients_by_username[uname].copy()
                    # Add connection info
                    client_info['ip'] = addr[0]
                    client_info['port'] = addr[1]
                    client_info['connect_time'] = self.client_connect_times.get(uname, 0)
                    # Remove socket object
                    client_info.pop('socket', None)
                    admin_data['data']['clients'][f"{addr[0]}:{addr[1]}"] = client_info

        # Add global protocol counts
        with self.protocol_lock:
            admin_data['data']['global_protocols'] = self.protocol_counts.copy()

        # Add environment data
        with self.environment_lock:
            for env_name, env_data in self.environments.items():
                admin_data['data']['environments'][env_name] = {
                    'clients': list(env_data['clients'].keys()),
                    'protocol_counts': env_data['protocol_counts'].copy(),
                    'packet_count': env_data['packet_count']
                }

        # Send to requesting admin
        try:
            socket_conn = None
            with self.clients_lock:
                if username in self.clients_by_username:
                    socket_conn = self.clients_by_username[username].get('socket')

            if socket_conn:
                socket_conn.sendall((json.dumps(admin_data) + '\n').encode('utf-8'))
                # Only log for non-dashboard connections to reduce spam
                if client_addr not in self.admin_dashboard_connections:
                    print(f"[SERVER] Sent admin stats to {username}")
        except Exception as e:
            print(f"[SERVER] Error sending admin stats: {e}")

    def process_packet(self, packet_data, client_addr, environments=None):
        """
        Process a packet and update counts for specified environments

        Args:
            packet_data: JSON string with packet information
            client_addr: Client address tuple (IP, port)
            environments: List of environment names to process this packet for

        Returns:
            Boolean indicating success
        """
        try:
            packet = json.loads(packet_data)

            # Handle admin stats request
            if packet.get('type') == 'admin_stats_request':
                self.handle_admin_request(packet, client_addr)
                return True

            # Skip system/heartbeat messages
            if packet.get('type') in ['heartbeat', 'stats', 'ack']:
                return False

            # NEW: Skip packet processing for admin dashboard connections
            with self.clients_lock:
                if client_addr in self.admin_dashboard_connections:
                    return False  # Admin dashboards don't send packets

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

            # Use environments from the packet if provided
            if not environments:
                # Get environments from packet
                packet_envs = packet.get('environments', [])
                # If not specified, use a default or the client's environments
                if not packet_envs:
                    packet_envs = packet.get('env_name', 'default')
                    if isinstance(packet_envs, str):
                        packet_envs = [packet_envs]
                environments = packet_envs

            # Determine protocol
            protocol = self.determine_protocol(packet)

            # Single deduplication check
            is_new_packet = False
            with self.processed_packets_lock:
                if packet_id not in self.processed_packet_ids:
                    self.processed_packet_ids.add(packet_id)
                    is_new_packet = True

                    # Limit the size of the processed_packet_ids set to prevent memory issues
                    if len(self.processed_packet_ids) > 20000:
                        # Keep only the most recent 10000 packet IDs
                        self.processed_packet_ids = set(list(self.processed_packet_ids)[-10000:])
                else:
                    print(f"[SERVER] Duplicate packet ignored from user {username}: {packet_id}")
                    return False

            # Only process new packets
            if is_new_packet:
                print(f"[SERVER] Processing new packet from {username}: {packet_id}, protocol: {protocol}")

                # Update client protocol counts
                with self.clients_lock:
                    if username in self.clients_by_username:
                        if protocol in self.clients_by_username[username]['protocol_counts']:
                            self.clients_by_username[username]['protocol_counts'][protocol] += 1
                        else:
                            self.clients_by_username[username]['protocol_counts']['Other'] += 1

                        # Increment client packet count
                        self.clients_by_username[username]['packet_count'] += 1
                        print(
                            f"[SERVER] Client {username} packet count: {self.clients_by_username[username]['packet_count']}")

                # Update global protocol counts
                with self.protocol_lock:
                    if protocol in self.protocol_counts:
                        self.protocol_counts[protocol] += 1
                    else:
                        self.protocol_counts['Other'] += 1

                    total_global = sum(self.protocol_counts.values())
                    print(
                        f"[SERVER] Global protocol counts - {protocol}: {self.protocol_counts[protocol]}, Total: {total_global}")

                # Process each specified environment
                for env_name in environments:
                    # Skip invalid environments
                    if not env_name:
                        continue

                    # Check if client is authorized for this environment
                    with self.clients_lock:
                        client_envs = self.clients_by_username[username].get('environments', [])
                        if env_name not in client_envs:
                            print(f"[SERVER] Client {username} not authorized for {env_name}, skipping")
                            continue

                    # Update environment-specific counts
                    with self.environment_lock:
                        if env_name in self.environments:
                            if protocol in self.environments[env_name]['protocol_counts']:
                                self.environments[env_name]['protocol_counts'][protocol] += 1
                            else:
                                self.environments[env_name]['protocol_counts']['Other'] += 1

                            self.environments[env_name]['packet_count'] += 1
                            env_total = sum(self.environments[env_name]['protocol_counts'].values())
                            print(
                                f"[SERVER] Environment {env_name} - {protocol}: "
                                f"{self.environments[env_name]['protocol_counts'][protocol]}, Total: {env_total}")
                        else:
                            print(f"[SERVER] Environment {env_name} not found, skipping")

                # Send acknowledgment with all environment info in a single ACK
                try:
                    # Get client socket
                    socket_conn = None
                    with self.clients_lock:
                        if username in self.clients_by_username:
                            socket_conn = self.clients_by_username[username].get('socket')

                    if socket_conn:
                        # Create a single ACK message with packet ID and all environment info
                        ack_message = {
                            'type': 'ack',
                            'packet_id': packet_id,
                            'environments': environments,
                            'timestamp': datetime.now().isoformat()
                        }

                        # **FIXED: Don't send protocol counts in ACK to avoid conflicts**
                        # Let the periodic stats handle protocol count updates

                        # Send the ACK
                        socket_conn.sendall((json.dumps(ack_message) + '\n').encode('utf-8'))
                        print(f"[SERVER] Sent ACK for packet {packet_id}")
                except Exception as e:
                    print(f"[SERVER] Error sending ACK: {e}")

                # Notify UI if callback is registered
                if self.ui_update_callback:
                    self.ui_update_callback()

                return True
            else:
                return False

        except json.JSONDecodeError as e:
            print(f"[SERVER] Error decoding JSON: {e}")
            print(f"[SERVER] Received data: {packet_data}")
        except Exception as e:
            print(f"[SERVER] Error processing packet: {e}")
            import traceback
            traceback.print_exc()

        return False

    def add_environment(self, env_name, env_password=None):
        """Add or update an environment - no password verification"""
        # Store credentials for reference if provided
        if env_password:
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
                print(f"[SERVER] Added environment: {env_name}")
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
        print(f"[SERVER] New connection from {addr}")

        authenticated = False
        buffer = ""
        username = None
        verified_environments = []  # List of environments this client has access to
        is_admin = False
        is_admin_dashboard = False  # NEW: Track if this is an admin dashboard connection

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
                                # Extract username from auth data
                                username = auth_json.get('username')
                                account_info = auth_json.get('account_info', {})

                                if not username and isinstance(account_info, dict):
                                    username = account_info.get('username')
                                if not username and isinstance(account_info, str):
                                    username = account_info
                                if not username:
                                    username = f"user_{addr[0]}_{addr[1]}"  # Fallback username

                                # NEW: Check if this is an admin dashboard connection
                                is_admin_dashboard = auth_json.get('is_admin_dashboard', False)

                                if is_admin_dashboard:
                                    print(f"[SERVER] Admin dashboard connection from {addr} as user: {username}")
                                else:
                                    print(f"[SERVER] Client {addr} attempting authentication as user: {username}")

                                # Check if admin user
                                if auth_json.get('is_admin'):
                                    is_admin = True
                                    self.admin_clients.add(username)
                                    if is_admin_dashboard:
                                        print(f"[SERVER] Admin dashboard user {username} connected")
                                    else:
                                        print(f"[SERVER] Admin user {username} connected")

                                # Track connection time
                                self.client_connect_times[username] = time.time()

                                # Handle multiple environments
                                environments = auth_json.get('environments', [])

                                # For backward compatibility
                                if not environments:
                                    # Try legacy format (single environment)
                                    env_name = auth_json.get('env_name')
                                    env_password = auth_json.get('env_password')

                                    if env_name:
                                        environments = [{'env_name': env_name, 'env_password': env_password}]
                                    else:
                                        # Default environment
                                        environments = [{'env_name': 'default', 'env_password': 'default_password'}]

                                # CHANGE: SKIP ENVIRONMENT VERIFICATION - PASSWORDS ALREADY VERIFIED
                                # Just extract the environment names
                                verified_environments = [env.get('env_name') for env in environments if
                                                         env.get('env_name')]

                                print(f"[SERVER] Accepting environments without verification: {verified_environments}")
                                authenticated = True

                                # Initialize environments if needed
                                for env in environments:
                                    env_name = env.get('env_name')
                                    env_password = env.get('env_password')

                                    if env_name in verified_environments:
                                        # Add/initialize environment without verification
                                        self.add_environment(env_name, env_password)

                                        # Add client to environment (only for non-admin dashboard connections)
                                        if not is_admin_dashboard:
                                            with self.environment_lock:
                                                self.environments[env_name]['clients'][username] = {
                                                    'username': username,
                                                    'connected': True,
                                                    'account_info': account_info
                                                }

                                # Register or update the client with multiple environments
                                with self.clients_lock:
                                    # If user exists, update connection info but keep counts
                                    if username in self.clients_by_username:
                                        # Update with new connection details
                                        self.clients_by_username[username]['connected'] = True
                                        self.clients_by_username[username]['environments'] = verified_environments
                                        self.clients_by_username[username]['account_info'] = account_info
                                        self.clients_by_username[username]['socket'] = conn
                                        self.clients_by_username[username]['last_addr'] = addr

                                        if is_admin_dashboard:
                                            print(f"[SERVER] Admin dashboard {username} reconnected")
                                        else:
                                            print(
                                                f"[SERVER] User {username} reconnected with environments: {verified_environments}")
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
                                            'environments': verified_environments,
                                            'account_info': account_info,
                                            'socket': conn,
                                            'last_addr': addr
                                        }

                                        if is_admin_dashboard:
                                            print(f"[SERVER] New admin dashboard {username} registered")
                                        else:
                                            print(
                                                f"[SERVER] New user {username} registered with environments: {verified_environments}")

                                    # NEW: Map connection based on type
                                    if is_admin_dashboard:
                                        # Track as admin dashboard connection
                                        self.admin_dashboard_connections[addr] = username
                                        self.admin_dashboard_clients.add(username)
                                    else:
                                        # Map as regular client connection
                                        self.active_connections[addr] = username

                                # Send auth success response with verified environments
                                response = {
                                    'status': 'authenticated',
                                    'message': f'Connected as {"admin dashboard" if is_admin_dashboard else "user"}: {username}',
                                    'environments': verified_environments
                                }
                                conn.sendall((json.dumps(response) + '\n').encode('utf-8'))

                                # Capture any additional data (like packet lines)
                                remaining_lines = auth_lines[i + 1:]
                                buffer = '\n'.join(remaining_lines)
                                break  # stop after handling one valid auth
                        except json.JSONDecodeError as e:
                            print(f"[SERVER] Error parsing JSON line: {line} - {e}")

                    if self.ui_update_callback:
                        self.ui_update_callback()

                except Exception as e:
                    print(f"[SERVER] Error during authentication: {e}")
                    return

            # Make socket non-blocking for the packet processing loop
            conn.setblocking(False)

            # Process remaining data in buffer
            if buffer and authenticated:
                for line in buffer.strip().split('\n'):
                    if line.strip():
                        self.process_packet(line, addr, verified_environments)

            # Enter main processing loop for this client
            while self.running and authenticated:
                try:
                    # Use select to check for data with a timeout
                    readable, _, _ = select.select([conn], [], [], 0.5)

                    if conn in readable:
                        data = conn.recv(4096).decode('utf-8')
                        if not data:  # Connection closed
                            dashboard_text = " (admin dashboard)" if is_admin_dashboard else ""
                            print(f"[SERVER] Client {username}{dashboard_text} disconnected")
                            break

                        # Process packets (admin dashboards may send admin requests)
                        buffer += data

                        # Process complete lines (packets)
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            if line.strip():
                                # Extract environments from packet if possible
                                try:
                                    packet_json = json.loads(line)
                                    packet_environments = packet_json.get('environments', [])

                                    # If not specified in packet, use all verified environments
                                    if not packet_environments:
                                        packet_environments = verified_environments

                                    # Process packet for specified environments (intersection with verified)
                                    valid_envs = [env for env in packet_environments if env in verified_environments]

                                    if valid_envs or is_admin_dashboard:  # Admin dashboards can send without environments
                                        self.process_packet(line, addr, valid_envs)
                                except json.JSONDecodeError:
                                    # If can't parse JSON, use all verified environments
                                    if not is_admin_dashboard:  # Only regular clients send packets
                                        self.process_packet(line, addr, verified_environments)

                except (ConnectionResetError, BrokenPipeError) as e:
                    dashboard_text = " (admin dashboard)" if is_admin_dashboard else ""
                    print(f"[SERVER] Connection with {username}{dashboard_text} was reset: {e}")
                    break
                except socket.timeout:
                    continue
                except Exception as e:
                    dashboard_text = " (admin dashboard)" if is_admin_dashboard else ""
                    print(f"[SERVER] Error processing data from {username}{dashboard_text}: {e}")
                    break

        except Exception as e:
            print(f"[SERVER] Client handler error for {addr}: {e}")
        finally:
            # Update client status
            with self.clients_lock:
                # NEW: Handle cleanup for both connection types
                if addr in self.active_connections:
                    username = self.active_connections[addr]
                    if username in self.clients_by_username:
                        self.clients_by_username[username]['connected'] = False
                        self.clients_by_username[username]['socket'] = None  # Remove socket reference

                    # Remove from active connections
                    del self.active_connections[addr]

                elif addr in self.admin_dashboard_connections:
                    username = self.admin_dashboard_connections[addr]
                    if username in self.clients_by_username:
                        self.clients_by_username[username]['connected'] = False
                        self.clients_by_username[username]['socket'] = None  # Remove socket reference

                    # Remove from admin dashboard connections
                    del self.admin_dashboard_connections[addr]

                    # Remove from admin dashboard clients set
                    if username in self.admin_dashboard_clients:
                        self.admin_dashboard_clients.remove(username)

            # Remove from admin clients if admin
            if username and username in self.admin_clients:
                self.admin_clients.remove(username)
                dashboard_text = " (admin dashboard)" if is_admin_dashboard else ""
                print(f"[SERVER] Admin user {username}{dashboard_text} disconnected")

            # Update environment status (only for non-admin dashboard connections)
            if not is_admin_dashboard:
                with self.environment_lock:
                    for env_name in verified_environments:
                        if env_name in self.environments and username and username in self.environments[env_name][
                            'clients']:
                            self.environments[env_name]['clients'][username]['connected'] = False

            # Notify UI if registered
            if self.ui_update_callback:
                self.ui_update_callback()

            # Close the connection
            try:
                conn.close()
            except:
                pass

            dashboard_text = " (admin dashboard)" if is_admin_dashboard else ""
            print(f"[SERVER] Connection with {username or addr}{dashboard_text} closed")

    def load_environments_from_db(self, db_file="credentials.db"):

        try:
            import sqlite3
            import os

            # Get the absolute path of the parent directory of the current script
            current_dir = os.path.dirname(os.path.abspath(__file__))

            # Try multiple possible locations for the database
            possible_paths = [
                db_file,  # Current directory
                os.path.join(current_dir, db_file),  # Same directory as script
                os.path.join(current_dir, "../..", "client_side", db_file),  # ../client_side/ directory
                os.path.join(current_dir, "../..", db_file),  # Parent directory
                os.path.abspath(db_file)  # Absolute path provided
            ]

            # Find the first path that exists
            db_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    db_path = path
                    break

            if not db_path:
                print(f"[SERVER] Could not find database file. Tried paths: {possible_paths}")
                print("[SERVER] Using default environment only")

                # Add 'C1' and 'test' environments with default passwords
                self.add_environment('C1', 'CCC')
                self.add_environment('test', 'test')
                return

            # Connect to the found database
            print(f"[SERVER] Found database at: {db_path}")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Print database schema for debugging
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            print(f"[SERVER] Database tables: {tables}")

            if ('environments',) in tables:
                # Query all unique environment names and passwords
                cursor.execute("""
                    SELECT DISTINCT env_name, env_password 
                    FROM environments
                """)

                env_count = 0
                for row in cursor.fetchall():
                    env_name, env_password = row
                    self.add_environment(env_name, env_password)
                    env_count += 1
                    print(f"[SERVER] Loaded environment: {env_name} with password: {env_password}")

                print(f"[SERVER] Loaded {env_count} environments from database at {db_path}")
            else:
                print("[SERVER] No 'environments' table found in database")
                print("[SERVER] Adding default environments")
                # Add 'C1' and 'test' environments with default passwords
                self.add_environment('C1', 'CCC')
                self.add_environment('test', 'test')

            conn.close()
        except Exception as e:
            print(f"[SERVER] Error loading environments from database: {e}")
            print("[SERVER] Using default environment only")
            # Add 'C1' and 'test' environments with default passwords
            self.add_environment('C1', 'CCC')
            self.add_environment('test', 'test')

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
                    print(f"[SERVER] Error accepting connection: {e}")
                    time.sleep(0.1)  # Brief pause to avoid CPU hogging on repeated errors
        except Exception as e:
            if self.running:  # Only log error if not intentionally shutting down
                print(f"[SERVER] Error accepting connections: {e}")
        finally:
            print("[SERVER] Connection acceptor thread stopped")

    def stop(self):
        """Stop the server"""
        print("\n[SERVER] Server shutting down...")
        self.running = False
        self.server_socket.close()


if __name__ == "__main__":
    from packet_server_ui import start_ui

    server = PacketServer()
    server.load_environments_from_db()
    server.start()
    start_ui(server)
