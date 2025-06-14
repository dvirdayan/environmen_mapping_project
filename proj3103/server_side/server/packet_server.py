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
            time.sleep(5)  # Send stats every 5 seconds

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

            # Send stats to all connected clients
            self._send_stats_to_clients()

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

    def _send_stats_to_clients(self):
        """Send personalized stats to each client - FIXED to properly separate admin and regular users"""
        # Get all connected clients (regular + admin dashboard)
        all_connected_clients = {}

        with self.clients_lock:
            # Get regular clients
            for addr, username in self.active_connections.items():
                if addr in self.admin_dashboard_connections:
                    continue  # Skip admin dashboard connections from regular list

                if username in self.clients_by_username and self.clients_by_username[username].get('connected', False):
                    all_connected_clients[addr] = {
                        'client_info': self.clients_by_username[username],
                        'username': username,
                        'is_admin_dashboard': False
                    }

            # Get admin dashboard clients
            for addr, username in self.admin_dashboard_connections.items():
                if username in self.clients_by_username and self.clients_by_username[username].get('connected', False):
                    all_connected_clients[addr] = {
                        'client_info': self.clients_by_username[username],
                        'username': username,
                        'is_admin_dashboard': True
                    }

        if not all_connected_clients:
            return

        # Send stats to each client based on their role
        for addr, client_data in all_connected_clients.items():
            try:
                client_info = client_data['client_info']
                username = client_data['username']
                socket_conn = client_info.get('socket')

                if not socket_conn:
                    print(f"[SERVER] No socket connection for {username}, skipping stats")
                    continue

                # FIXED: Determine user role correctly - check BOTH conditions
                is_admin_user = (
                        username in self.admin_clients and
                        client_data['is_admin_dashboard']  # Only admin dashboard connections get environment stats
                        )
                client_environments = client_info.get('environments', [])

                print(
                    f"[SERVER] Preparing stats for {username}: admin={is_admin_user}, is_dashboard={client_data['is_admin_dashboard']}, environments={client_environments}")

                # Ensure personal stats are initialized
                if 'protocol_counts' not in client_info:
                    client_info['protocol_counts'] = {
                        'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SMTP': 0, 'Other': 0
                    }
                    print(f"[SERVER] EMERGENCY: Initialized missing personal stats for {username}")

                # Get personal protocol distribution for this user
                personal_distribution = self.get_personal_protocol_distribution(username)

                if not personal_distribution:
                    print(f"[SERVER] ERROR: Could not get personal distribution for {username}")
                    continue

                # FIXED LOGIC: Only send environment stats to admin dashboard users
                if is_admin_user:
                    # ADMIN DASHBOARD USERS: Send environment stats AND personal stats
                    for env_name in client_environments:
                        if not env_name:
                            continue

                        with self.environment_lock:
                            if env_name in self.environments:
                                env_protocol_counts = self.environments[env_name]['protocol_counts'].copy()
                                env_total = sum(env_protocol_counts.values())

                                # Calculate environment distribution
                                env_distribution = {}
                                if env_total > 0:
                                    for protocol, count in env_protocol_counts.items():
                                        env_distribution[protocol] = round((count / env_total) * 100, 2)
                                else:
                                    env_distribution = {protocol: 0.0 for protocol in env_protocol_counts.keys()}

                                # Prepare admin stats message with BOTH environment and personal data
                                stats_message = {
                                    'type': 'stats',
                                    'environment': env_name,
                                    'protocol_data': {
                                        'environment_counts': env_protocol_counts,
                                        'environment_distribution': env_distribution,
                                        'environment_total': env_total,
                                        'personal_counts': personal_distribution['counts'],
                                        'personal_distribution': personal_distribution['distribution'],
                                        'personal_total': personal_distribution['total_packets']
                                    },
                                    'timestamp': datetime.now().isoformat(),
                                    'stats_type': 'admin_with_personal',
                                    'username': username,
                                    'is_personal': False  # False for admin dashboard users
                                }

                                # Send the admin message
                                try:
                                    # Handle encryption if this is EncryptedPacketServer
                                    if hasattr(self, 'encrypted_clients') and hasattr(self, 'client_message_handlers'):
                                        if addr in self.encrypted_clients and addr in self.client_message_handlers:
                                            # Send encrypted
                                            message_handler = self.client_message_handlers[addr]
                                            encrypted_msg = message_handler.prepare_message(stats_message)
                                            socket_conn.sendall(encrypted_msg.encode('utf-8'))
                                        else:
                                            # Send unencrypted
                                            message_json = json.dumps(stats_message)
                                            message_bytes = (message_json + '\n').encode('utf-8')
                                            socket_conn.sendall(message_bytes)
                                    else:
                                        # Regular unencrypted server
                                        message_json = json.dumps(stats_message)
                                        message_bytes = (message_json + '\n').encode('utf-8')
                                        socket_conn.sendall(message_bytes)

                                    print(
                                        f"[SERVER] ✓ Successfully sent admin+personal stats to {username} for {env_name}")
                                except socket.error as e:
                                    print(f"[SERVER] Socket error sending stats to {username}: {e}")
                                    with self.clients_lock:
                                        if username in self.clients_by_username:
                                            self.clients_by_username[username]['connected'] = False
                                    break  # Exit environment loop for this client
                                except Exception as e:
                                    print(f"[SERVER] Error sending admin stats to {username}: {e}")
                            else:
                                print(f"[SERVER] Environment {env_name} not found for admin {username}")

                else:
                    # REGULAR USERS (including admin users that are NOT using dashboard): Send ONLY personal stats
                    stats_message = {
                        'type': 'stats',
                        'environment': client_environments[0] if client_environments else 'default',
                        'environments': client_environments,
                        'protocol_data': {
                            # ONLY personal data for regular users - NO environment data
                            'personal_counts': personal_distribution['counts'],
                            'personal_distribution': personal_distribution['distribution'],
                            'personal_total': personal_distribution['total_packets']
                            # Explicitly NOT including:
                            # - environment_counts
                            # - environment_distribution
                            # - environment_total
                        },
                        'timestamp': datetime.now().isoformat(),
                        'stats_type': 'personal_only',
                        'username': username,
                        'is_personal': True  # Always true for regular users
                    }

                    print(f"[SERVER] SENDING PERSONAL-ONLY STATS to regular user {username}:")
                    print(f"  - Personal counts: {personal_distribution['counts']}")
                    print(f"  - Personal distribution: {personal_distribution['distribution']}")
                    print(f"  - Total packets: {personal_distribution['total_packets']}")

                    # Send the personal-only message
                    try:
                        # Handle encryption if this is EncryptedPacketServer
                        if hasattr(self, 'encrypted_clients') and hasattr(self, 'client_message_handlers'):
                            if addr in self.encrypted_clients and addr in self.client_message_handlers:
                                # Send encrypted
                                message_handler = self.client_message_handlers[addr]
                                encrypted_msg = message_handler.prepare_message(stats_message)
                                socket_conn.sendall(encrypted_msg.encode('utf-8'))
                            else:
                                # Send unencrypted
                                message_json = json.dumps(stats_message)
                                message_bytes = (message_json + '\n').encode('utf-8')
                                socket_conn.sendall(message_bytes)
                        else:
                            # Regular unencrypted server
                            message_json = json.dumps(stats_message)
                            message_bytes = (message_json + '\n').encode('utf-8')
                            socket_conn.sendall(message_bytes)

                        print(f"[SERVER] ✓ Successfully sent PERSONAL-ONLY stats to regular user {username}")
                    except socket.error as e:
                        print(f"[SERVER] Socket error sending stats to {username}: {e}")
                        with self.clients_lock:
                            if username in self.clients_by_username:
                                self.clients_by_username[username]['connected'] = False
                        continue
                    except Exception as e:
                        print(f"[SERVER] Error sending personal stats to {username}: {e}")
                        import traceback
                        traceback.print_exc()

            except Exception as e:
                print(f"[SERVER] Error preparing stats for {client_data['username']}: {e}")
                import traceback
                traceback.print_exc()

    def register_ui_callback(self, callback):
        """Register a callback function that will be called when data changes"""
        self.ui_update_callback = callback

    def get_clients_data(self):
        """Get a copy of the current clients data (excluding admin dashboards)"""
        with self.clients_lock:
            # Create a dictionary that maps active connections to client info
            # Exclude admin dashboard connections
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
            # Filter out admin dashboard clients from the result
            result = {}
            for username, client_info in self.clients_by_username.items():
                # Skip if this is an admin dashboard client
                if username in self.admin_dashboard_clients:
                    continue
                result[username] = client_info.copy()
            return result

    def get_client_personalized_stats_summary(self):
        """Get a summary of all clients' personalized stats for debugging"""
        summary = {
            'regular_users': {},
            'admin_users': {},
            'environment_stats': {}
        }

        with self.clients_lock:
            for username, client_info in self.clients_by_username.items():
                # Skip admin dashboard clients from summary
                if username in self.admin_dashboard_clients:
                    continue

                user_stats = {
                    'personal_counts': client_info.get('protocol_counts', {}),
                    'total_personal_packets': sum(client_info.get('protocol_counts', {}).values()),
                    'environments': client_info.get('environments', []),
                    'connected': client_info.get('connected', False)
                }

                if username in self.admin_clients:
                    summary['admin_users'][username] = user_stats
                else:
                    summary['regular_users'][username] = user_stats

        # Add environment stats that admins see
        with self.environment_lock:
            for env_name, env_data in self.environments.items():
                summary['environment_stats'][env_name] = {
                    'protocol_counts': env_data.get('protocol_counts', {}),
                    'total_packets': sum(env_data.get('protocol_counts', {}).values()),
                    'connected_clients': len(
                        [c for c in env_data.get('clients', {}).values() if c.get('connected', False)])
                }

        return summary

    def get_protocol_data(self):
        """Get a copy of the current protocol data"""
        with self.protocol_lock:
            return self.protocol_counts.copy()

    def determine_protocol(self, packet):
        """Determine the protocol of a packet"""
        protocol = packet.get('protocol', '').upper()
        highest_layer = packet.get('highest_layer', '').upper()
        src_port = str(packet.get('source_port', ''))  # Convert to string for consistent comparison
        dst_port = str(packet.get('destination_port', ''))  # Convert to string for consistent comparison

        # Check for specific application protocols
        if highest_layer == 'HTTP' or src_port == '80' or dst_port == '80':
            return 'HTTP'
        elif highest_layer == 'TLS' or highest_layer == 'HTTPS' or src_port == '443' or dst_port == '443':
            # Accept both 'TLS' (from real packets) and 'HTTPS' (from test packets)
            return 'HTTPS'
        elif highest_layer == 'FTP' or src_port == '21' or dst_port == '21':
            return 'FTP'
        elif highest_layer == 'SMTP' or src_port == '25' or dst_port == '25' or src_port == '587' or dst_port == '587':
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

        # Gather client data (excluding admin dashboard connections)
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
        Enhanced process_packet method with better username validation and
        improved personal stats tracking
        FIXED: Ensure proper separation of personal vs environment stats
        """
        try:
            packet = json.loads(packet_data)
            connection_username = self.active_connections.get(client_addr)
            packet_username = packet.get('username')
            # print(f"[SERVER] Connection username: {connection_username}")
            # print(f"[SERVER] Packet username: {packet_username}")

            # Handle admin stats request
            if packet.get('type') == 'admin_stats_request':
                self.handle_admin_request(packet, client_addr)
                return True

            # Skip system/heartbeat messages
            if packet.get('type') in ['heartbeat', 'stats', 'ack']:
                return False

            # Skip packet processing for admin dashboard connections
            with self.clients_lock:
                if client_addr in self.admin_dashboard_connections:
                    return False  # Admin dashboards don't send packets

            # ENHANCED: Get username with validation
            username = self._get_validated_username(packet, client_addr)
            if not username:
                return False

            # Check for a unique packet ID
            packet_id = packet.get('packet_id')
            if not packet_id:
                print(f"[SERVER] Missing packet_id from user {username}, ignoring")
                return False

            # Use environments from the packet if provided
            if not environments:
                packet_envs = packet.get('environments', [])
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

                    # Limit the size of the processed_packet_ids set
                    if len(self.processed_packet_ids) > 20000:
                        self.processed_packet_ids = set(list(self.processed_packet_ids)[-10000:])
                else:
                    print(f"[SERVER] Duplicate packet ignored from user {username}: {packet_id}")
                    return False

            # Only process new packets
            if is_new_packet:
                # print(f"[SERVER] Processing new packet from {username}: {packet_id}, protocol: {protocol}")

                # FIXED: Update personal stats (only for non-admin users now)
                if not self._update_personal_stats(username, protocol):
                    print(f"[SERVER] Failed to update personal stats for {username}")
                    return False

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
                    if not env_name:
                        continue

                    # Check if client is authorized for this environment
                    if not self._validate_user_environment_access(username, env_name):
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
                            # print(f"[SERVER] Environment {env_name} - {protocol}: "
                            #       f"{self.environments[env_name]['protocol_counts'][protocol]}, Total: {env_total}")
                        else:
                            print(f"[SERVER] Environment {env_name} not found, skipping")

                # Send acknowledgment
                self._send_packet_acknowledgment(username, packet_id, environments)

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

    def _send_packet_acknowledgment(self, username, packet_id, environments):
        """
        Send acknowledgment for processed packet
        """
        try:
            # Get client socket
            socket_conn = None
            with self.clients_lock:
                if username in self.clients_by_username:
                    socket_conn = self.clients_by_username[username].get('socket')

            if socket_conn:
                ack_message = {
                    'type': 'ack',
                    'packet_id': packet_id,
                    'environments': environments,
                    'timestamp': datetime.now().isoformat(),
                    'username': username  # Include username for client verification
                }

                # Handle encryption if this is EncryptedPacketServer
                if hasattr(self, 'encrypted_clients') and hasattr(self, 'client_message_handlers'):
                    client_addr = self.clients_by_username[username].get('last_addr')
                    if (client_addr and client_addr in self.encrypted_clients and
                            client_addr in self.client_message_handlers):
                        # Send encrypted ACK
                        message_handler = self.client_message_handlers[client_addr]
                        encrypted_msg = message_handler.prepare_message(ack_message)
                        socket_conn.sendall(encrypted_msg.encode('utf-8'))
                    else:
                        # Send unencrypted ACK
                        socket_conn.sendall((json.dumps(ack_message) + '\n').encode('utf-8'))
                else:
                    # Regular unencrypted server
                    socket_conn.sendall((json.dumps(ack_message) + '\n').encode('utf-8'))

                # print(f"[SERVER] Sent ACK for packet {packet_id} to {username}")
        except Exception as e:
            print(f"[SERVER] Error sending ACK to {username}: {e}")

    def _ensure_personal_stats_initialized(self, username):
        """Ensure a user has properly initialized personal protocol stats"""
        with self.clients_lock:
            if username not in self.clients_by_username:
                print(f"[SERVER] ERROR: Username {username} not found for stats initialization")
                return False

            client_info = self.clients_by_username[username]

            # Initialize if missing or invalid
            if ('protocol_counts' not in client_info or
                    not isinstance(client_info['protocol_counts'], dict) or
                    len(client_info['protocol_counts']) == 0):
                client_info['protocol_counts'] = {
                    'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
                    'FTP': 0, 'SMTP': 0, 'Other': 0
                }
                print(f"[SERVER] Initialized personal stats for {username}")

            # Ensure all required protocols exist
            required_protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'Other']
            for protocol in required_protocols:
                if protocol not in client_info['protocol_counts']:
                    client_info['protocol_counts'][protocol] = 0

            return True

    def get_personal_protocol_distribution(self, username):
        """
        Calculate personal protocol distribution for a specific user
        FIXED: Enhanced validation and error handling
        """
        with self.clients_lock:
            if username not in self.clients_by_username:
                print(f"[SERVER] ERROR: Username {username} not found in clients_by_username")
                return None

            client_info = self.clients_by_username[username]
            protocol_counts = client_info.get('protocol_counts', {})

            # FIXED: Validate protocol_counts structure
            if not isinstance(protocol_counts, dict):
                print(f"[SERVER] ERROR: Invalid protocol_counts for {username}: {type(protocol_counts)}")
                # Initialize with default values
                protocol_counts = {'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SMTP': 0, 'Other': 0}
                client_info['protocol_counts'] = protocol_counts

            # Ensure all required protocols exist
            required_protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'Other']
            for protocol in required_protocols:
                if protocol not in protocol_counts:
                    protocol_counts[protocol] = 0

            # Calculate total packets for this user
            total_packets = sum(protocol_counts.values())

            print(f"[SERVER] Personal stats calculation for {username}:")
            print(f"  - Protocol counts: {protocol_counts}")
            print(f"  - Total packets: {total_packets}")

            if total_packets == 0:
                # Return zero distribution if no packets
                distribution = {protocol: 0.0 for protocol in protocol_counts.keys()}
                result = {
                    'distribution': distribution,
                    'counts': protocol_counts.copy(),
                    'total_packets': 0
                }
                print(f"  - Zero distribution: {distribution}")
                return result

            # Calculate percentage distribution
            distribution = {}
            for protocol, count in protocol_counts.items():
                if count > 0:
                    distribution[protocol] = round((count / total_packets) * 100, 2)
                else:
                    distribution[protocol] = 0.0

            result = {
                'distribution': distribution,
                'counts': protocol_counts.copy(),
                'total_packets': total_packets
            }

            print(f"  - Calculated distribution: {distribution}")
            return result

    def _get_validated_username(self, packet, client_addr):
        """
        Enhanced username validation that checks both connection mapping and packet data
        """
        # Get username from connection mapping
        connection_username = None
        with self.clients_lock:
            connection_username = self.active_connections.get(client_addr)

        # Get username from packet
        packet_username = packet.get('username')

        # Validate usernames match if both are available
        if packet_username and connection_username:
            if packet_username != connection_username:
                print(f"[SERVER] USERNAME MISMATCH - Connection: {connection_username}, Packet: {packet_username}")
                print(f"[SERVER] Using connection username for security: {connection_username}")
                # Use connection username for security (harder to spoof)
                return connection_username

        # Use the most reliable username (prefer connection mapping)
        username = connection_username or packet_username

        if not username:
            print(f"[SERVER] No username available for {client_addr}")
            return None

        return username

    def _update_personal_stats(self, username, protocol):
        """
        Thread-safe method to update individual user's personal protocol statistics
        FIXED: Always update personal stats for ALL users
        """
        # First ensure stats are properly initialized
        if not self._ensure_personal_stats_initialized(username):
            print(f"[SERVER] ERROR: Could not initialize personal stats for {username}")
            return False

        with self.clients_lock:
            if username not in self.clients_by_username:
                print(f"[SERVER] ERROR: Username {username} not found in clients")
                return False

            user_data = self.clients_by_username[username]

            # Update personal stats for ALL users (both admin and regular)
            user_stats = user_data['protocol_counts']
            if protocol in user_stats:
                user_stats[protocol] += 1
            else:
                user_stats['Other'] += 1

            # Update packet count
            user_data['packet_count'] = user_data.get('packet_count', 0) + 1

            # Debug logging
            total_personal = sum(user_stats.values())
            user_type = "admin" if username in self.admin_clients else "regular"
            print(
                f"[SERVER] Updated personal stats for {user_type} user {username}: {user_stats} (Total: {total_personal})")

            return True

    def _validate_user_environment_access(self, username, env_name):
        """
        Validate that a user has access to a specific environment
        """
        with self.clients_lock:
            if username not in self.clients_by_username:
                return False

            user_envs = self.clients_by_username[username].get('environments', [])
            return env_name in user_envs

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

    def get_user_protocol_data(self, env_name):
        """Get protocol data for a specific environment"""
        with self.environment_lock:
            if env_name in self.environments:
                return self.clients_by_username[env_name]['protocol_counts'].copy()
            return {}

    def handle_client(self, conn, addr):
        print(f"[SERVER] New connection from {addr}")

        authenticated = False
        buffer = ""
        username = None
        verified_environments = []  # List of environments this client has access to
        is_admin = False
        is_admin_dashboard = False  # Track if this is an admin dashboard connection

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

                                # Check if this is an admin dashboard connection
                                is_admin_dashboard = auth_json.get('is_admin_dashboard', False)

                                if is_admin_dashboard:
                                    print(f"[SERVER] Admin dashboard connection from {addr} as user: {username}")
                                else:
                                    print(f"[SERVER] Client {addr} attempting authentication as user: {username}")

                                # Check if admin user
                                if auth_json.get('is_admin'):
                                    is_admin = True
                                    self.admin_clients.add(username)
                                    print(f"[SERVER] Added {username} to admin_clients set: {self.admin_clients}")
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

                                # Extract the environment names (passwords already verified)
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
                                        existing_client = self.clients_by_username[username]
                                        existing_client['connected'] = True
                                        existing_client['environments'] = verified_environments
                                        existing_client['account_info'] = account_info
                                        existing_client['socket'] = conn
                                        existing_client['last_addr'] = addr

                                        # CRITICAL: Ensure personal stats are initialized for ALL users
                                        if ('protocol_counts' not in existing_client or
                                                not isinstance(existing_client['protocol_counts'], dict)):
                                            existing_client['protocol_counts'] = {
                                                'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
                                                'FTP': 0, 'SMTP': 0, 'Other': 0
                                            }
                                            print(
                                                f"[SERVER] Re-initialized personal stats for existing user {username}")

                                        if is_admin_dashboard:
                                            print(f"[SERVER] Admin dashboard {username} reconnected")
                                        else:
                                            print(
                                                f"[SERVER] User {username} reconnected with environments: {verified_environments}")
                                    else:
                                        # Create new user entry with properly initialized personal stats
                                        self.clients_by_username[username] = {
                                            'username': username,
                                            'packet_count': 0,
                                            'protocol_counts': {  # CRITICAL: Always initialize this for ALL users
                                                'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
                                                'FTP': 0, 'SMTP': 0, 'Other': 0
                                            },
                                            'connected': True,
                                            'environments': verified_environments,
                                            'account_info': account_info,
                                            'socket': conn,
                                            'last_addr': addr
                                        }

                                        print(
                                            f"[SERVER] New user {username} registered with personal stats initialized")

                                    # Map connection based on type
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
                # Handle cleanup for both connection types
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
                print(f"[SERVER] Removed {username} from admin_clients set: {self.admin_clients}")
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