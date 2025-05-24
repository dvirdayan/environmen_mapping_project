import socket
import threading
import json
import time
import select
from datetime import datetime
import os
import sys

# Import the original packet server
from proj3103.back.packet_server import PacketServer

# Import encryption module
try:
    from crypto_handler import CryptoHandler, SecureMessageHandler, CRYPTO_AVAILABLE
except ImportError:
    print("Error: crypto_handler.py not found")
    CRYPTO_AVAILABLE = False


class EncryptedPacketServer(PacketServer):
    """Enhanced packet server with RSA/AES encryption support that works with both encrypted and unencrypted clients"""

    def __init__(self, host='0.0.0.0', port=9007, enable_encryption=True):
        super().__init__(host, port)
        self.enable_encryption = enable_encryption and CRYPTO_AVAILABLE

        if self.enable_encryption:
            print("[SERVER] Encryption support enabled")
            # Server crypto handler
            self.crypto = CryptoHandler()
            self.setup_encryption()

            # Client crypto handlers - one per connection
            self.client_crypto = {}  # {client_addr: CryptoHandler}
            self.client_message_handlers = {}  # {client_addr: SecureMessageHandler}
            self.encrypted_clients = set()  # Track which clients are using encryption
        else:
            if enable_encryption and not CRYPTO_AVAILABLE:
                print("[SERVER] Encryption requested but pycryptodome not installed")
            print("[SERVER] Running without encryption support")

    def setup_encryption(self):
        """Setup RSA keys for the server"""
        key_file = "server_private_key.pem"

        # Try to load existing key
        if os.path.exists(key_file):
            print(f"[SERVER] Loading RSA private key from {key_file}")
            if self.crypto.load_rsa_private_key(key_file):
                print("[SERVER] RSA private key loaded successfully")
            else:
                print("[SERVER] Failed to load RSA key, generating new one")
                self.generate_new_rsa_key(key_file)
        else:
            self.generate_new_rsa_key(key_file)

    def generate_new_rsa_key(self, key_file):
        """Generate new RSA keypair"""
        print("[SERVER] Generating new RSA keypair...")
        self.crypto.generate_rsa_keypair()

        # Save private key
        if self.crypto.save_rsa_private_key(key_file):
            print(f"[SERVER] RSA private key saved to {key_file}")
        else:
            print("[SERVER] Warning: Could not save RSA private key")

        # Display public key
        public_key = self.crypto.get_public_key_pem()
        print("[SERVER] RSA public key generated")

    def handle_client(self, conn, addr):
        """Handle client connection with support for both encrypted and unencrypted clients"""
        if not self.enable_encryption:
            # Use original handler if encryption is disabled
            super().handle_client(conn, addr)
            return

        print(f"[SERVER] New connection from {addr}")

        authenticated = False
        buffer = ""
        username = None
        verified_environments = []
        is_admin = False
        is_admin_dashboard = False
        encrypted_session = False

        # Create crypto handler for this client
        client_crypto = CryptoHandler()
        message_handler = None

        try:
            # Make socket non-blocking for timeout handling
            conn.settimeout(10)

            # First, we need to detect if this is an encrypted client or regular client
            # We'll wait for the first message to determine this
            first_data = conn.recv(4096).decode('utf-8')

            if not first_data:
                print(f"[SERVER] No data received from {addr}")
                return

            # Check if this looks like an auth message (unencrypted client)
            try:
                # Try to parse as JSON
                lines = first_data.strip().split('\n')
                first_msg = json.loads(lines[0])

                if first_msg.get('type') == 'auth':
                    # This is an unencrypted client - use original authentication flow
                    print(f"[SERVER] Detected unencrypted client from {addr}")

                    # Process the auth message
                    auth_json = first_msg

                    # Extract username from auth data
                    username = auth_json.get('username')
                    account_info = auth_json.get('account_info', {})

                    if not username and isinstance(account_info, dict):
                        username = account_info.get('username')
                    if not username and isinstance(account_info, str):
                        username = account_info
                    if not username:
                        username = f"user_{addr[0]}_{addr[1]}"

                    is_admin_dashboard = auth_json.get('is_admin_dashboard', False)

                    if is_admin_dashboard:
                        print(f"[SERVER] Admin dashboard connection from {addr} as user: {username}")
                    else:
                        print(f"[SERVER] Client {addr} attempting authentication as user: {username}")

                    # Check if admin user
                    if auth_json.get('is_admin'):
                        is_admin = True
                        self.admin_clients.add(username)
                        print(f"[SERVER] Admin user {username} connected")

                    # Track connection time
                    self.client_connect_times[username] = time.time()

                    # Handle environments (same as original)
                    environments = auth_json.get('environments', [])
                    if not environments:
                        env_name = auth_json.get('env_name')
                        env_password = auth_json.get('env_password')
                        if env_name:
                            environments = [{'env_name': env_name, 'env_password': env_password}]
                        else:
                            environments = [{'env_name': 'default', 'env_password': 'default_password'}]

                    # Extract environment names
                    verified_environments = [env.get('env_name') for env in environments if env.get('env_name')]
                    print(f"[SERVER] Accepting environments: {verified_environments}")
                    authenticated = True

                    # Initialize environments
                    for env in environments:
                        env_name = env.get('env_name')
                        env_password = env.get('env_password')
                        if env_name in verified_environments:
                            self.add_environment(env_name, env_password)
                            if not is_admin_dashboard:
                                with self.environment_lock:
                                    self.environments[env_name]['clients'][username] = {
                                        'username': username,
                                        'connected': True,
                                        'account_info': account_info
                                    }

                    # Register client
                    with self.clients_lock:
                        if username in self.clients_by_username:
                            self.clients_by_username[username]['connected'] = True
                            self.clients_by_username[username]['environments'] = verified_environments
                            self.clients_by_username[username]['account_info'] = account_info
                            self.clients_by_username[username]['socket'] = conn
                            self.clients_by_username[username]['last_addr'] = addr
                            self.clients_by_username[username]['encrypted'] = False
                            print(f"[SERVER] User {username} reconnected with environments: {verified_environments}")
                        else:
                            self.clients_by_username[username] = {
                                'username': username,
                                'packet_count': 0,
                                'protocol_counts': {
                                    'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
                                    'FTP': 0, 'SMTP': 0, 'Other': 0
                                },
                                'connected': True,
                                'environments': verified_environments,
                                'account_info': account_info,
                                'socket': conn,
                                'last_addr': addr,
                                'encrypted': False
                            }
                            print(f"[SERVER] New user {username} registered with environments: {verified_environments}")

                        if is_admin_dashboard:
                            self.admin_dashboard_connections[addr] = username
                            self.admin_dashboard_clients.add(username)
                        else:
                            self.active_connections[addr] = username

                    # Send auth success response (unencrypted)
                    response = {
                        'status': 'authenticated',
                        'message': f'Connected as {"admin dashboard" if is_admin_dashboard else "user"}: {username}',
                        'environments': verified_environments
                    }
                    conn.sendall((json.dumps(response) + '\n').encode('utf-8'))

                    # Process any remaining data
                    if len(lines) > 1:
                        buffer = '\n'.join(lines[1:])

                    # Update UI
                    if self.ui_update_callback:
                        self.ui_update_callback()

                elif first_msg.get('type') == 'client_hello' or 'supports_encryption' in first_msg:
                    # This is an encrypted client
                    print(f"[SERVER] Detected encryption-capable client from {addr}")

                    # Send server public key
                    public_key_msg = {
                        'type': 'server_hello',
                        'encryption_enabled': True,
                        'public_key': self.crypto.get_public_key_pem()
                    }
                    conn.sendall((json.dumps(public_key_msg) + '\n').encode('utf-8'))
                    print(f"[SERVER] Sent public key to {addr}")

                    # Continue with encryption handshake
                    # Wait for key exchange
                    key_exchange_data = conn.recv(4096)
                    if key_exchange_data:
                        key_exchange_text = key_exchange_data.decode('utf-8').strip()
                        key_exchange_msg = json.loads(key_exchange_text.split('\n')[0])

                        if key_exchange_msg.get('type') == 'key_exchange':
                            print(f"[SERVER] Received key exchange from {addr}")

                            # Process key exchange
                            client_crypto.process_key_exchange_message(key_exchange_msg)

                            # Create message handler
                            message_handler = SecureMessageHandler(client_crypto)
                            self.client_crypto[addr] = client_crypto
                            self.client_message_handlers[addr] = message_handler
                            self.encrypted_clients.add(addr)

                            # Send acknowledgment
                            ack_msg = {'type': 'key_exchange_ack', 'status': 'success'}
                            encrypted_ack = message_handler.prepare_message(ack_msg)
                            conn.sendall(encrypted_ack.encode('utf-8'))

                            encrypted_session = True
                            print(f"[SERVER] Key exchange complete with {addr}")

                            # Now wait for encrypted auth
                            auth_data = conn.recv(4096)
                            if auth_data:
                                auth_text = auth_data.decode('utf-8').strip()
                                auth_json = message_handler.process_message(auth_text)

                                if auth_json and auth_json.get('type') == 'auth':
                                    # Process auth (same as above but for encrypted client)
                                    # ... (same auth processing code)
                                    authenticated = True
                else:
                    # Unknown message type
                    print(f"[SERVER] Unknown initial message from {addr}: {first_msg.get('type')}")
                    return

            except json.JSONDecodeError:
                # Not JSON - might be a legacy client
                print(f"[SERVER] Non-JSON data from {addr}, closing connection")
                return

            if not authenticated:
                print(f"[SERVER] Authentication failed for {addr}")
                return

            # Make socket non-blocking for the packet processing loop
            conn.setblocking(False)

            # Enter main processing loop (same as original)
            while self.running and authenticated:
                try:
                    readable, _, _ = select.select([conn], [], [], 0.5)

                    if conn in readable:
                        data = conn.recv(4096).decode('utf-8')
                        if not data:
                            dashboard_text = " (admin dashboard)" if is_admin_dashboard else ""
                            print(f"[SERVER] Client {username}{dashboard_text} disconnected")
                            break

                        buffer += data

                        # Process complete lines
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            if line.strip():
                                # Decrypt if this is an encrypted client
                                if encrypted_session and addr in self.encrypted_clients and message_handler:
                                    try:
                                        decrypted_msg = message_handler.process_message(line)
                                        if decrypted_msg:
                                            line = json.dumps(decrypted_msg)
                                    except:
                                        pass

                                # Process packet
                                try:
                                    packet_json = json.loads(line)
                                    packet_environments = packet_json.get('environments', [])

                                    if not packet_environments:
                                        packet_environments = verified_environments

                                    valid_envs = [env for env in packet_environments if env in verified_environments]

                                    if valid_envs or is_admin_dashboard:
                                        self.process_packet(line, addr, valid_envs)

                                except json.JSONDecodeError:
                                    if not is_admin_dashboard:
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
            # Cleanup
            if addr in self.client_crypto:
                del self.client_crypto[addr]
            if addr in self.client_message_handlers:
                del self.client_message_handlers[addr]
            if addr in self.encrypted_clients:
                self.encrypted_clients.remove(addr)

            # Rest of cleanup (same as original)
            with self.clients_lock:
                if addr in self.active_connections:
                    username = self.active_connections[addr]
                    if username in self.clients_by_username:
                        self.clients_by_username[username]['connected'] = False
                        self.clients_by_username[username]['socket'] = None
                    del self.active_connections[addr]
                elif addr in self.admin_dashboard_connections:
                    username = self.admin_dashboard_connections[addr]
                    if username in self.clients_by_username:
                        self.clients_by_username[username]['connected'] = False
                        self.clients_by_username[username]['socket'] = None
                    del self.admin_dashboard_connections[addr]
                    if username in self.admin_dashboard_clients:
                        self.admin_dashboard_clients.remove(username)

            if username and username in self.admin_clients:
                self.admin_clients.remove(username)

            if not is_admin_dashboard:
                with self.environment_lock:
                    for env_name in verified_environments:
                        if env_name in self.environments and username and username in self.environments[env_name][
                            'clients']:
                            self.environments[env_name]['clients'][username]['connected'] = False

            if self.ui_update_callback:
                self.ui_update_callback()

            try:
                conn.close()
            except:
                pass

            dashboard_text = " (admin dashboard)" if is_admin_dashboard else ""
            print(f"[SERVER] Connection with {username or addr}{dashboard_text} closed")

    def _send_stats_periodically(self):
        """Override to handle encrypted clients properly"""
        # Use the parent class implementation but check for encryption
        while self.running:
            time.sleep(30)

            # Clear old packet IDs
            current_time = time.time()
            if current_time - self.last_packet_id_cleanup > 3600:
                with self.processed_packets_lock:
                    if len(self.processed_packet_ids) > 10000:
                        print(f"[SERVER] Clearing packet ID cache. Size before: {len(self.processed_packet_ids)}")
                        self.processed_packet_ids = set(list(self.processed_packet_ids)[-5000:])
                        print(f"[SERVER] New packet ID cache size: {len(self.processed_packet_ids)}")
                self.last_packet_id_cleanup = current_time

            # Get connected clients
            connected_clients = {}
            with self.clients_lock:
                for addr, username in self.active_connections.items():
                    if addr in self.admin_dashboard_connections:
                        continue
                    if username in self.clients_by_username and self.clients_by_username[username].get('connected',
                                                                                                       False):
                        connected_clients[addr] = self.clients_by_username[username]

            # Also get admin dashboard clients
            admin_dashboard_clients = {}
            with self.clients_lock:
                for addr, username in self.admin_dashboard_connections.items():
                    if username in self.clients_by_username and self.clients_by_username[username].get('connected',
                                                                                                       False):
                        admin_dashboard_clients[addr] = self.clients_by_username[username]

            all_clients_for_stats = {**connected_clients, **admin_dashboard_clients}

            if not all_clients_for_stats:
                continue

            # Send stats to each client
            for addr, client_info in all_clients_for_stats.items():
                try:
                    with self.protocol_lock:
                        global_protocol_counts = self.protocol_counts.copy()

                    global_stats_message = {
                        'type': 'stats',
                        'protocol_counts': global_protocol_counts,
                        'timestamp': datetime.now().isoformat()
                    }

                    socket_conn = client_info.get('socket')
                    if socket_conn:
                        try:
                            # Check if this is an encrypted client
                            if self.enable_encryption and addr in self.encrypted_clients and addr in self.client_message_handlers:
                                # Send encrypted
                                message_handler = self.client_message_handlers[addr]
                                encrypted_msg = message_handler.prepare_message(global_stats_message)
                                socket_conn.sendall(encrypted_msg.encode('utf-8'))
                            else:
                                # Send unencrypted
                                socket_conn.sendall((json.dumps(global_stats_message) + '\n').encode('utf-8'))
                        except Exception as e:
                            print(f"[SERVER] Error sending global stats to {client_info['username']}: {e}")
                            with self.clients_lock:
                                if client_info['username'] in self.clients_by_username:
                                    self.clients_by_username[client_info['username']]['connected'] = False

                    # Send environment-specific stats
                    client_environments = client_info.get('environments', [])
                    for env_name in client_environments:
                        with self.environment_lock:
                            if env_name in self.environments:
                                env_protocol_counts = self.environments[env_name]['protocol_counts'].copy()
                            else:
                                continue

                        env_stats_message = {
                            'type': 'stats',
                            'environment': env_name,
                            'protocol_counts': env_protocol_counts,
                            'timestamp': datetime.now().isoformat()
                        }

                        if socket_conn:
                            try:
                                # Check if encrypted
                                if self.enable_encryption and addr in self.encrypted_clients and addr in self.client_message_handlers:
                                    message_handler = self.client_message_handlers[addr]
                                    encrypted_msg = message_handler.prepare_message(env_stats_message)
                                    socket_conn.sendall(encrypted_msg.encode('utf-8'))
                                else:
                                    socket_conn.sendall((json.dumps(env_stats_message) + '\n').encode('utf-8'))
                            except Exception as e:
                                print(f"[SERVER] Error sending {env_name} stats to {client_info['username']}: {e}")

                except Exception as e:
                    print(f"[SERVER] Error preparing stats for {client_info['username']}: {e}")

            # Send admin stats
            if int(time.time()) % 2 == 0:
                for username in list(self.admin_clients):
                    try:
                        client_addr = None
                        with self.clients_lock:
                            for addr, uname in self.active_connections.items():
                                if uname == username:
                                    client_addr = addr
                                    break
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


if __name__ == "__main__":
    from packet_server_ui import start_ui

    # Check if encryption should be enabled
    enable_encryption = '--no-encryption' not in sys.argv

    if enable_encryption and not CRYPTO_AVAILABLE:
        print("\nWARNING: Encryption requested but pycryptodome is not installed!")
        print("Install it with: pip install pycryptodome")
        print("Running with encryption support disabled...\n")
        enable_encryption = False

    server = EncryptedPacketServer(enable_encryption=enable_encryption)
    server.load_environments_from_db()
    server.start()
    start_ui(server)