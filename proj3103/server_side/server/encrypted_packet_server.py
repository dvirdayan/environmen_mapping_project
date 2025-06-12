import socket
import json
import time
import select
from datetime import datetime
import os
import sys

# Import the original packet server
from proj3103.server_side.server.packet_server import PacketServer

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
        key_file = "../server_private_key.pem"

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
            # Make socket blocking for initial handshake
            conn.settimeout(10)

            # Wait for the first message to determine client type
            try:
                first_data = conn.recv(4096)

                if not first_data:
                    print(f"[SERVER] No data received from {addr}")
                    return

                first_text = first_data.decode('utf-8').strip()
                print(f"[SERVER] Received from {addr}: {first_text[:100]}...")

                lines = first_text.split('\n')
                first_msg = json.loads(lines[0])

                if first_msg.get('type') == 'auth':
                    print(f"[SERVER] Detected unencrypted client from {addr}")
                    # Handle unencrypted client authentication
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

                    # Check if admin user
                    if auth_json.get('is_admin'):
                        is_admin = True
                        self.admin_clients.add(username)
                        print(f"[SERVER] Admin user {username} connected")

                    # Handle environments
                    environments = auth_json.get('environments', [])
                    if not environments:
                        env_name = auth_json.get('env_name')
                        env_password = auth_json.get('env_password')
                        if env_name:
                            environments = [{'env_name': env_name, 'env_password': env_password}]
                        else:
                            environments = [{'env_name': 'default', 'env_password': 'default_password'}]

                    verified_environments = [env.get('env_name') for env in environments if env.get('env_name')]
                    authenticated = True

                    # Register client and send response (same as original logic)
                    # ... [rest of unencrypted auth logic] ...

                elif first_msg.get('type') == 'client_hello' and first_msg.get('supports_encryption'):
                    print(f"[SERVER] Detected encryption-capable client from {addr}")

                    # Send server hello with public key
                    public_key_msg = {
                        'type': 'server_hello',
                        'encryption_enabled': True,
                        'public_key': self.crypto.get_public_key_pem()
                    }
                    response = json.dumps(public_key_msg) + '\n'
                    conn.sendall(response.encode('utf-8'))
                    print(f"[SERVER] Sent public key to {addr}")

                    # Wait for key exchange
                    key_exchange_data = conn.recv(4096)
                    if not key_exchange_data:
                        print(f"[SERVER] No key exchange data from {addr}")
                        return

                    key_exchange_text = key_exchange_data.decode('utf-8').strip()
                    key_exchange_lines = key_exchange_text.split('\n')
                    key_exchange_msg = json.loads(key_exchange_lines[0])

                    if key_exchange_msg.get('type') == 'key_exchange':
                        print(f"[SERVER] Processing key exchange from {addr}")

                        # Process key exchange - extract AES key
                        try:
                            # Use the main server crypto handler to decrypt the key exchange
                            encrypted_key = key_exchange_msg.get('encrypted_key')
                            if not encrypted_key:
                                raise ValueError("No encrypted key in message")
                            # Decrypt with server's RSA private key
                            decrypted_json = self.crypto.rsa_decrypt(encrypted_key)
                            key_data = json.loads(decrypted_json)

                            # Extract AES key and IV
                            import base64
                            aes_key = base64.b64decode(key_data['aes_key'])
                            aes_iv = base64.b64decode(key_data['aes_iv'])

                            # Set up client-specific crypto handler
                            client_crypto.set_aes_key(aes_key, aes_iv)

                            # Create message handler
                            message_handler = SecureMessageHandler(client_crypto)
                            self.client_crypto[addr] = client_crypto
                            self.client_message_handlers[addr] = message_handler
                            self.encrypted_clients.add(addr)

                            # Send encrypted acknowledgment
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
                                    print(f"[SERVER] Processing encrypted auth from {addr}")

                                    # Extract auth info (same logic as unencrypted)
                                    username = auth_json.get('username')
                                    account_info = auth_json.get('account_info', {})

                                    if not username and isinstance(account_info, dict):
                                        username = account_info.get('username')
                                    if not username and isinstance(account_info, str):
                                        username = account_info
                                    if not username:
                                        username = f"user_{addr[0]}_{addr[1]}"

                                    is_admin_dashboard = auth_json.get('is_admin_dashboard', False)

                                    if auth_json.get('is_admin'):
                                        is_admin = True
                                        self.admin_clients.add(username)

                                    # Handle environments
                                    environments = auth_json.get('environments', [])
                                    if not environments:
                                        environments = [{'env_name': 'default', 'env_password': 'default_password'}]

                                    verified_environments = [env.get('env_name') for env in environments if
                                                             env.get('env_name')]
                                    authenticated = True

                                    print(
                                        f"[SERVER] Encrypted client {username} authenticated with environments: {verified_environments}")
                                else:
                                    print(f"[SERVER] Invalid encrypted auth from {addr}")
                                    return
                            else:
                                print(f"[SERVER] No encrypted auth received from {addr}")
                                return

                        except Exception as e:
                            print(f"[SERVER] Key exchange processing failed for {addr}: {e}")
                            return
                    else:
                        print(f"[SERVER] Expected key_exchange, got {key_exchange_msg.get('type')}")
                        return
                else:
                    print(f"[SERVER] Unknown initial message type from {addr}: {first_msg.get('type')}")
                    return

            except json.JSONDecodeError as e:
                print(f"[SERVER] JSON decode error from {addr}: {e}")
                return
            except Exception as e:
                print(f"[SERVER] Error parsing initial message from {addr}: {e}")
                return

            if not authenticated:
                print(f"[SERVER] Authentication failed for {addr}")
                return

            # Track connection time
            self.client_connect_times[username] = time.time()

            # Initialize environments
            for env in (auth_json.get('environments', []) if 'auth_json' in locals() else []):
                env_name = env.get('env_name')
                env_password = env.get('env_password')
                if env_name in verified_environments:
                    self.add_environment(env_name, env_password)
                    if not is_admin_dashboard:
                        with self.environment_lock:
                            self.environments[env_name]['clients'][username] = {
                                'username': username,
                                'connected': True,
                                'account_info': account_info if 'account_info' in locals() else {}
                            }

            # Register client
            with self.clients_lock:
                if username in self.clients_by_username:
                    self.clients_by_username[username]['connected'] = True
                    self.clients_by_username[username]['environments'] = verified_environments
                    self.clients_by_username[username][
                        'account_info'] = account_info if 'account_info' in locals() else {}
                    self.clients_by_username[username]['socket'] = conn
                    self.clients_by_username[username]['last_addr'] = addr
                    self.clients_by_username[username]['encrypted'] = encrypted_session
                    print(
                        f"[SERVER] User {username} reconnected ({'encrypted' if encrypted_session else 'unencrypted'})")
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
                        'account_info': account_info if 'account_info' in locals() else {},
                        'socket': conn,
                        'last_addr': addr,
                        'encrypted': encrypted_session
                    }
                    print(
                        f"[SERVER] New user {username} registered ({'encrypted' if encrypted_session else 'unencrypted'})")

                if is_admin_dashboard:
                    self.admin_dashboard_connections[addr] = username
                    self.admin_dashboard_clients.add(username)
                else:
                    self.active_connections[addr] = username

            # Send auth success response
            response = {
                'status': 'authenticated',
                'message': f'Connected as {"admin dashboard" if is_admin_dashboard else "user"}: {username}',
                'environments': verified_environments
            }

            if encrypted_session and message_handler:
                encrypted_response = message_handler.prepare_message(response)
                conn.sendall(encrypted_response.encode('utf-8'))
            else:
                conn.sendall((json.dumps(response) + '\n').encode('utf-8'))

            # Update UI
            if self.ui_update_callback:
                self.ui_update_callback()

            # Make socket non-blocking for packet processing
            conn.setblocking(False)

            # Enter main processing loop
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
                                    except Exception as e:
                                        print(f"[SERVER] Decryption error from {username}: {e}")
                                        continue

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
            import traceback
            traceback.print_exc()
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
        """Override to handle encrypted clients properly with personal vs environment protocol counts"""
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

                    # MODIFIED: Send different stats based on admin status
                    username = client_info['username']
                    is_admin = username in self.admin_clients
                    client_environments = client_info.get('environments', [])

                    for env_name in client_environments:
                        if is_admin:
                            # Admin clients get environment-wide protocol counts
                            with self.environment_lock:
                                if env_name in self.environments:
                                    env_protocol_counts = self.environments[env_name]['protocol_counts'].copy()
                                else:
                                    continue

                            env_stats_message = {
                                'type': 'stats',
                                'environment': env_name,
                                'protocol_counts': env_protocol_counts,
                                'timestamp': datetime.now().isoformat(),
                                'stats_type': 'environment'  # Indicate this is environment-wide data
                            }
                        else:
                            # Non-admin clients get their personal protocol counts
                            personal_protocol_counts = client_info.get('protocol_counts', {
                                'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SMTP': 0, 'Other': 0
                            }).copy()

                            env_stats_message = {
                                'type': 'stats',
                                'environment': env_name,
                                'protocol_counts': personal_protocol_counts,
                                'timestamp': datetime.now().isoformat(),
                                'stats_type': 'personal'  # Indicate this is personal data
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