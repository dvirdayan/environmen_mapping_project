import threading
import time
import queue
import socket
import json
import select
import traceback
import uuid
from datetime import datetime

# Import the original socket client
from proj3103.databaseV3.client.socket_client import StableSocketClient

# Import encryption module
try:
    from proj3103.back.crypto_handler import CryptoHandler, SecureMessageHandler, CRYPTO_AVAILABLE
except ImportError:
    print("Error: crypto_handler.py not found")
    CRYPTO_AVAILABLE = False


class EncryptedSocketClient(StableSocketClient):
    """Enhanced socket client with RSA/AES encryption support"""

    def __init__(self, host, port, logger=None, debug_mode=True, is_admin_dashboard=False, enable_encryption=True):
        super().__init__(host, port, logger, debug_mode, is_admin_dashboard)

        self.enable_encryption = enable_encryption and CRYPTO_AVAILABLE
        self.encrypted_session = False
        self.server_public_key = None

        if self.enable_encryption:
            self.crypto = CryptoHandler()
            self.message_handler = None
            self.log("Encryption support enabled for client")
        else:
            if enable_encryption and not CRYPTO_AVAILABLE:
                self.log("WARNING: Encryption requested but pycryptodome not installed")
                self.log("Client will connect in unencrypted mode")
            else:
                self.log("Running in unencrypted mode")

    def connect(self):
        """Connect to server with encryption support"""
        if self.connected and self.socket:
            return True

        try:
            # Close any existing socket
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None

            self.auth_attempts += 1
            if not self.is_admin_dashboard:
                self.log(f"Connecting to {self.host}:{self.port} (attempt {self.auth_attempts})")

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.connection_timeout)

            self.socket.connect((self.host, self.port))

            if not self.is_admin_dashboard:
                self.log(f"Connected to {self.host}:{self.port}")

            # Handle encryption handshake if enabled
            if self.enable_encryption:
                if not self.perform_encryption_handshake():
                    self.log("Encryption handshake failed")
                    return False

            # Handle authentication
            if not self.auth_data:
                self.auth_data = {
                    'type': 'auth',
                    'environments': self.environments,
                    'username': self.username,
                    'is_admin': self.is_admin,
                    'is_admin_dashboard': self.is_admin_dashboard
                }

            # Send auth data (encrypted if session is encrypted)
            if self.encrypted_session and self.message_handler:
                auth_message = self.message_handler.prepare_message(self.auth_data)
            else:
                auth_message = json.dumps(self.auth_data) + '\n'

            self.socket.sendall(auth_message.encode('utf-8'))

            if not self.is_admin_dashboard:
                self.log("Auth data sent, waiting for response...")

            # Wait for response
            response_data = b""
            timeout_time = time.time() + self.connection_timeout

            while time.time() < timeout_time:
                try:
                    self.socket.settimeout(2.0)
                    chunk = self.socket.recv(1024)

                    if chunk:
                        response_data += chunk
                        if b'\n' in response_data:
                            break
                    else:
                        if not self.is_admin_dashboard:
                            self.log("Server closed connection during auth")
                        return False

                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.is_admin_dashboard:
                        self.log(f"Auth error: {str(e)}")
                    return False

            if not response_data:
                if not self.is_admin_dashboard:
                    self.log("No authentication response received")
                return False

            # Check authentication
            response_text = response_data.decode('utf-8', errors='ignore').strip()

            # Try to decrypt if encrypted
            if self.encrypted_session and self.message_handler:
                try:
                    response_dict = self.message_handler.process_message(response_text)
                    if response_dict:
                        authenticated = response_dict.get('status') == 'authenticated'
                    else:
                        authenticated = False
                except:
                    authenticated = False
            else:
                # Original authentication check
                authenticated = False
                if "authenticated" in response_text or "success" in response_text:
                    authenticated = True
                else:
                    for line in response_text.split('\n'):
                        if line.strip():
                            try:
                                response = json.loads(line)
                                if response.get('status') == 'authenticated':
                                    authenticated = True
                                    break
                            except:
                                continue

            if not authenticated:
                if not self.is_admin_dashboard:
                    self.log("Authentication failed")
                return False

            # Set to non-blocking
            self.socket.setblocking(False)
            self.connected = True

            status_msg = "Successfully connected and authenticated"
            if self.encrypted_session:
                status_msg += " (encrypted)"
            if not self.is_admin_dashboard:
                self.log(status_msg)

            # If admin, request initial stats
            if self.is_admin:
                if not self.is_admin_dashboard:
                    self.log("Admin user connected - requesting initial stats")
                threading.Timer(1.0, self.request_admin_stats).start()

            # Reset counters
            with self.lock:
                self.packet_count = 0
                self.local_packet_count = 0
                self.acked_packet_ids.clear()

            self.auth_attempts = 0
            return True

        except Exception as e:
            if not self.is_admin_dashboard:
                self.log(f"Connection error: {str(e)}")
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            self.socket = None
            self.connected = False
            self.encrypted_session = False
            return False

    def perform_encryption_handshake(self):
        """Perform encryption handshake with server"""
        try:
            self.log("Starting encryption handshake...")

            # Wait for server hello with public key
            hello_data = b""
            timeout_time = time.time() + 10.0

            while time.time() < timeout_time:
                try:
                    chunk = self.socket.recv(4096)
                    if chunk:
                        hello_data += chunk
                        if b'\n' in hello_data:
                            break
                except socket.timeout:
                    continue

            if not hello_data:
                self.log("No server hello received")
                return False

            # Parse server hello
            hello_text = hello_data.decode('utf-8').strip()
            try:
                hello_msg = json.loads(hello_text.split('\n')[0])

                if hello_msg.get('type') != 'server_hello':
                    self.log("Invalid server hello")
                    return False

                if not hello_msg.get('encryption_enabled'):
                    self.log("Server does not support encryption")
                    self.enable_encryption = False
                    return True

                # Get server's public key
                server_public_key = hello_msg.get('public_key')
                if not server_public_key:
                    self.log("No public key in server hello")
                    return False

                # Load server's public key
                if not self.crypto.load_rsa_public_key(server_public_key):
                    self.log("Failed to load server public key")
                    return False

                self.log("Server public key loaded")

                # Generate AES key and send key exchange
                key_exchange_msg = self.crypto.create_key_exchange_message()
                self.socket.sendall((json.dumps(key_exchange_msg) + '\n').encode('utf-8'))
                self.log("Key exchange sent")

                # Wait for key exchange acknowledgment
                ack_data = b""
                timeout_time = time.time() + 10.0

                while time.time() < timeout_time:
                    try:
                        chunk = self.socket.recv(4096)
                        if chunk:
                            ack_data += chunk
                            if b'\n' in ack_data:
                                break
                    except socket.timeout:
                        continue

                if not ack_data:
                    self.log("No key exchange acknowledgment received")
                    return False

                # Create message handler for encrypted communication
                self.message_handler = SecureMessageHandler(self.crypto)

                # Try to decrypt the acknowledgment
                ack_text = ack_data.decode('utf-8').strip()
                try:
                    ack_msg = self.message_handler.process_message(ack_text.split('\n')[0])

                    if ack_msg and ack_msg.get('type') == 'key_exchange_ack' and ack_msg.get('status') == 'success':
                        self.encrypted_session = True
                        self.log("Encryption handshake complete - session is now encrypted")
                        return True
                    else:
                        self.log("Invalid key exchange acknowledgment")
                        return False

                except Exception as e:
                    self.log(f"Failed to decrypt key exchange ack: {e}")
                    return False

            except Exception as e:
                self.log(f"Error parsing server hello: {e}")
                return False

        except Exception as e:
            self.log(f"Encryption handshake error: {e}")
            return False

    def send_packet(self, packet_dict, target_environments=None):
        """Send packet with encryption if enabled"""
        if not self.running:
            return False

        try:
            if isinstance(packet_dict, dict):
                # Add standard fields
                if self.username and 'username' not in packet_dict:
                    packet_dict['username'] = self.username
                if 'packet_id' not in packet_dict:
                    packet_dict['packet_id'] = str(uuid.uuid4())

                # Add environments
                envs_to_send = self.environments
                if not envs_to_send:
                    return False
                packet_dict['environments'] = [env.get('env_name') for env in envs_to_send]

                # Prepare message (encrypt if session is encrypted)
                if self.encrypted_session and self.message_handler:
                    serialized = self.message_handler.prepare_message(packet_dict)
                else:
                    serialized = json.dumps(packet_dict) + '\n'

                # Queue the message
                try:
                    self.send_queue.put_nowait(serialized)
                    return True
                except queue.Full:
                    # Try to make room
                    try:
                        for _ in range(10):
                            self.send_queue.get_nowait()
                        self.send_queue.put_nowait(serialized)
                        return True
                    except:
                        return False
            else:
                return False

        except Exception as e:
            if not self.is_admin_dashboard:
                self.log(f"Error queueing packet: {str(e)}")
            return False

    def _recv_loop(self):
        """Enhanced receive loop with decryption support"""
        buffer = ""
        last_packet_count_log = 0
        last_admin_stats_request = 0

        while self.running:
            try:
                if not self.connected or self.socket is None:
                    time.sleep(1.0)
                    continue

                with self.lock:
                    if not self.connected or self.socket is None:
                        continue
                    current_socket = self.socket

                try:
                    readable, _, exceptional = select.select([current_socket], [], [current_socket], 1.0)
                except:
                    with self.lock:
                        self.connected = False
                        if self.socket:
                            try:
                                self.socket.close()
                            except:
                                pass
                            self.socket = None
                    continue

                if current_socket in exceptional:
                    with self.lock:
                        self.connected = False
                        if self.socket:
                            try:
                                self.socket.close()
                            except:
                                pass
                            self.socket = None
                    continue

                if current_socket in readable:
                    try:
                        data = current_socket.recv(4096)

                        if not data:
                            if not self.is_admin_dashboard:
                                self.log("Connection closed by server")
                            with self.lock:
                                self.connected = False
                                if self.socket:
                                    try:
                                        self.socket.close()
                                    except:
                                        pass
                                    self.socket = None
                            continue

                        text_data = data.decode('utf-8')
                        buffer += text_data

                        if len(buffer) > 10000:
                            buffer = buffer[-5000:]

                        messages_processed = 0
                        max_messages_per_cycle = 10

                        while '\n' in buffer and messages_processed < max_messages_per_cycle:
                            line, buffer = buffer.split('\n', 1)
                            if not line.strip():
                                continue

                            try:
                                # Decrypt if encrypted session
                                if self.encrypted_session and self.message_handler:
                                    response = self.message_handler.process_message(line)
                                    if not response:
                                        continue
                                else:
                                    response = json.loads(line)

                                # Process message (same as original)
                                msg_type = response.get('type', 'unknown')

                                if msg_type == 'ack':
                                    self.last_ack_time = time.time()
                                    packet_id = response.get('packet_id')

                                    if packet_id and packet_id not in self.acked_packet_ids:
                                        with self.lock:
                                            self.packet_count += 1
                                            self.local_packet_count += 1
                                            self.acked_packet_ids.add(packet_id)

                                            if len(self.acked_packet_ids) > 1000:
                                                self.acked_packet_ids = set(list(self.acked_packet_ids)[-500:])

                                            if not self.is_admin_dashboard and self.packet_count - last_packet_count_log >= 50:
                                                self.log(f"Packet count: {self.packet_count}")
                                                last_packet_count_log = self.packet_count

                                elif msg_type == 'stats':
                                    current_time = time.time()

                                    if current_time - self.last_ui_update < self.ui_update_interval:
                                        continue

                                    if 'environment' not in response and 'protocol_counts' in response:
                                        self.last_ui_update = current_time
                                        self.protocol_counts = response['protocol_counts']

                                        if self.protocol_update_callback:
                                            try:
                                                self.protocol_update_callback(self.protocol_counts, None)
                                            except Exception as e:
                                                if self.verbose_logging and not self.is_admin_dashboard:
                                                    self.log(f"Error in UI callback: {e}")

                                elif msg_type == 'admin_stats':
                                    if self.is_admin and self.admin_stats_callback:
                                        try:
                                            admin_data = response.get('data', {})
                                            self.admin_stats_callback(admin_data)
                                            if self.verbose_logging and not self.is_admin_dashboard:
                                                client_count = len(admin_data.get('clients', {}))
                                                self.log(f"Received admin stats: {client_count} clients")
                                        except Exception as e:
                                            if not self.is_admin_dashboard:
                                                self.log(f"Error in admin stats callback: {e}")

                                elif msg_type == 'authenticated':
                                    if not self.is_admin_dashboard:
                                        self.log("Authentication confirmed")

                                elif msg_type == 'error':
                                    if not self.is_admin_dashboard:
                                        self.log(f"Server error: {response.get('message', 'Unknown')}")

                                messages_processed += 1

                            except json.JSONDecodeError:
                                pass

                        # Periodic admin stats request
                        if self.is_admin and self.connected and self.is_admin_dashboard:
                            current_time = time.time()
                            if current_time - last_admin_stats_request > 2.0:
                                self.request_admin_stats()
                                last_admin_stats_request = current_time

                    except Exception as e:
                        if self.verbose_logging and not self.is_admin_dashboard:
                            self.log(f"Error processing received data: {str(e)}")
                        time.sleep(0.5)

            except Exception as e:
                if not self.is_admin_dashboard:
                    self.log(f"Unexpected error in receive loop: {str(e)}")
                time.sleep(2.0)

    def request_admin_stats(self):
        """Request admin stats with encryption support"""
        if self.is_admin and self.connected:
            request_msg = {
                'type': 'admin_stats_request',
                'username': self.username,
                'is_admin_dashboard': self.is_admin_dashboard
            }

            try:
                # Encrypt if session is encrypted
                if self.encrypted_session and self.message_handler:
                    serialized = self.message_handler.prepare_message(request_msg)
                else:
                    serialized = json.dumps(request_msg) + '\n'

                self.send_queue.put_nowait(serialized)

                if not self.is_admin_dashboard:
                    self.log("Requested admin stats from server")

            except queue.Full:
                self.log("Failed to request admin stats - queue full")


# Test the encrypted client
if __name__ == "__main__":
    import sys

    # Simple test
    print("Testing encrypted socket client...")

    # Check if encryption is available
    if not CRYPTO_AVAILABLE:
        print("WARNING: pycryptodome not installed!")
        print("Install with: pip install pycryptodome")
        sys.exit(1)

    # Create test client
    client = EncryptedSocketClient('localhost', 9007, debug_mode=True)

    # Set up test authentication
    client.set_auth(
        environments=[{'env_name': 'test', 'env_password': 'test'}],
        username='test_user',
        account_info={'user_id': '123', 'username': 'test_user'}
    )

    # Start client
    client.start()

    print("Client started. Press Ctrl+C to stop...")

    try:
        # Keep running
        while True:
            time.sleep(1)

            # Send test packet
            if client.connected:
                test_packet = {
                    'type': 'packet',
                    'protocol': 'TCP',
                    'source_ip': '192.168.1.100',
                    'destination_ip': '10.0.0.1',
                    'timestamp': datetime.now().isoformat()
                }

                if client.send_packet(test_packet):
                    print("Test packet sent")

    except KeyboardInterrupt:
        print("\nStopping client...")
        client.stop()