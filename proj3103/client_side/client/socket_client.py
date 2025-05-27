import threading
import time
import queue
import socket
import json
import select
import traceback
import uuid
from datetime import datetime


class StableSocketClient:
    def __init__(self, host, port, logger=None, debug_mode=True, is_admin_dashboard=False):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.running = False
        self.logger = logger
        self.debug_mode = debug_mode
        self.reconnect_delay = 2.0  # CHANGED: from 5.0
        self.send_thread = None
        self.recv_thread = None
        self.last_ack_time = 0
        self.packet_count = 0
        self.local_packet_count = 0
        self.auth_data = None
        self.environments = []
        self.username = None
        self.lock = threading.Lock()
        self.send_queue = queue.Queue(maxsize=500)  # CHANGED: from 50
        self.pending_packets = set()
        self.pending_packets_lock = threading.Lock()
        self.acked_packet_ids = set()
        self.protocol_counts = {
            'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SMTP': 0, 'Other': 0
        }
        self.environment_protocol_counts = {}
        self.protocol_update_callback = None
        self.auth_attempts = 0
        self.max_auth_attempts = 3
        self.verbose_logging = False
        self.connection_timeout = 30.0  # CHANGED: from 15.0
        self.last_ui_update = 0
        self.ui_update_interval = 2.0  # CHANGED: from 10.0

        # Admin support
        self.is_admin = False
        self.admin_stats_callback = None
        self.is_admin_dashboard = is_admin_dashboard  # NEW: Flag to identify admin dashboard connections

        self.log(f"Initialized StableSocketClient for {host}:{port} (Admin Dashboard: {is_admin_dashboard})")

    def log(self, message):
        """Log a message with optional debug prefix"""
        if self.debug_mode:
            timestamp = datetime.now().strftime('%H:%M:%S')
            formatted_message = f"[{timestamp}][CLIENT] {message}"
        else:
            formatted_message = message

        if self.logger:
            self.logger(formatted_message)
        else:
            print(formatted_message)

    def start(self):
        """Start the client."""
        if self.running:
            return
        self.running = True
        self.log("Starting client threads...")

        # Start send thread
        self.send_thread = threading.Thread(target=self._send_loop)
        self.send_thread.daemon = True
        self.send_thread.start()

        # Start receive thread
        self.recv_thread = threading.Thread(target=self._recv_loop)
        self.recv_thread.daemon = True
        self.recv_thread.start()

        self.log("Client threads started")

    def set_auth(self, environments, username=None, account_info=None):
        """Set authentication data with multiple environments"""
        self.username = username
        self.log(f"Setting authentication for user: {username}")

        # Check if user is admin
        if account_info and isinstance(account_info, dict):
            self.is_admin = account_info.get('is_admin', False)
            if self.is_admin:
                self.log(f"User {username} is an ADMIN")

        # Store the environments
        if isinstance(environments, list):
            self.environments = environments
        else:
            # For backward compatibility
            env_name = getattr(environments, 'env_name', environments)
            env_password = getattr(environments, 'env_password', None)
            self.environments = [{'env_name': env_name, 'env_password': env_password}]

        # Ensure we have at least one environment
        if not self.environments:
            self.log("WARNING: No environments provided, using default")
            self.environments = [{'env_name': 'default', 'env_password': 'default_password'}]

        # Initialize protocol counts for each environment
        for env in self.environments:
            env_name = env.get('env_name', 'default')
            if env_name not in self.environment_protocol_counts:
                self.environment_protocol_counts[env_name] = {
                    'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SMTP': 0, 'Other': 0
                }

        # Create auth data with all environments
        self.auth_data = {
            'type': 'auth',
            'environments': self.environments,
            'username': username,
            'account_info': account_info,
            'is_admin': self.is_admin,
            'is_admin_dashboard': self.is_admin_dashboard
        }

    def set_protocol_update_callback(self, callback):
        """Set callback function to be called when protocol counts are updated"""
        self.protocol_update_callback = callback

    def set_admin_stats_callback(self, callback):
        """Set callback for admin statistics updates"""
        self.admin_stats_callback = callback
        self.log("Admin stats callback registered")

    def request_admin_stats(self):
        """Request admin statistics from server"""
        if self.is_admin and self.connected:
            request_msg = {
                'type': 'admin_stats_request',
                'username': self.username,
                'is_admin_dashboard': self.is_admin_dashboard  # NEW: Include dashboard flag
            }
            try:
                self.send_queue.put_nowait(json.dumps(request_msg) + '\n')
                if not self.is_admin_dashboard:  # Only log for regular clients, not dashboard
                    self.log("Requested admin stats from server")
            except queue.Full:
                self.log("Failed to request admin stats - queue full")

    def connect(self):
        """Attempt to connect to the server with improved error handling."""
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
            if not self.is_admin_dashboard:  # Only log connection attempts for regular clients
                self.log(f"Connecting to {self.host}:{self.port} (attempt {self.auth_attempts})")

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.connection_timeout)

            self.socket.connect((self.host, self.port))

            if not self.is_admin_dashboard:  # Only log for regular clients
                self.log(f"Connected to {self.host}:{self.port}")

            # Handle authentication
            if not self.auth_data:
                self.auth_data = {
                    'type': 'auth',
                    'environments': self.environments,
                    'username': self.username,
                    'is_admin': self.is_admin,
                    'is_admin_dashboard': self.is_admin_dashboard  # NEW: Include dashboard flag
                }

            # Send auth data
            auth_message = json.dumps(self.auth_data) + '\n'
            self.socket.sendall(auth_message.encode('utf-8'))

            if not self.is_admin_dashboard:  # Only log for regular clients
                self.log("Auth data sent, waiting for response...")

            # Wait for response
            response_data = b""
            timeout_time = time.time() + self.connection_timeout

            while time.time() < timeout_time:
                try:
                    self.socket.settimeout(2.0)  # **LAG FIX: Shorter timeout**
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

            authenticated = False
            if "authenticated" in response_text or "success" in response_text:
                authenticated = True
            else:
                # Try parsing JSON
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

            if not self.is_admin_dashboard:  # Only log for regular clients
                self.log("Successfully connected and authenticated")

            # If admin, request initial stats
            if self.is_admin:
                if not self.is_admin_dashboard:
                    self.log("Admin user connected - requesting initial stats")
                # Delay the initial request slightly
                threading.Timer(1.0, self.request_admin_stats).start()

            # Reset counters
            with self.lock:
                self.packet_count = 0
                self.local_packet_count = 0
                self.acked_packet_ids.clear()

            self.auth_attempts = 0
            return True

        except Exception as e:
            if not self.is_admin_dashboard:  # Only log errors for regular clients
                self.log(f"Connection error: {str(e)}")
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            self.socket = None
            self.connected = False
            return False

    def stop(self):
        """Stop the client."""
        if not self.running:
            return
        self.running = False
        if not self.is_admin_dashboard:  # Only log for regular clients
            self.log("Stopping client...")

        with self.lock:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            self.connected = False

        if not self.is_admin_dashboard:  # Only log for regular clients
            self.log("Client stopped")

    def send_packet(self, packet_dict, target_environments=None):
        """Send a packet to all environments the user is connected to."""
        if not self.running:
            return False
        try:
            if isinstance(packet_dict, dict):
                if self.username and 'username' not in packet_dict:
                    packet_dict['username'] = self.username
                if 'packet_id' not in packet_dict:
                    packet_dict['packet_id'] = str(uuid.uuid4())
                envs_to_send = self.environments
                if not envs_to_send:
                    return False
                packet_dict['environments'] = [env.get('env_name') for env in envs_to_send]
                serialized = json.dumps(packet_dict) + '\n'
                try:
                    self.send_queue.put_nowait(serialized)
                    return True
                except queue.Full:
                    try:
                        for _ in range(10):
                            self.send_queue.get_nowait()
                        self.send_queue.put_nowait(serialized)
                        return True
                    except queue.Empty:
                        try:
                            self.send_queue.put_nowait(serialized)
                            return True
                        except queue.Full:
                            return False
                    except Exception:
                        return False
            else:
                return False
        except Exception as e:
            if not self.is_admin_dashboard:  # Only log errors for regular clients
                self.log(f"Error queueing packet: {str(e)}")
            return False

    def _send_loop(self):
        """Background thread for sending packets"""
        reconnect_time = 0
        consecutive_failures = 0
        while self.running:
            try:
                current_time = time.time()
                if not self.connected or self.socket is None:
                    if current_time - reconnect_time >= self.reconnect_delay:
                        reconnect_time = current_time
                        if self.auth_attempts < self.max_auth_attempts:
                            if self.connect():
                                consecutive_failures = 0
                                if not self.is_admin_dashboard:  # Only log for regular clients
                                    self.log("Reconnected successfully")
                        else:
                            time.sleep(self.reconnect_delay * 2)
                            self.auth_attempts = 0
                    time.sleep(0.5)
                    continue
                packets_sent = 0
                max_packets_per_batch = 20
                batch_start_time = time.time()
                while packets_sent < max_packets_per_batch and (time.time() - batch_start_time < 1.0):
                    try:
                        data = self.send_queue.get(timeout=0.1)
                    except queue.Empty:
                        break
                    try:
                        with self.lock:
                            if not self.connected or self.socket is None:
                                self.send_queue.put(data)
                                break
                            if isinstance(data, dict):
                                data = json.dumps(data) + '\n'
                            elif isinstance(data, str) and not data.endswith('\n'):
                                data += '\n'
                            self.socket.sendall(data.encode('utf-8'))
                            packets_sent += 1
                            consecutive_failures = 0
                    except socket.error as e:
                        consecutive_failures += 1
                        if not self.is_admin_dashboard:  # Only log errors for regular clients
                            self.log(f"Send error (#{consecutive_failures}): {str(e)}")
                        try:
                            self.send_queue.put(data)
                        except:
                            pass
                        with self.lock:
                            self.connected = False
                            if self.socket:
                                try:
                                    self.socket.close()
                                except:
                                    pass
                                self.socket = None
                        break
                    except Exception as e:
                        consecutive_failures += 1
                        if not self.is_admin_dashboard:  # Only log errors for regular clients
                            self.log(f"Unexpected send error: {str(e)}")
                        break
                time.sleep(0.1)
            except Exception as e:
                if not self.is_admin_dashboard:  # Only log errors for regular clients
                    self.log(f"Unexpected error in send loop: {str(e)}")
                time.sleep(1.0)

    def _recv_loop(self):
        """Background thread for receiving responses"""
        buffer = ""
        last_packet_count_log = 0
        last_admin_stats_request = 0

        while self.running:
            try:
                # Check connection status
                if not self.connected or self.socket is None:
                    time.sleep(1.0)  # **LAG FIX: Longer sleep**
                    continue

                # Make a local copy of socket
                with self.lock:
                    if not self.connected or self.socket is None:
                        continue
                    current_socket = self.socket

                # Check for data with longer timeout
                try:
                    readable, _, exceptional = select.select([current_socket], [], [current_socket],
                                                             1.0)  # **LAG FIX: Longer timeout**
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

                # Check for exceptional conditions
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

                # Process readable socket
                if current_socket in readable:
                    try:
                        data = current_socket.recv(4096)

                        if not data:
                            if not self.is_admin_dashboard:  # Only log for regular clients
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

                        # Process the data
                        text_data = data.decode('utf-8')
                        buffer += text_data

                        # **LAG FIX: Limit buffer size**
                        if len(buffer) > 10000:
                            buffer = buffer[-5000:]  # Keep only last 5000 characters

                        # Process complete messages
                        messages_processed = 0
                        max_messages_per_cycle = 10  # **LAG FIX: Limit messages processed**

                        while '\n' in buffer and messages_processed < max_messages_per_cycle:
                            line, buffer = buffer.split('\n', 1)
                            if not line.strip():
                                continue

                            try:
                                response = json.loads(line)
                                msg_type = response.get('type', 'unknown')

                                if msg_type == 'ack':
                                    self.last_ack_time = time.time()
                                    packet_id = response.get('packet_id')

                                    if packet_id and packet_id not in self.acked_packet_ids:
                                        with self.lock:
                                            self.packet_count += 1
                                            self.local_packet_count += 1
                                            self.acked_packet_ids.add(packet_id)

                                            # **LAG FIX: Limit set size more aggressively**
                                            if len(self.acked_packet_ids) > 1000:
                                                self.acked_packet_ids = set(list(self.acked_packet_ids)[-500:])

                                            # **LAG FIX: Log less frequently and only for regular clients**
                                            if not self.is_admin_dashboard and self.packet_count - last_packet_count_log >= 50:
                                                self.log(f"Packet count: {self.packet_count}")
                                                last_packet_count_log = self.packet_count

                                elif msg_type == 'stats':
                                    # **LAG FIX: Heavy throttling for UI updates**
                                    current_time = time.time()

                                    if current_time - self.last_ui_update < self.ui_update_interval:
                                        continue

                                    # Only process global stats
                                    if 'environment' not in response and 'protocol_counts' in response:
                                        self.last_ui_update = current_time
                                        self.protocol_counts = response['protocol_counts']

                                        # Call UI update callback if registered
                                        if self.protocol_update_callback:
                                            try:
                                                self.protocol_update_callback(self.protocol_counts, None)
                                            except Exception as e:
                                                if self.verbose_logging and not self.is_admin_dashboard:
                                                    self.log(f"Error in UI callback: {e}")

                                elif msg_type == 'admin_stats':
                                    # Handle admin statistics
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
                                    if not self.is_admin_dashboard:  # Only log for regular clients
                                        self.log("Authentication confirmed")

                                elif msg_type == 'error':
                                    if not self.is_admin_dashboard:  # Only log for regular clients
                                        self.log(f"Server error: {response.get('message', 'Unknown')}")

                                messages_processed += 1

                            except json.JSONDecodeError:
                                # Skip invalid JSON
                                pass

                        # Periodic admin stats request
                        if self.is_admin and self.connected and self.is_admin_dashboard:
                            current_time = time.time()
                            if current_time - last_admin_stats_request > 2.0:  # Request every 2 seconds
                                self.request_admin_stats()
                                last_admin_stats_request = current_time

                    except Exception as e:
                        if self.verbose_logging and not self.is_admin_dashboard:
                            self.log(f"Error processing received data: {str(e)}")
                        time.sleep(0.5)

            except Exception as e:
                if not self.is_admin_dashboard:  # Only log errors for regular clients
                    self.log(f"Unexpected error in receive loop: {str(e)}")
                time.sleep(2.0)

    def get_packet_count(self):
        """Return the current packet count"""
        with self.lock:
            return self.local_packet_count

    def get_protocol_counts(self, environment=None):
        """Return protocol counts"""
        if environment and environment in self.environment_protocol_counts:
            return self.environment_protocol_counts[environment].copy()
        return self.protocol_counts.copy()

    def get_environments(self):
        """Return the list of environments"""
        return [env.get('env_name') for env in self.environments]