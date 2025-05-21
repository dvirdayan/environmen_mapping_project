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
    def __init__(self, host, port, logger=None, debug_mode=True):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.running = False
        self.logger = logger
        self.debug_mode = debug_mode  # Debug mode is enabled by default
        self.reconnect_delay = 2.0
        self.send_thread = None
        self.recv_thread = None
        self.last_ack_time = 0
        self.packet_count = 0
        self.local_packet_count = 0
        self.auth_data = None
        self.environments = []  # List of environment dictionaries
        self.username = None  # Add username field
        self.lock = threading.Lock()
        self.send_queue = queue.Queue()
        self.pending_packets = set()
        self.pending_packets_lock = threading.Lock()
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'FTP': 0,
            'SMTP': 0,
            'Other': 0
        }
        # Store protocol counts per environment
        self.environment_protocol_counts = {}
        self.protocol_update_callback = None

        # Track authentication attempts
        self.auth_attempts = 0
        self.max_auth_attempts = 3

        # Debug flags
        self.verbose_logging = True  # Set to True for maximum verbosity

        # Extended timeout for connections
        self.connection_timeout = 30.0  # Increased from 10 to 30 seconds

        # Log initialization
        self.log(f"Initialized StableSocketClient for {host}:{port} with debug_mode={debug_mode}")

    def log(self, message):
        """Log a message with optional debug prefix"""
        if self.debug_mode:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            formatted_message = f"[{timestamp}][SOCKET_CLIENT] {message}"
        else:
            formatted_message = message

        if self.logger:
            self.logger(formatted_message)
        else:
            print(formatted_message)

    def start(self):
        """Start the client."""
        if self.running:  # Check if already running
            if self.logger:
                self.logger("Client is already running.")
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
        """Set authentication data with multiple environments
        Args:
            environments: List of dictionaries with env_name and env_password
            username: Username for authentication
            account_info: Additional account information
        """
        self.username = username
        self.log(f"Setting authentication for user: {username}")

        # Store the environments
        if isinstance(environments, list):
            self.environments = environments
            self.log(f"Setting {len(environments)} environments")
        else:
            # For backward compatibility, convert single environment to list
            env_name = getattr(environments, 'env_name', environments)
            env_password = getattr(environments, 'env_password', None)
            self.environments = [{'env_name': env_name, 'env_password': env_password}]
            self.log(f"Converting single environment {env_name} to list format")

        # Ensure we have at least one environment
        if not self.environments:
            self.log("WARNING: No environments provided, using default")
            self.environments = [{'env_name': 'default', 'env_password': 'default_password'}]

        # Log the environments (mask passwords)
        for env in self.environments:
            masked_pw = '*' * len(env.get('env_password', '')) if env.get('env_password') else None
            self.log(f"Environment: {env.get('env_name')}, Password: {masked_pw}")

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
            'account_info': account_info
        }

        # Log auth data with masked passwords
        masked_auth = self.auth_data.copy()
        if 'environments' in masked_auth:
            masked_auth['environments'] = []
            for env in self.environments:
                masked_env = env.copy()
                if 'env_password' in masked_env:
                    masked_env['env_password'] = '*' * len(masked_env['env_password']) if masked_env[
                        'env_password'] else None
                masked_auth['environments'].append(masked_env)

        self.log(f"Auth data set: {json.dumps(masked_auth, indent=2)}")

    def set_protocol_update_callback(self, callback):
        """Set callback function to be called when protocol counts are updated"""
        self.protocol_update_callback = callback

    def connect(self):
        """Attempt to connect to the server with improved error handling."""
        if self.connected and self.socket:
            self.log("Already connected, skipping connection attempt")
            return True

        try:
            # Close any existing socket
            if self.socket:
                try:
                    self.log("Closing existing socket before reconnect")
                    self.socket.close()
                except Exception as e:
                    self.log(f"Error closing existing socket: {str(e)}")
                self.socket = None

            self.auth_attempts += 1
            self.log(f"Attempting to connect to {self.host}:{self.port} (attempt {self.auth_attempts})")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.connection_timeout)  # Use extended timeout

            # Log socket options
            self.log(f"Socket created with timeout={self.connection_timeout}s")

            try:
                # Get address info before connecting
                address_info = socket.getaddrinfo(self.host, self.port,
                                                  socket.AF_INET, socket.SOCK_STREAM)
                self.log(f"Address info: {address_info}")
            except socket.gaierror as e:
                self.log(f"Error resolving address: {str(e)}")

            connection_start = time.time()
            self.socket.connect((self.host, self.port))
            connection_time = time.time() - connection_start
            self.log(f"Socket connected to {self.host}:{self.port} in {connection_time:.2f}s")

            # Add a small delay to ensure the server is ready for authentication
            time.sleep(0.2)

            # Handle authentication - always send auth data
            if not self.auth_data:
                # Create minimal auth data if none exists
                self.log("WARNING: No auth data set before connect, creating minimal auth")
                self.auth_data = {
                    'type': 'auth',
                    'environments': self.environments,
                    'username': self.username
                }

            try:
                # Log what we're sending (mask passwords)
                log_data = self.auth_data.copy()
                if 'environments' in log_data:
                    for env in log_data['environments']:
                        if 'env_password' in env:
                            env['env_password'] = '******'
                self.log(f"Sending auth data: {json.dumps(log_data, indent=2)}")

                # Send auth data
                auth_message = json.dumps(self.auth_data) + '\n'
                self.log(f"Raw auth message ({len(auth_message)} bytes): {auth_message}")

                send_start = time.time()
                self.socket.sendall(auth_message.encode('utf-8'))
                send_time = time.time() - send_start
                self.log(f"Auth data sent in {send_time:.2f}s, waiting for response...")

                # Wait for response with timeout
                response_data = b""
                timeout_time = time.time() + self.connection_timeout  # Extended timeout for response

                # Track the response receiving process
                last_log_time = time.time()
                chunks_received = 0

                while time.time() < timeout_time:
                    try:
                        # Log waiting for data periodically
                        if time.time() - last_log_time > 1.0:  # Log every second
                            self.log(f"Waiting for auth response... ({chunks_received} chunks so far)")
                            last_log_time = time.time()

                        # Try to receive with shorter timeout
                        self.socket.settimeout(1.0)
                        chunk = self.socket.recv(1024)

                        if chunk:
                            chunks_received += 1
                            chunk_hex = ' '.join([f'{b:02x}' for b in chunk[:20]]) + "..." if len(
                                chunk) > 20 else ' '.join([f'{b:02x}' for b in chunk])
                            self.log(f"Received chunk {chunks_received}: {len(chunk)} bytes, hex: {chunk_hex}")
                            response_data += chunk

                            # Log raw received data for debugging
                            try:
                                chunk_text = chunk.decode('utf-8', errors='ignore')
                                self.log(f"Chunk {chunks_received} text: {chunk_text}")
                            except:
                                pass
                        else:
                            self.log("Server closed connection during auth (empty chunk)")
                            break

                        # Check if we have a complete response (has newline)
                        if b'\n' in response_data:
                            self.log("Complete response received (found newline)")
                            break

                    except socket.timeout:
                        self.log("Socket timeout during single auth response chunk, continuing to wait")
                        continue  # Continue waiting for data
                    except Exception as e:
                        self.log(f"Exception during auth response chunk: {str(e)}")
                        break

                # Check for timeout
                if time.time() >= timeout_time:
                    self.log("Authentication timed out waiting for response")
                    self.socket.close()
                    self.socket = None
                    return False

                if not response_data:
                    self.log("No authentication response received")
                    self.socket.close()
                    self.socket = None
                    return False

                # Decode the response
                response_text = response_data.decode('utf-8', errors='ignore').strip()
                self.log(f"Auth response received ({len(response_text)} bytes)")
                self.log(f"Full response text: {response_text}")

                # Process response to determine if authenticated
                authenticated = False

                # Check for simple text match first
                if "authenticated" in response_text or "success" in response_text:
                    authenticated = True
                    self.log("Authentication successful via text matching")
                else:
                    # Try parsing JSON for each line
                    for line in response_text.split('\n'):
                        if not line.strip():
                            continue
                        try:
                            self.log(f"Trying to parse JSON line: {line}")
                            response = json.loads(line)
                            self.log(f"Parsed JSON response: {json.dumps(response, indent=2)}")

                            if response.get('status') == 'authenticated':
                                authenticated = True
                                self.log("Authentication successful via JSON parsing")

                                # Check if server sent back allowed environments
                                if 'environments' in response:
                                    self.log(f"Server confirmed environments: {response['environments']}")
                                break
                        except json.JSONDecodeError as e:
                            self.log(f"Failed to parse JSON response line: {line[:100]} - Error: {str(e)}")
                            continue

                if not authenticated:
                    self.log("Authentication failed - server did not confirm authentication")
                    self.socket.close()
                    self.socket = None
                    return False

                # Set to non-blocking for normal operation
                self.socket.setblocking(False)
                self.connected = True
                self.log(f"Successfully connected to server {self.host}:{self.port}")

                # Reset packet count on successful reconnection
                with self.lock:
                    self.packet_count = 0

                # Clear pending packets on reconnection
                with self.pending_packets_lock:
                    self.pending_packets.clear()

                # Reset auth attempts counter on success
                self.auth_attempts = 0

                # Wait a short time before sending packets to ensure everything is ready
                time.sleep(0.5)
                return True

            except socket.timeout:
                self.log("Authentication response timeout")
                self.socket.close()
                self.socket = None
                return False
            except Exception as e:
                self.log(f"Authentication error: {str(e)}")
                self.log(traceback.format_exc())
                self.socket.close()
                self.socket = None
                return False

        except socket.error as e:
            self.log(f"Connection error: {str(e)}")
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            self.socket = None
            self.connected = False
            return False
        except Exception as e:
            self.log(f"Unexpected connection error: {str(e)}")
            self.log(traceback.format_exc())
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            self.socket = None
            self.connected = False
            return False

    def send(self, data):
        """Send data to the server."""
        try:
            self.socket.sendall(data)
        except socket.error as e:
            if self.logger:
                self.logger(f"Send error: {e}")
            self.connected = False
            self.connect()  # Reconnect and retry

    def receive(self):
        """Receive data from the server."""
        try:
            return self.socket.recv(1024)
        except socket.error as e:
            if self.logger:
                self.logger(f"Receive error: {e}")
            self.connected = False
            self.connect()  # Reconnect and retry

    def stop(self):
        """Stop the client."""
        if not self.running:  # Check if already stopped
            if self.logger:
                self.logger("Client is not running.")
            return
        self.running = False
        self.log("Stopping client...")

        # Clear queue
        try:
            while not self.send_queue.empty():
                try:
                    self.send_queue.get_nowait()
                except queue.Empty:
                    break
        except:
            pass

        with self.lock:
            if self.socket:
                try:
                    self.log("Closing socket...")
                    self.socket.close()
                except Exception as e:
                    self.log(f"Error closing socket: {str(e)}")
                self.socket = None
            self.connected = False

        # Wait for threads
        if self.send_thread and self.send_thread.is_alive():
            self.log("Waiting for send thread to stop...")
            self.send_thread.join(timeout=1.0)

        if self.recv_thread and self.recv_thread.is_alive():
            self.log("Waiting for receive thread to stop...")
            self.recv_thread.join(timeout=1.0)

        self.log("Client stopped")

    def send_packet(self, packet_dict, target_environments=None):
        """Send a packet to all environments the user is connected to.

        Args:
            packet_dict: The packet data to send
            target_environments: Ignored - always sends to all environments
        """
        if not self.running:
            return False

        try:
            if isinstance(packet_dict, dict):
                # Add username to each packet
                if self.username and 'username' not in packet_dict:
                    packet_dict['username'] = self.username

                # Always ensure packet has a unique ID
                if 'packet_id' not in packet_dict:
                    packet_dict['packet_id'] = str(uuid.uuid4())

                # Always send to all configured environments, ignoring target_environments
                envs_to_send = self.environments

                if not envs_to_send:
                    self.log("Warning: No environments to send packet to")
                    return False

                # Add environments list to packet
                packet_dict['environments'] = [env.get('env_name') for env in envs_to_send]

                # Add to pending packets set with lock
                with self.pending_packets_lock:
                    packet_id = packet_dict['packet_id']
                    self.pending_packets.add(packet_id)

                serialized = json.dumps(packet_dict) + '\n'
                self.send_queue.put(serialized)

                if self.verbose_logging:
                    self.log(
                        f"[CLIENT] Queued packet {packet_dict['packet_id']} for environments: {packet_dict['environments']}")
                return True
            else:
                self.log(f"Error: Expected dict for packet, got {type(packet_dict)}")
                return False
        except Exception as e:
            self.log(f"Error queueing packet: {str(e)}")
            self.log(traceback.format_exc())
            return False

    def _send_loop(self):
        """Background thread for sending packets"""
        reconnect_time = 0
        last_heartbeat_time = time.time()

        while self.running:
            try:
                current_time = time.time()

                # Check connection status first
                if not self.connected or self.socket is None:
                    # Don't spam reconnection attempts
                    if current_time - reconnect_time >= self.reconnect_delay:
                        reconnect_time = current_time
                        # Only try to reconnect if we haven't exceeded max attempts
                        if self.auth_attempts < self.max_auth_attempts:
                            if self.connect():  # Try to connect with proper error handling
                                # Reset heartbeat timer after successful reconnection
                                last_heartbeat_time = current_time
                        else:
                            self.log(
                                f"Exceeded max auth attempts ({self.max_auth_attempts}). Waiting longer before retry.")
                            time.sleep(self.reconnect_delay * 5)  # Wait 5x longer
                            self.auth_attempts = 0  # Reset counter to allow future attempts
                    time.sleep(0.5)
                    continue

                # Send heartbeat every 30 seconds if no other activity
                if current_time - last_heartbeat_time > 30:
                    try:
                        heartbeat = {
                            'type': 'heartbeat',
                            'timestamp': datetime.now().isoformat(),
                            'environments': [env.get('env_name') for env in self.environments]
                        }

                        serialized = json.dumps(heartbeat) + '\n'
                        with self.lock:
                            if self.socket and self.connected:
                                self.socket.sendall(serialized.encode('utf-8'))
                                self.log("Sent heartbeat")
                                last_heartbeat_time = current_time
                    except Exception as e:
                        self.log(f"Error sending heartbeat: {str(e)}")
                        with self.lock:
                            self.connected = False
                            if self.socket:
                                try:
                                    self.socket.close()
                                except:
                                    pass
                                self.socket = None
                        continue

                # Get next packet from queue with timeout
                try:
                    data = self.send_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                # Send the packet
                try:
                    with self.lock:
                        if not self.connected or self.socket is None:
                            # Put the packet back in the queue
                            self.send_queue.put(data)
                            continue

                        # Make sure data is properly formatted
                        if isinstance(data, dict):
                            data = json.dumps(data) + '\n'
                        elif isinstance(data, str) and not data.endswith('\n'):
                            data += '\n'

                        self.socket.sendall(data.encode('utf-8'))

                except Exception as e:
                    self.log(f"Send error: {str(e)}")
                    # Put the packet back in the queue to retry later
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

            except Exception as e:
                self.log(f"Unexpected error in send loop: {str(e)}")
                traceback.print_exc()
                time.sleep(1)

    def _recv_loop(self):
        """Background thread for receiving responses"""
        buffer = ""
        last_packet_count_log = 0

        while self.running:
            try:
                # Check connection status
                if not self.connected or self.socket is None:
                    time.sleep(0.5)
                    continue

                # Make a local copy of socket to avoid race conditions
                with self.lock:
                    if not self.connected or self.socket is None:
                        continue
                    current_socket = self.socket

                # Safely check for data without holding the lock
                try:
                    # Use select with a short timeout to avoid blocking
                    readable, _, exceptional = select.select([current_socket], [], [current_socket], 0.5)
                except (select.error, ValueError, TypeError) as e:
                    self.log(f"Socket selection error: {str(e)}")
                    with self.lock:
                        self.connected = False
                        if self.socket:
                            try:
                                self.socket.close()
                            except Exception as close_error:
                                self.log(f"Error closing socket: {close_error}")
                            self.socket = None
                    continue

                # Check for exceptional conditions
                if current_socket in exceptional:
                    self.log("Socket in exceptional condition")
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
                        # Try to read data
                        try:
                            data = current_socket.recv(4096)
                        except (socket.error, OSError) as e:
                            self.log(f"Socket error during receive: {str(e)}")
                            with self.lock:
                                self.connected = False
                                if self.socket:
                                    try:
                                        self.socket.close()
                                    except:
                                        pass
                                    self.socket = None
                            continue

                        # Process received data
                        if not data:
                            self.log("Connection closed by server (empty receive)")
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
                        try:
                            text_data = data.decode('utf-8')
                            buffer += text_data

                            # Log raw data for debugging (truncated to avoid spamming logs)
                            if len(text_data) > 200:
                                self.log(f"Received data: {text_data[:100]}...{text_data[-100:]}")
                            else:
                                self.log(f"Received data: {text_data}")

                            # Process complete messages
                            while '\n' in buffer:
                                line, buffer = buffer.split('\n', 1)
                                if not line.strip():  # Skip empty lines
                                    continue

                                try:
                                    response = json.loads(line)
                                    msg_type = response.get('type', 'unknown')
                                    self.log(f"Received message type: {msg_type}")

                                    if msg_type == 'ack':
                                        # Update last acknowledgment time
                                        self.last_ack_time = time.time()

                                        # Increment packet count when ACK received
                                        with self.lock:
                                            self.packet_count += 1
                                            self.local_packet_count += 1

                                            # Log packet count periodically to avoid log spam
                                            if self.packet_count - last_packet_count_log >= 10:
                                                self.log(f"Packet count updated to {self.packet_count}")
                                                last_packet_count_log = self.packet_count

                                        # Get protocol counts for each environment if available
                                        env_name = response.get('environment')
                                        if 'protocol_counts' in response:
                                            protocol_counts = response['protocol_counts']

                                            # Update environment-specific counts if environment is specified
                                            if env_name and env_name in self.environment_protocol_counts:
                                                self.environment_protocol_counts[env_name] = protocol_counts
                                                self.log(f"Updated protocol counts for environment: {env_name}")

                                            # Also update global counts
                                            self.protocol_counts = protocol_counts

                                            # Call update callback if registered
                                            if self.protocol_update_callback:
                                                self.protocol_update_callback(self.protocol_counts, env_name)

                                    elif msg_type == 'stats':
                                        self.log("Received stats update from server")
                                        # Update protocol counts from stats message
                                        if 'protocol_counts' in response:
                                            old_counts = self.protocol_counts.copy()
                                            self.protocol_counts = response['protocol_counts']

                                            # If environment-specific counts are included
                                            env_name = response.get('environment')
                                            if env_name and 'protocol_counts' in response:
                                                if env_name not in self.environment_protocol_counts:
                                                    self.environment_protocol_counts[env_name] = {
                                                        'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
                                                        'FTP': 0, 'SMTP': 0, 'Other': 0
                                                    }
                                                self.environment_protocol_counts[env_name] = response['protocol_counts']
                                                self.log(f"Updated stats for environment: {env_name}")

                                            # Calculate total packets from protocol counts
                                            new_total = sum(self.protocol_counts.values())
                                            old_total = sum(old_counts.values())

                                            # Log if there's a significant change
                                            if abs(new_total - old_total) > 5:
                                                self.log(f"Protocol counts updated: {old_total} → {new_total}")

                                            # Update the UI if callback is registered
                                            if self.protocol_update_callback:
                                                self.protocol_update_callback(self.protocol_counts, env_name)

                                        # If stats message contains a packet_count, sync to it
                                        if 'packet_count' in response:
                                            server_count = response.get('packet_count', 0)
                                            with self.lock:
                                                if abs(server_count - self.packet_count) > 5:
                                                    self.log(
                                                        f"Syncing packet count with server: {self.packet_count} → {server_count}")
                                                    self.packet_count = server_count

                                    elif msg_type == 'authenticated':
                                        self.log(f"Authentication confirmed: {response.get('message', '')}")
                                        # Check if server sent back allowed environments
                                        if 'environments' in response:
                                            self.log(
                                                f"Server confirmed access to environments: {response['environments']}")

                                    elif msg_type == 'error':
                                        self.log(f"Error from server: {response.get('message', 'Unknown error')}")

                                    else:
                                        self.log(f"Unhandled message type: {msg_type}")

                                except json.JSONDecodeError as e:
                                    self.log(f"Invalid JSON: {line[:100]}... - Error: {str(e)}")

                        except UnicodeDecodeError:
                            self.log("Received non-UTF8 data, ignoring")
                            buffer = ""  # Clear buffer on decode error

                    except Exception as e:
                        self.log(f"Error processing received data: {str(e)}")
                        traceback.print_exc()
                        time.sleep(0.1)

            except Exception as e:
                self.log(f"Unexpected error in receive loop: {str(e)}")
                traceback.print_exc()
                time.sleep(1)

    def get_packet_count(self):
        """Return the current packet count from local tracking"""
        with self.lock:
            return self.local_packet_count

    def get_protocol_counts(self, environment=None):
        """Return the current protocol counts received from server

        Args:
            environment: Optional environment name to get counts for
        """
        if environment and environment in self.environment_protocol_counts:
            return self.environment_protocol_counts[environment].copy()
        return self.protocol_counts.copy()

    def get_protocol_percentages(self, environment=None):
        """Calculate protocol percentages based on current counts

        Args:
            environment: Optional environment name to get percentages for
        """
        counts = self.get_protocol_counts(environment)

        percentages = {}
        total = sum(counts.values())

        if total > 0:
            for protocol, count in counts.items():
                percentages[protocol] = round((count / total) * 100, 2)
        else:
            # If no packets yet, set all to 0%
            for protocol in counts.keys():
                percentages[protocol] = 0.0

        return percentages

    def get_environments(self):
        """Return the list of environments this client is connected to"""
        return [env.get('env_name') for env in self.environments]

    def dump_debug_info(self):
        """Dump all debug information to the log"""
        self.log("--- CLIENT DEBUG DUMP ---")
        self.log(f"Connected: {self.connected}")
        self.log(f"Running: {self.running}")
        self.log(f"Auth attempts: {self.auth_attempts}")
        self.log(f"Username: {self.username}")

        # Environments (masked passwords)
        env_info = []
        for env in self.environments:
            masked_pw = '*' * len(env.get('env_password', '')) if env.get('env_password') else None
            env_info.append(f"{env.get('env_name')}: {masked_pw}")
        self.log(f"Environments: {env_info}")

        # Protocol counts
        self.log(f"Global protocol counts: {self.protocol_counts}")
        for env_name, counts in self.environment_protocol_counts.items():
            self.log(f"Protocol counts for {env_name}: {counts}")

        # Packet counts
        self.log(f"Packet count: {self.packet_count}")
        self.log(f"Local packet count: {self.local_packet_count}")
        self.log(f"Pending packets: {len(self.pending_packets)}")

        # Thread status
        if self.send_thread:
            self.log(f"Send thread alive: {self.send_thread.is_alive()}")
        if self.recv_thread:
            self.log(f"Receive thread alive: {self.recv_thread.is_alive()}")

        # Queue status
        self.log(f"Send queue size: {self.send_queue.qsize()}")

        self.log("--- END DEBUG DUMP ---")