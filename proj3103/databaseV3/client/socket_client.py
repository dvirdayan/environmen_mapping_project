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
    def __init__(self, host, port, logger=None):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.running = False
        self.logger = logger
        self.reconnect_delay = 2.0
        self.send_thread = None
        self.recv_thread = None
        self.last_ack_time = 0
        self.packet_count = 0
        self.local_packet_count = 0
        self.auth_data = None
        self.env_name = None
        self.env_password = None
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
        self.protocol_update_callback = None

    def start(self):
        """Start the client."""
        if self.running:  # Check if already running
            if self.logger:
                self.logger.warning("Client is already running.")
            return
        self.running = True
        # Add logic to start threads or other operations

        # Start send thread
        self.send_thread = threading.Thread(target=self._send_loop)
        self.send_thread.daemon = True
        self.send_thread.start()

        # Start receive thread
        self.recv_thread = threading.Thread(target=self._recv_loop)
        self.recv_thread.daemon = True
        self.recv_thread.start()

    def set_auth(self, env_name, env_password, username=None, account_info=None):
        """Set authentication data with account information"""
        self.env_name = env_name
        self.username = username
        self.env_password = env_password

        # Make sure we always have valid auth data
        # Fallback to defaults if any values are missing
        if not env_name:
            env_name = "default"
        if not env_password:
            env_password = "default_password"

        # Always create auth data, even with defaults
        self.auth_data = {
            'type': 'auth',
            'env_name': env_name,
            'env_password': env_password
        }

        # Add username to auth data if provided
        if username:
            self.auth_data['username'] = username
            self.log(f"Auth data set with username: {username}")
        else:
            self.log("Auth data set without username")

        # Add account_info to auth data if provided
        if account_info:
            self.auth_data['account_info'] = account_info
            self.log(f"Auth data includes account information")

    def set_protocol_update_callback(self, callback):
        """Set callback function to be called when protocol counts are updated"""
        self.protocol_update_callback = callback

    def log(self, message):
        if self.logger:
            self.logger(message)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

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

            self.log(f"Attempting to connect to {self.host}:{self.port}")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10.0)  # Set longer timeout for initial connection
            self.socket.connect((self.host, self.port))
            self.log(f"Socket connected to {self.host}:{self.port}")

            # Add a small delay to ensure the server is ready for authentication
            time.sleep(0.2)

            # Handle authentication - always send auth data
            if not self.auth_data:
                # Create minimal auth data if none exists
                self.auth_data = {
                    'type': 'auth',
                    'env_name': self.env_name or "default",
                    'env_password': self.env_password or "default_password"
                }
                if self.username:
                    self.auth_data['username'] = self.username

            try:
                # Log what we're sending (mask password)
                log_data = self.auth_data.copy()
                if 'env_password' in log_data:
                    log_data['env_password'] = '******'
                self.log(f"Sending auth data: {log_data}")

                # Send auth data
                auth_message = json.dumps(self.auth_data) + '\n'
                self.socket.sendall(auth_message.encode('utf-8'))

                # Wait for response with timeout
                response_data = b""
                timeout_time = time.time() + 5.0  # 5 second timeout

                while time.time() < timeout_time:
                    try:
                        chunk = self.socket.recv(1024)
                        if not chunk:
                            break
                        response_data += chunk

                        # Check if we have a complete response
                        if b'\n' in response_data:
                            break
                    except socket.timeout:
                        break

                response_text = response_data.decode('utf-8', errors='ignore').strip()
                self.log(f"Auth response received ({len(response_text)} bytes): {response_text[:100]}...")

                # Process response
                authenticated = False

                if "authenticated" in response_text or "success" in response_text:
                    authenticated = True
                    self.log("Authentication successful via text matching")
                else:
                    # Try JSON parsing for each line
                    for line in response_text.split('\n'):
                        if not line.strip():
                            continue
                        try:
                            response = json.loads(line)
                            if response.get('status') == 'authenticated':
                                authenticated = True
                                self.log("Authentication successful via JSON")
                                break
                        except:
                            pass

                if not authenticated:
                    self.log("Authentication failed")
                    self.socket.close()
                    self.socket = None
                    return False

            except socket.timeout:
                self.log("Authentication response timeout")
                self.socket.close()
                self.socket = None
                return False
            except Exception as e:
                self.log(f"Authentication error: {str(e)}")
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

            # Wait a short time before sending packets to ensure everything is ready
            time.sleep(0.5)
            return True

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
                self.logger.error(f"Send error: {e}")
            self.connected = False
            self.connect()  # Reconnect and retry

    def receive(self):
        """Receive data from the server."""
        try:
            return self.socket.recv(1024)
        except socket.error as e:
            if self.logger:
                self.logger.error(f"Receive error: {e}")
            self.connected = False
            self.connect()  # Reconnect and retry

    def stop(self):
        """Stop the client."""
        if not self.running:  # Check if already stopped
            if self.logger:
                self.logger.warning("Client is not running.")
            return
        self.running = False
        # Add logic to stop threads or other operations

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
                    self.socket.close()
                except:
                    pass
                self.socket = None
            self.connected = False

        # Wait for threads
        if self.send_thread and self.send_thread.is_alive():
            self.send_thread.join(timeout=1.0)

        if self.recv_thread and self.recv_thread.is_alive():
            self.recv_thread.join(timeout=1.0)

        self.log("Client stopped")

    def send_packet(self, packet_dict):
        if not self.running:
            return False

        try:
            if isinstance(packet_dict, dict):
                if self.env_name and 'env_name' not in packet_dict:
                    packet_dict['env_name'] = self.env_name

                # Add username to each packet
                if self.username and 'username' not in packet_dict:
                    packet_dict['username'] = self.username

                # Always ensure packet has a unique ID
                if 'packet_id' not in packet_dict:
                    packet_dict['packet_id'] = str(uuid.uuid4())

                # Add to pending packets set with lock
                with self.pending_packets_lock:
                    packet_id = packet_dict['packet_id']
                    self.pending_packets.add(packet_id)

                serialized = json.dumps(packet_dict) + '\n'
                self.send_queue.put(serialized)

                self.log(f"[CLIENT] Queued packet {packet_dict['packet_id']}")
                return True
            else:
                self.log(f"Error: Expected dict for packet, got {type(packet_dict)}")
                return False
        except Exception as e:
            self.log(f"Error queueing packet: {str(e)}")
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
                        if self.connect():  # Try to connect with proper error handling
                            # Reset heartbeat timer after successful reconnection
                            last_heartbeat_time = current_time
                    time.sleep(0.5)
                    continue

                # Send heartbeat every 30 seconds if no other activity
                if current_time - last_heartbeat_time > 30:
                    try:
                        heartbeat = {
                            'type': 'heartbeat',
                            'timestamp': datetime.now().isoformat()
                        }

                        # Add environment name to heartbeat if available
                        if self.env_name:
                            heartbeat['env_name'] = self.env_name

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
                            if self.env_name and 'env_name' not in data:
                                data['env_name'] = self.env_name
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
                # Check connection
                with self.lock:
                    if not self.connected or self.socket is None:
                        time.sleep(0.5)
                        continue

                    # Make a local copy of socket to avoid race conditions
                    current_socket = self.socket

                # Safely check for data without holding the lock
                try:
                    readable, _, exceptional = select.select([current_socket], [], [current_socket], 0.5)
                except (select.error, ValueError, TypeError):
                    with self.lock:
                        self.connected = False
                        if self.socket:
                            try:
                                self.socket.close()
                            except:
                                pass
                            self.socket = None
                    self.log("Socket selection error, connection marked as closed")
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
                        with self.lock:
                            if not self.connected or self.socket is None:
                                continue

                            try:
                                data = self.socket.recv(4096)
                            except (socket.error, OSError) as e:
                                self.log(f"Socket error during receive: {str(e)}")
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

                                        # Get protocol counts if available
                                        if 'protocol_counts' in response:
                                            self.protocol_counts = response['protocol_counts']
                                            if self.protocol_update_callback:
                                                self.protocol_update_callback(self.protocol_counts)

                                    elif msg_type == 'stats':
                                        self.log("Received stats update from server")
                                        # Update protocol counts from stats message
                                        if 'protocol_counts' in response:
                                            old_counts = self.protocol_counts.copy()
                                            self.protocol_counts = response['protocol_counts']

                                            # Calculate total packets from protocol counts
                                            new_total = sum(self.protocol_counts.values())
                                            old_total = sum(old_counts.values())

                                            # Log if there's a significant change
                                            if abs(new_total - old_total) > 5:
                                                self.log(f"Protocol counts updated: {old_total} → {new_total}")

                                            # Update the UI if callback is registered
                                            if self.protocol_update_callback:
                                                self.protocol_update_callback(self.protocol_counts)

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

                                    elif msg_type == 'error':
                                        self.log(f"Error from server: {response.get('message', 'Unknown error')}")

                                    else:
                                        self.log(f"Unhandled message type: {msg_type}")

                                except json.JSONDecodeError as e:
                                    self.log(f"Invalid JSON: {line[:30]}... - Error: {str(e)}")

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

    def get_protocol_counts(self):
        """Return the current protocol counts received from server"""
        return self.protocol_counts.copy()

    def get_protocol_percentages(self):
        """Calculate protocol percentages based on current counts"""
        percentages = {}
        total = sum(self.protocol_counts.values())

        if total > 0:
            for protocol, count in self.protocol_counts.items():
                percentages[protocol] = round((count / total) * 100, 2)
        else:
            # If no packets yet, set all to 0%
            for protocol in self.protocol_counts.keys():
                percentages[protocol] = 0.0

        return percentages