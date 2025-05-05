import threading
import time
import queue
import socket
import json
import select
import traceback
from datetime import datetime


# Create a simple packet processing class that doesn't rely on pyshark initially
class SimplePacketHandler:
    def __init__(self, interface, callback=None):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.thread = None
        self.packet_queue = queue.Queue(maxsize=1000)  # Limit queue size
        self.processing_thread = None

    def start(self):
        """Start a dummy packet generation for testing connection"""
        self.running = True
        self.thread = threading.Thread(target=self._generate_test_packets)
        self.thread.daemon = True
        self.thread.start()

        # Start processing thread
        self.processing_thread = threading.Thread(target=self._process_packets)
        self.processing_thread.daemon = True
        self.processing_thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        if self.processing_thread:
            self.processing_thread.join(timeout=1.0)

    def _generate_test_packets(self):
        """Generate simple test packets to verify connection stability"""
        counter = 0
        while self.running:
            try:
                counter += 1
                # Create a simple test packet
                packet = {
                    'timestamp': datetime.now().isoformat(),
                    'protocol': 'TCP',
                    'highest_layer': 'TCP',
                    'packet_length': 64,
                    'source_ip': '192.168.0.1',
                    'destination_ip': '192.168.0.2',
                    'source_port': 12345,
                    'destination_port': 80,
                    'test_counter': counter
                }

                # Queue the packet instead of immediately processing
                try:
                    # Use put_nowait with a timeout to avoid blocking
                    self.packet_queue.put(packet, timeout=0.1)
                except queue.Full:
                    # Skip packet if queue is full
                    pass

                # Sleep to avoid flooding
                time.sleep(0.5)
            except Exception as e:
                print(f"Error generating packet: {str(e)}")
                time.sleep(1)

    def _process_packets(self):
        """Process packets from the queue"""
        while self.running:
            try:
                # Get packet with timeout
                try:
                    packet = self.packet_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                # Process packet
                if self.callback:
                    try:
                        self.callback(packet)
                    except Exception as e:
                        print(f"Error in packet callback: {str(e)}")
            except Exception as e:
                print(f"Error processing packet: {str(e)}")
                time.sleep(0.5)


class StableSocketClient:
    def __init__(self, host, port, logger=None):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.running = False  # Add this attribute
        self.logger = logger
        self.reconnect_delay = 2.0
        self.send_thread = None
        self.recv_thread = None
        self.last_ack_time = 0
        self.packet_count = 0
        self.auth_data = None
        self.env_name = None  # Add this attribute
        self.lock = threading.Lock()  # Add a lock for thread safety
        self.send_queue = queue.Queue()

        # Add protocol counts dict that will be updated from server
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'FTP': 0,
            'SMTP': 0,
            'Other': 0
        }
        # Add callback for protocol updates
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

    def set_auth(self, env_name, env_password):
        """Set authentication data"""
        self.env_name = env_name  # Set the env_name here
        if env_name and env_password:
            self.auth_data = {
                'type': 'auth',
                'env_name': env_name,
                'env_password': env_password
            }
        else:
            self.auth_data = None

    def set_protocol_update_callback(self, callback):
        """Set callback function to be called when protocol counts are updated"""
        self.protocol_update_callback = callback

    def log(self, message):
        if self.logger:
            self.logger(message)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    # In your client code, modify the connect method:

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

            # Handle authentication
            if self.auth_data:
                try:
                    # Ensure auth_data format exactly matches what server expects
                    auth_message = json.dumps(self.auth_data) + '\n'
                    self.log(f"Sending auth: {auth_message.strip()}")
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

                            # Check if we have a complete response (ending with newline)
                            if b'\n' in response_data:
                                break
                        except socket.timeout:
                            break

                    response_text = response_data.decode('utf-8', errors='ignore').strip()
                    self.log(f"Auth response received ({len(response_text)} bytes): {response_text[:100]}...")

                    # Process response even if it's not JSON
                    authenticated = False

                    if "authenticated" in response_text or "success" in response_text:
                        authenticated = True
                        self.log("Authentication successful via text matching")
                    else:
                        # Try JSON parsing
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
            else:
                self.log("No authentication data to send")

            # Set to non-blocking for normal operation
            self.socket.setblocking(False)
            self.connected = True
            self.log(f"Successfully connected to server {self.host}:{self.port}")

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
        """Queue a packet for sending"""
        if not self.running:
            return False

        try:
            # Make sure we're sending a proper packet structure
            if isinstance(packet_dict, dict):
                # Add environment name if it's not already there
                if self.env_name and 'env_name' not in packet_dict:
                    packet_dict['env_name'] = self.env_name

                serialized = json.dumps(packet_dict) + '\n'  # Ensure we have a newline
                self.send_queue.put(serialized)
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

                            # Process complete messages
                            while '\n' in buffer:
                                line, buffer = buffer.split('\n', 1)
                                if line.strip():  # Skip empty lines
                                    try:
                                        response = json.loads(line)
                                        # Concise logging
                                        msg_type = response.get('type', 'unknown')
                                        self.log(f"Received: {msg_type}")

                                        if msg_type == 'ack':
                                            self.last_ack_time = time.time()
                                            self.packet_count += 1

                                            # Get protocol counts from the server if available
                                            if 'protocol_counts' in response:
                                                # Update our local protocol counts
                                                self.protocol_counts = response['protocol_counts']

                                                # Call the callback if registered
                                                if self.protocol_update_callback:
                                                    self.protocol_update_callback(self.protocol_counts)

                                        elif msg_type == 'stats':
                                            # Update protocol counts from stats message
                                            if 'protocol_counts' in response:
                                                self.protocol_counts = response['protocol_counts']

                                                # Call the callback if registered
                                                if self.protocol_update_callback:
                                                    self.protocol_update_callback(self.protocol_counts)

                                            self.log(f"Updated protocol counts from server")
                                    except json.JSONDecodeError:
                                        self.log(f"Invalid JSON: {line[:30]}...")
                        except UnicodeDecodeError:
                            self.log("Received non-UTF8 data, ignoring")
                            buffer = ""  # Clear buffer on decode error
                    except Exception as e:
                        self.log(f"Error processing received data: {str(e)}")
                        time.sleep(0.1)
            except Exception as e:
                self.log(f"Unexpected error in receive loop: {str(e)}")
                traceback.print_exc()
                time.sleep(1)

    def get_protocol_counts(self):
        """Return the current protocol counts received from server"""
        return self.protocol_counts.copy()


class StablePacketCaptureBackend:
    def __init__(self, ui=None):
        # Existing initialization code...

        # UI reference for callbacks
        self.ui = ui

        # Connection settings (will be set by configure method)
        self.capture_interface = None
        self.server_host = 'localhost'
        self.server_port = 65432
        self.env_name = None
        self.env_password = None

        # State tracking
        self.packet_count = 0
        self.running = False
        self.connected = False

        # Threads
        self.capture_thread = None
        self.stats_thread = None

        # Client
        self.client = None

        # Packet handler
        self.packet_handler = None

        # Queue for UI updates
        self.ui_queue = queue.Queue()
        self.ui_update_thread = None

        # Protocol counts from server
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'FTP': 0,
            'SMTP': 0,
            'Other': 0
        }

    def log(self, message):
        """Log a message through the UI"""
        if self.ui:
            # Queue UI updates to avoid blocking
            self.ui_queue.put(("log", message))
        else:
            print(message)

    def configure(self, capture_interface=None, server_host=None, server_port=None,
                  env_name=None, env_password=None):
        """Configure the backend with settings from UI"""
        self.capture_interface = capture_interface

        if server_host:
            self.server_host = server_host

        if server_port:
            self.server_port = server_port

        self.env_name = env_name
        self.env_password = env_password

    def start(self):
        """Start packet capture"""
        if self.running:
            return

        self.running = True

        # Start UI update thread
        self.ui_update_thread = threading.Thread(target=self._process_ui_updates)
        self.ui_update_thread.daemon = True
        self.ui_update_thread.start()

        # Create client
        self.client = StableSocketClient(self.server_host, self.server_port, self.log)
        self.client.set_auth(self.env_name, self.env_password)

        # Register protocol update callback
        self.client.set_protocol_update_callback(self.update_protocol_counts)

        # Create packet handler
        self.packet_handler = SimplePacketHandler(self.capture_interface, self.process_packet)

        # Start the client
        self.client.start()

        # Start the packet handler
        self.packet_handler.start()

        # Start stats thread
        self.stats_thread = threading.Thread(target=self.update_stats)
        self.stats_thread.daemon = True
        self.stats_thread.start()

        # Start UI packet processing if UI exists
        if self.ui:
            self.ui.start_processing_packets()

    def stop(self):
        """Stop packet capture"""
        self.running = False

        if self.packet_handler:
            self.packet_handler.stop()
            self.packet_handler = None

        if self.client:
            self.client.stop()
            self.client = None

    def update_protocol_counts(self, protocol_counts):
        """Update protocol counts received from server"""
        self.protocol_counts = protocol_counts

        # Update UI with protocol counts
        if self.ui:
            self.ui_queue.put(("protocol_counts", protocol_counts))

    def process_packet(self, packet_dict):
        """Process a packet from the handler and send it to the server"""
        if not self.running:
            return

        try:
            # Add environment name if available
            if self.env_name:
                packet_dict['env_name'] = self.env_name

            # Send to server
            if self.client:
                self.client.send_packet(packet_dict)

            # Update UI (through queue)
            if self.ui:
                self.ui_queue.put(("packet", packet_dict))
        except Exception as e:
            self.log(f"Error processing packet: {str(e)}")

    def _process_ui_updates(self):
        """Process UI updates from queue to avoid blocking"""
        while self.running:
            try:
                # Get update with timeout
                try:
                    update_type, data = self.ui_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                # Process update
                if update_type == "log" and self.ui:
                    try:
                        self.ui.log_message(data)
                    except Exception as e:
                        print(f"Error updating UI log: {str(e)}")

                elif update_type == "packet" and self.ui:
                    try:
                        self.ui.process_packet(data)
                    except Exception as e:
                        print(f"Error updating UI with packet: {str(e)}")

                elif update_type == "packet_count" and self.ui:
                    try:
                        self.ui.update_packet_count(data)
                    except Exception as e:
                        print(f"Error updating packet count: {str(e)}")

                elif update_type == "connection" and self.ui:
                    try:
                        self.ui.update_connection_status(data)
                    except Exception as e:
                        print(f"Error updating connection status: {str(e)}")

                elif update_type == "protocol_counts" and self.ui:
                    try:
                        # Make sure UI has the update_protocol_counts method
                        if hasattr(self.ui, 'update_protocol_counts'):
                            self.ui.update_protocol_counts(data)
                        else:
                            print("UI doesn't have update_protocol_counts method")
                    except Exception as e:
                        print(f"Error updating protocol counts: {str(e)}")

            except Exception as e:
                print(f"Error processing UI update: {str(e)}")
                time.sleep(0.5)

    def update_stats(self):
        """Update statistics periodically"""
        while self.running:
            try:
                if self.client:
                    self.packet_count = self.client.packet_count
                    self.connected = self.client.connected

                    # Get protocol counts from client
                    if hasattr(self.client, 'get_protocol_counts'):
                        protocol_counts = self.client.get_protocol_counts()
                        self.protocol_counts = protocol_counts

                        # Update UI with protocol counts
                        if self.ui:
                            self.ui_queue.put(("protocol_counts", protocol_counts))

                # Queue UI updates
                self.ui_queue.put(("packet_count", self.packet_count))
                self.ui_queue.put(("connection", self.connected))

                time.sleep(1)
            except Exception as e:
                self.log(f"Error updating stats: {str(e)}")
                time.sleep(1)


# After verifying this works, we can add real packet capture
# This function would be called to upgrade from test packets to real capture
def upgrade_to_real_capture(backend):
    """Upgrade from test packets to real capture once connection is stable"""
    if backend.packet_handler:
        backend.packet_handler.stop()

    # Now implement real packet capture using either PyShark or Scapy
    # For example, using Scapy:
    try:
        from scapy.all import sniff

        class ScapyPacketHandler:
            def __init__(self, interface, callback=None):
                self.interface = interface
                self.callback = callback
                self.running = False
                self.thread = None

            def start(self):
                self.running = True
                self.thread = threading.Thread(target=self._capture_packets)
                self.thread.daemon = True
                self.thread.start()

            def stop(self):
                self.running = False
                if self.thread:
                    self.thread.join(timeout=1.0)

            def _capture_packets(self):
                def packet_handler(packet):
                    if not self.running:
                        return

                    # Convert Scapy packet to dict
                    packet_dict = self._packet_to_dict(packet)

                    if self.callback:
                        self.callback(packet_dict)

                backend.log(f"Starting real packet capture on interface {self.interface}")
                try:
                    sniff(iface=self.interface, prn=packet_handler, store=0, stop_filter=lambda _: not self.running)
                except Exception as e:
                    backend.log(f"Capture error: {e}")

            def _packet_to_dict(self, packet):
                """Convert a Scapy packet to dictionary"""
                packet_dict = {
                    'timestamp': datetime.now().isoformat(),
                    'protocol': 'UNKNOWN',
                    'highest_layer': 'UNKNOWN',
                    'packet_length': len(packet),
                    'source_ip': None,
                    'destination_ip': None,
                    'source_port': None,
                    'destination_port': None
                }

                # Extract IP info
                if 'IP' in packet:
                    packet_dict['source_ip'] = packet['IP'].src
                    packet_dict['destination_ip'] = packet['IP'].dst
                    packet_dict['protocol'] = 'IP'

                # Extract TCP/UDP info
                if 'TCP' in packet:
                    packet_dict['source_port'] = packet['TCP'].sport
                    packet_dict['destination_port'] = packet['TCP'].dport
                    packet_dict['protocol'] = 'TCP'
                    packet_dict['highest_layer'] = 'TCP'
                elif 'UDP' in packet:
                    packet_dict['source_port'] = packet['UDP'].sport
                    packet_dict['destination_port'] = packet['UDP'].dport
                    packet_dict['protocol'] = 'UDP'
                    packet_dict['highest_layer'] = 'UDP'

                # Check for higher-level protocols
                if 'HTTP' in packet:
                    packet_dict['highest_layer'] = 'HTTP'
                elif 'DNS' in packet:
                    packet_dict['highest_layer'] = 'DNS'

                return packet_dict

        # Create and start the Scapy handler
        backend.packet_handler = ScapyPacketHandler(backend.capture_interface, backend.process_packet)
        backend.packet_handler.start()

    except ImportError:
        backend.log("Scapy not available. Using dummy packets for testing.")
        # Continue with test packets if Scapy isn't available