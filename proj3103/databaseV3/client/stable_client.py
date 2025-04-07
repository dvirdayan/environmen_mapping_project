import threading
import time
import queue
import socket
import json
import select
from datetime import datetime


# Create a simple packet processing class that doesn't rely on pyshark initially
class SimplePacketHandler:
    def __init__(self, interface, callback=None):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.thread = None

    def start(self):
        """Start a dummy packet generation for testing connection"""
        self.running = True
        self.thread = threading.Thread(target=self._generate_test_packets)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _generate_test_packets(self):
        """Generate simple test packets to verify connection stability"""
        counter = 0
        while self.running:
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

            if self.callback:
                self.callback(packet)

            # Sleep to avoid flooding
            time.sleep(0.2)


class StableSocketClient:
    def __init__(self, host, port, logger=None):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.running = False
        self.send_queue = queue.Queue()
        self.logger = logger
        self.send_thread = None
        self.recv_thread = None
        self.reconnect_delay = 2.0
        self.last_ack_time = 0
        self.packet_count = 0
        self.auth_data = None

    def set_auth(self, env_name, env_password):
        """Set authentication data"""
        if env_name and env_password:
            self.auth_data = {
                'type': 'auth',
                'env_name': env_name,
                'env_password': env_password
            }
        else:
            self.auth_data = None

    def log(self, message):
        """Log a message"""
        if self.logger:
            self.logger(message)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def connect(self, host, port, env_name=None, env_password=None, account_info=None):
        self.disconnect()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)

        try:
            self.sock.connect((host, port))
            self.running = True
            self.connected = True
            print(f"Connected to server {host}:{port}")

            # ✅ Send authentication message immediately after connecting
            auth_payload = {
                "type": "auth",
                "env_name": env_name or "default",
                "env_password": env_password or "default_password",
                "account_info": account_info or "anonymous"
            }
            self.sock.sendall(json.dumps(auth_payload).encode('utf-8'))

            self.listener_thread = threading.Thread(target=self.listen_to_server, daemon=True)
            self.listener_thread.start()
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            self.disconnect()
            return False

    def start(self):
        """Start client operation"""
        if self.running:
            return

        self.running = True

        # Start send thread
        self.send_thread = threading.Thread(target=self._send_loop)
        self.send_thread.daemon = True
        self.send_thread.start()

        # Start receive thread
        self.recv_thread = threading.Thread(target=self._recv_loop)
        self.recv_thread.daemon = True
        self.recv_thread.start()

    def stop(self):
        """Stop client operation"""
        self.running = False

        # Clear queue
        while not self.send_queue.empty():
            try:
                self.send_queue.get_nowait()
            except queue.Empty:
                break

        if self.socket:
            try:
                self.socket.close()
            except:
                pass

        self.connected = False

        # Wait for threads
        if self.send_thread and self.send_thread.is_alive():
            self.send_thread.join(timeout=1.0)

        if self.recv_thread and self.recv_thread.is_alive():
            self.recv_thread.join(timeout=1.0)

    def send_packet(self, packet_dict):
        """Queue a packet for sending"""
        if not self.running:
            return False

        try:
            serialized = json.dumps(packet_dict) + '\n'
            self.send_queue.put(serialized)
            return True
        except Exception as e:
            self.log(f"Error queueing packet: {e}")
            return False

    def _send_loop(self):
        """Background thread for sending packets"""
        reconnect_time = 0

        while self.running:
            try:
                if not self.send_queue.empty():
                    if not self.send_queue.empty():
                        data = self.send_queue.get()

                        if data is None:
                            self.log("Warning: Got None from send_queue")
                            continue

                        # Try to parse JSON if it's a string
                        if isinstance(data, str):
                            try:
                                data = json.loads(data)
                            except json.JSONDecodeError:
                                self.log(f"Invalid JSON in queue: {data}")
                                continue

                        if not isinstance(data, dict):
                            self.log(f"Unexpected data type in queue (not dict): {type(data)} - {data}")
                            continue

                        msg_type = data.get("type")
                        if msg_type == "packet":
                            self.send_packet(data.get("packet"))
                        elif msg_type == "auth":
                            self.send_auth(data)
                        else:
                            self.log(f"Unknown message type: {msg_type}")

                        # Sleep to avoid busy waiting
                time.sleep(0.01)
            except Exception as e:
                print(f"Error in send loop: {e}")
            try:
                # Check connection status
                # Check connection status
                if not self.connected:
                    current_time = time.time()
                    if current_time - reconnect_time >= self.reconnect_delay:
                        reconnect_time = current_time
                        self.log(f"Not connected. Attempting to connect to {self.host}:{self.port}")

                        if not self.auth_data:
                            self.log("auth_data is None — skipping connect()")
                            time.sleep(0.5)
                            continue

                        self.connect(
                            self.host,
                            self.port,
                            self.auth_data.get('env_name'),
                            self.auth_data.get('env_password'),
                            self.auth_data.get('account_info')
                        )
                    time.sleep(0.5)
                    continue

                # Get next packet from queue with timeout
                try:
                    data = self.send_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                if data is None:
                    continue
                if not isinstance(data, str):
                    self.log(f"Expected string in send queue, got {type(data)}: {data}")
                    continue
                if not data.endswith('\n'):
                    data += '\n'
                # Send the packet
                try:
                    if self.socket:
                        self.socket.sendall(data.encode('utf-8'))
                    else:
                        raise socket.error("Socket is None")
                except Exception as e:
                    self.log(f"Send error: {e}")
                    self.connected = False
                    if self.socket:
                        try:
                            self.socket.close()
                        except:
                            pass
                    self.socket = None

                # Check for ack timeout
                current_time = time.time()
                if current_time - self.last_ack_time > 10.0 and self.packet_count > 0:
                    self.log("No acknowledgment received for 10 seconds, forcing reconnection")
                    self.connected = False
                    if self.socket:
                        try:
                            self.socket.close()
                        except:
                            pass
                    self.socket = None

            except Exception as e:
                self.log(f"Error in send loop: {e}")
                time.sleep(0.5)

    def _recv_loop(self):
        """Background thread for receiving responses"""
        buffer = ""

        while self.running:
            if not self.connected or not self.socket:
                time.sleep(0.5)
                continue

            try:
                # Check for incoming data
                readable, _, _ = select.select([self.socket], [], [], 0.5)

                if self.socket in readable:
                    try:
                        data = self.socket.recv(4096).decode('utf-8')

                        if not data:
                            self.log("Connection closed by server (empty receive)")
                            self.connected = False
                            self.socket.close()
                            self.socket = None
                            continue

                        buffer += data

                        # Process complete messages
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)

                            # Parse the server's response
                            if '|' in line:
                                ack_parts = line.strip().split('|')
                                if len(ack_parts) == 2:
                                    try:
                                        self.packet_count = int(ack_parts[1])
                                        self.last_ack_time = time.time()
                                    except ValueError:
                                        self.log(f"Invalid packet count: {ack_parts[1]}")
                            else:
                                # Just log other responses
                                self.log(f"Server: {line}")

                    except socket.error as e:
                        self.log(f"Receive error: {e}")
                        self.connected = False
                        self.socket.close()
                        self.socket = None

            except Exception as e:
                self.log(f"Error in receive loop: {e}")
                time.sleep(0.5)


# Adapter class to use our stable client with the existing backend
class StablePacketCaptureBackend:
    def __init__(self, ui=None):
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

    def log(self, message):
        """Log a message through the UI"""
        if self.ui:
            self.ui.log_message(message)
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

        # Create client
        self.client = StableSocketClient(self.server_host, self.server_port, self.log)
        self.client.set_auth(self.env_name, self.env_password)

        # Create packet handler - first start with test packets
        # Later we'll replace this with real packet capture
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

        if self.client:
            self.client.stop()

    def process_packet(self, packet_dict):
        """Process a packet from the handler and send it to the server"""
        if not self.running:
            return

        # Add environment name if available
        if self.env_name:
            packet_dict['env_name'] = self.env_name

        # Send to server
        if self.client:
            self.client.send_packet(packet_dict)

        # Update UI
        if self.ui:
            self.ui.process_packet(packet_dict)

    def update_stats(self):
        """Update statistics periodically"""
        while self.running:
            if self.client:
                self.packet_count = self.client.packet_count
                self.connected = self.client.connected

            if self.ui:
                self.ui.update_packet_count(self.packet_count)
                self.ui.update_connection_status(self.connected)

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

