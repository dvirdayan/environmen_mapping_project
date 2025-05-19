import threading
import time
import queue
from datetime import datetime
from socket_client import StableSocketClient
from packet_handler import SimplePacketHandler


class StablePacketCaptureBackend:
    def __init__(self, ui=None):
        # Existing initialization code...

        # UI reference for callbacks
        self.ui = ui

        # Connection settings (will be set by configure method)
        self.capture_interface = None
        self.server_host = 'localhost'
        self.server_port = 9007
        self.env_name = None
        self.env_password = None
        self.username = None  # Add username field

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
                  env_name=None, env_password=None, username=None):
        """Configure the backend with settings from UI"""
        self.capture_interface = capture_interface

        if server_host:
            self.server_host = server_host

        if server_port:
            self.server_port = server_port

        if env_name:
            self.env_name = env_name

        if env_password:
            self.env_password = env_password

        if username:
            self.username = username

        # Log the configuration
        self.log(f"Backend configured: host={self.server_host}, port={self.server_port}")
        self.log(f"Username: {self.username}, Environment: {self.env_name}")

    def start(self):
        """Start packet capture"""
        if self.running:
            return

        self.running = True

        # Start UI update thread
        self.ui_update_thread = threading.Thread(target=self._process_ui_updates)
        self.ui_update_thread.daemon = True
        self.ui_update_thread.start()

        # Create client with explicit logging of credentials
        self.client = StableSocketClient(self.server_host, self.server_port, self.log)

        # Log the credentials being used (obscure password)
        self.log(
            f"Setting auth: env_name={self.env_name}, username={self.username}, password={'*****' if self.env_password else 'None'}")

        # Pass all auth data to the client
        self.client.set_auth(self.env_name, self.env_password, self.username)

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

            # Add username if available
            if self.username:
                packet_dict['username'] = self.username

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
                    # Get the packet count directly from client
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