import threading
import time
import queue
from datetime import datetime
from socket_client import StableSocketClient
from packet_handler import SimplePacketHandler


class StablePacketCaptureBackend:
    def __init__(self, ui=None):
        # UI reference for callbacks
        self.ui = ui

        # Connection settings (will be set by configure method)
        self.capture_interface = None
        self.server_host = 'localhost'
        self.server_port = 9007
        self.environments = []  # List of environment dictionaries
        self.username = None  # Add username field
        self.account_info = None  # Account info

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

        # Protocol counts from server (global and per environment)
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'FTP': 0,
            'SMTP': 0,
            'Other': 0
        }

        # Environment-specific protocol counts
        self.environment_protocol_counts = {}

    def log(self, message):
        """Log a message through the UI"""
        if self.ui:
            # Queue UI updates to avoid blocking
            self.ui_queue.put(("log", message))
        else:
            print(message)

    def configure(self, capture_interface=None, server_host=None, server_port=None,
                  environments=None, username=None, account_info=None,
                  distribution_strategy=None):
        """Configure the backend with settings from UI"""
        if capture_interface is not None:
            self.capture_interface = capture_interface

        if server_host is not None:
            self.server_host = server_host

        if server_port is not None:
            self.server_port = server_port

        if environments is not None:
            if isinstance(environments, list):
                self.environments = environments
            else:
                # Single environment support for backward compatibility
                env_name = getattr(environments, 'env_name', environments)
                env_password = getattr(environments, 'env_password', None)
                self.environments = [{'env_name': env_name, 'env_password': env_password}]

            # Initialize environment protocol counts
            for env in self.environments:
                env_name = env.get('env_name')
                if env_name and env_name not in self.environment_protocol_counts:
                    self.environment_protocol_counts[env_name] = {
                        'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SMTP': 0, 'Other': 0
                    }

        if username is not None:
            self.username = username

        if account_info is not None:
            self.account_info = account_info

        # Log the configuration
        self.log(f"Backend configured: host={self.server_host}, port={self.server_port}")
        self.log(f"Username: {self.username}, Environments: {[env.get('env_name') for env in self.environments]}")
        if self.account_info:
            self.log(f"Account info: {self.account_info}")
        self.log("Packets will be sent to all environments automatically")

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
        env_names = [env.get('env_name') for env in self.environments]
        self.log(f"Setting auth for environments: {env_names} as user: {self.username}")

        # Pass all auth data to the client including account_info
        self.client.set_auth(self.environments, self.username, self.account_info)

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

    def update_protocol_counts(self, protocol_counts, environment=None):
        """Update protocol counts received from server

        Args:
            protocol_counts: Dictionary of protocol counts
            environment: Optional environment name these counts belong to
        """
        # Update global counts
        self.protocol_counts = protocol_counts

        # If environment is specified, update environment-specific counts
        if environment and environment in self.environment_protocol_counts:
            self.environment_protocol_counts[environment] = protocol_counts

        # Update UI with protocol counts
        if self.ui:
            self.ui_queue.put(("protocol_counts", protocol_counts, environment))

    def process_packet(self, packet_dict):
        """Process a packet from the handler and send it to the server"""
        if not self.running:
            return

        try:
            # Get all available environment names - always send to all environments
            all_envs = [env.get('env_name') for env in self.environments]

            if not all_envs:
                self.log("No environments available to send packet")
                return

            # Add username if available
            if self.username:
                packet_dict['username'] = self.username

            # Send to server with all environments
            if self.client:
                self.client.send_packet(packet_dict)

            # Update UI (through queue)
            if self.ui:
                self.ui_queue.put(("packet", packet_dict, all_envs))

        except Exception as e:
            self.log(f"Error processing packet: {str(e)}")

    def _process_ui_updates(self):
        """Process UI updates from queue to avoid blocking"""
        while self.running:
            try:
                # Get update with timeout
                try:
                    update = self.ui_queue.get(timeout=0.5)
                    if len(update) == 2:
                        update_type, data = update
                        additional = None
                    else:
                        update_type, data, additional = update
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
                        if hasattr(self.ui, 'process_packet_with_environments'):
                            # Use the new method that supports environments
                            self.ui.process_packet_with_environments(data, additional)
                        else:
                            # Fallback to the old method
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
                        if hasattr(self.ui, 'update_protocol_counts_for_env'):
                            # Use the new method that supports environments
                            self.ui.update_protocol_counts_for_env(data, additional)
                        elif hasattr(self.ui, 'update_protocol_counts'):
                            # Fallback to the old method
                            self.ui.update_protocol_counts(data)
                        else:
                            print("UI doesn't have protocol count update methods")
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
                        # Get global protocol counts
                        protocol_counts = self.client.get_protocol_counts()
                        self.protocol_counts = protocol_counts

                        # Update UI with protocol counts
                        if self.ui:
                            self.ui_queue.put(("protocol_counts", protocol_counts, None))

                        # Get environment-specific counts
                        for env_name in self.environment_protocol_counts.keys():
                            env_counts = self.client.get_protocol_counts(env_name)
                            if env_counts:
                                self.environment_protocol_counts[env_name] = env_counts
                                # Update UI with environment-specific counts
                                if self.ui:
                                    self.ui_queue.put(("protocol_counts", env_counts, env_name))

                # Queue UI updates
                self.ui_queue.put(("packet_count", self.packet_count))
                self.ui_queue.put(("connection", self.connected))

                time.sleep(1)
            except Exception as e:
                self.log(f"Error updating stats: {str(e)}")
                time.sleep(1)

    def get_environments(self):
        """Return the list of configured environments"""
        return [env.get('env_name') for env in self.environments]