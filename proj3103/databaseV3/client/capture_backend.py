import threading
import time
import queue
from datetime import datetime
from socket_client import StableSocketClient
from packet_handler import RealPacketHandler


class OptimizedPacketCaptureBackend:
    def __init__(self, ui=None):
        # UI reference for callbacks
        self.ui = ui

        # Connection settings
        self.capture_interface = None
        self.server_host = 'localhost'
        self.server_port = 9007
        self.environments = []
        self.username = None
        self.account_info = None

        # State tracking
        self.packet_count = 0
        self.running = False
        self.connected = False

        # Components
        self.client = None
        self.packet_handler = None

        # Protocol counts
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'FTP': 0,
            'SMTP': 0,
            'Other': 0
        }

        # Optimized UI updates
        self.last_ui_update = 0
        self.ui_update_interval = 0.2  # 200ms for more responsive updates
        self.local_protocol_counts = {
            'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SMTP': 0, 'Other': 0
        }
        self.local_packet_count = 0

        # Track changes for incremental updates
        self.protocol_changes = {}
        self.last_protocol_snapshot = {}

    def log(self, message):
        """Log a message through the UI"""
        if self.ui:
            try:
                self.ui.log_message(message)
            except Exception as e:
                print(f"UI log error: {e}")
                print(message)
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
                # Single environment support
                env_name = getattr(environments, 'env_name', environments)
                env_password = getattr(environments, 'env_password', None)
                self.environments = [{'env_name': env_name, 'env_password': env_password}]

        if username is not None:
            self.username = username

        if account_info is not None:
            self.account_info = account_info

        # Log the configuration
        self.log(f"Backend configured: host={self.server_host}, port={self.server_port}")
        self.log(f"Username: {self.username}, Environments: {[env.get('env_name') for env in self.environments]}")

    def start(self):
        """Start packet capture"""
        if self.running:
            return

        self.running = True

        # Create client
        self.client = StableSocketClient(self.server_host, self.server_port, self.log)

        # Set authentication
        env_names = [env.get('env_name') for env in self.environments]
        self.log(f"Setting auth for environments: {env_names} as user: {self.username}")
        self.client.set_auth(self.environments, self.username, self.account_info)

        # Register protocol update callback
        self.client.set_protocol_update_callback(self.update_protocol_counts)

        # Create packet handler with real capture capability
        self.packet_handler = RealPacketHandler(self.capture_interface, self.process_packet)

        # Start the client
        self.client.start()

        # Start the packet handler
        self.packet_handler.start()

        # Start stats updates with better frequency
        stats_thread = threading.Thread(target=self.update_stats)
        stats_thread.daemon = True
        stats_thread.start()

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
        """Update protocol counts with incremental UI updates"""
        current_time = time.time()

        # Quick check if update needed
        if current_time - self.last_ui_update < 0.1:  # 100ms minimum between updates
            return

        # Calculate what changed
        changes = {}
        for protocol, count in protocol_counts.items():
            last_count = self.last_protocol_snapshot.get(protocol, 0)
            if count != last_count:
                changes[protocol] = count

        # Only update if there are changes
        if changes:
            if environment is None:
                self.protocol_counts = protocol_counts
                self.last_ui_update = current_time
                self.last_protocol_snapshot = protocol_counts.copy()

                if self.ui and hasattr(self.ui, 'update_protocol_counts_incremental'):
                    # Use incremental update if available
                    self.ui.update_protocol_counts_incremental(changes)
                elif self.ui:
                    # Fallback to full update
                    try:
                        if hasattr(self.ui, 'update_protocol_counts_for_env'):
                            self.ui.update_protocol_counts_for_env(protocol_counts, None)
                        elif hasattr(self.ui, 'update_protocol_counts'):
                            self.ui.update_protocol_counts(protocol_counts)
                        if hasattr(self.ui, 'protocol_pie_chart') and self.ui.protocol_pie_chart:
                            self.ui.protocol_pie_chart.update_plot_incremental(changes)
                    except Exception as e:
                        print(f"Error updating UI protocol counts: {e}")

    def process_packet(self, packet_dict):
        """Process a packet with immediate local UI feedback"""
        if not self.running:
            return

        try:
            # Extract protocol for immediate UI update
            protocol = packet_dict.get('highest_layer', packet_dict.get('protocol', 'Other'))

            # Update local counts immediately
            if protocol in self.local_protocol_counts:
                self.local_protocol_counts[protocol] += 1
            else:
                self.local_protocol_counts['Other'] += 1
            self.local_packet_count += 1

            # Immediate UI feedback (very fast)
            current_time = time.time()
            if current_time - self.last_ui_update > 0.2:  # 200ms updates
                self.last_ui_update = current_time
                if self.ui:
                    try:
                        # Update UI with local counts for immediate feedback
                        if hasattr(self.ui, 'update_protocol_counts_for_env'):
                            self.ui.update_protocol_counts_for_env(self.local_protocol_counts, None)
                        elif hasattr(self.ui, 'update_protocol_counts'):
                            self.ui.update_protocol_counts(self.local_protocol_counts)
                        self.ui.update_packet_count(self.local_packet_count)
                    except Exception as e:
                        print(f"Error updating UI with local counts: {e}")

            # Continue with normal packet processing
            all_envs = [env.get('env_name') for env in self.environments]
            if not all_envs:
                return

            if self.username:
                packet_dict['username'] = self.username

            if self.client:
                # Include protocol in packet for server
                packet_dict['protocol_hint'] = protocol
                success = self.client.send_packet(packet_dict)
                if not success:
                    if not hasattr(self, '_last_error_log') or time.time() - self._last_error_log > 5:
                        self.log("Warning: Failed to send packet to server")
                        self._last_error_log = time.time()

        except Exception as e:
            print(f"Error processing packet: {str(e)}")

    def update_stats(self):
        """Update statistics periodically with better responsiveness"""
        last_packet_count = 0
        last_connection_status = None

        while self.running:
            try:
                current_time = time.time()

                # More responsive updates
                if current_time - self.last_ui_update < self.ui_update_interval:
                    time.sleep(0.5)  # Shorter sleep
                    continue

                if self.client:
                    # Get stats from client
                    new_packet_count = self.client.packet_count
                    new_connection_status = self.client.connected

                    # Update UI more frequently with smaller changes
                    packet_count_changed = abs(new_packet_count - last_packet_count) >= 1  # Update on every packet
                    connection_changed = new_connection_status != last_connection_status

                    if packet_count_changed or connection_changed or True:
                        self.packet_count = new_packet_count
                        self.connected = new_connection_status

                        # Update UI
                        if self.ui:
                            try:
                                if packet_count_changed:
                                    self.ui.update_packet_count(self.packet_count)
                                    last_packet_count = new_packet_count

                                if connection_changed:
                                    self.ui.update_connection_status(self.connected)
                                    last_connection_status = new_connection_status

                            except Exception as e:
                                print(f"Error updating UI stats: {e}")

                        self.last_ui_update = current_time

                # More responsive sleep
                time.sleep(1.0)  # Update every 1 second instead of 5

            except Exception as e:
                print(f"Error in update_stats: {str(e)}")
                time.sleep(1.0)

    def get_environments(self):
        """Return the list of configured environments"""
        return [env.get('env_name') for env in self.environments]


# For backward compatibility
class StablePacketCaptureBackend(OptimizedPacketCaptureBackend):
    pass