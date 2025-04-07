import threading
import time
import queue
import pyshark
import socket
import json
import select
import asyncio
from datetime import datetime


class PacketCaptureBackend:
    def __init__(self, ui=None):
        # UI reference for callbacks
        self.ui = ui

        # Connection settings (will be set by configure method)
        self.capture_interface = None
        self.server_host = '192.168.0.113'
        self.server_port = 65432
        self.env_name = None
        self.env_password = None

        # State tracking
        self.client_socket = None
        self.packet_count = 0
        self.running = False
        self.connected = False
        self.reconnect_delay = 2

        # Threads
        self.capture_thread = None
        self.stats_thread = None

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

    def log(self, message):
        """Log a message through the UI"""
        if self.ui:
            self.ui.log_message(message)
        else:
            print(message)

    def start(self):
        """Start packet capture threads"""
        if self.running:
            return

        self.running = True

        # Start capture thread
        self.capture_thread = threading.Thread(target=self.capture_and_send)
        self.capture_thread.daemon = True
        self.capture_thread.start()

        # Start stats update thread
        self.stats_thread = threading.Thread(target=self.update_stats)
        self.stats_thread.daemon = True
        self.stats_thread.start()

        # Start UI packet processing if UI exists
        if self.ui:
            self.ui.start_processing_packets()

    def stop(self):
        """Stop packet capture"""
        self.running = False

        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None

        self.connected = False

    def connect_to_server(self):
        """Connect to the server"""
        try:
            if self.client_socket:
                self.client_socket.close()

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)
            self.client_socket.connect((self.server_host, self.server_port))

            # Send authentication if needed
            if self.env_name and self.env_password:
                credentials = {
                    'type': 'auth',
                    'env_name': self.env_name,
                    'env_password': self.env_password
                }
                auth_message = json.dumps(credentials) + '\n'
                self.client_socket.sendall(auth_message.encode('utf-8'))

                # Wait for auth response
                response = self.client_socket.recv(1024).decode('utf-8')
                response_data = json.loads(response)

                if response_data.get('status') != 'authenticated':
                    self.log(f"Authentication failed: {response_data.get('message', 'Unknown error')}")
                    self.client_socket.close()
                    return False

            # Set to non-blocking after connection
            self.client_socket.setblocking(False)
            self.connected = True
            self.log(f"Connected to server {self.server_host}:{self.server_port}")
            return True

        except Exception as e:
            self.log(f"Connection error: {e}")
            self.connected = False
            return False

    def update_stats(self):
        """Update statistics periodically"""
        while self.running:
            if self.ui:
                self.ui.update_packet_count(self.packet_count)
                self.ui.update_connection_status(self.connected)
            time.sleep(1)

    def serialize_packet(self, packet):
        """Convert packet to a serializable dictionary"""
        try:
            packet_dict = {
                'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else str(datetime.now()),
                'protocol': 'UNKNOWN',
                'highest_layer': packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN',
                'packet_length': packet.length if hasattr(packet, 'length') else 0,
                'env_name': self.env_name
            }

            if hasattr(packet, 'transport_layer') and packet.transport_layer:
                packet_dict['protocol'] = packet.transport_layer
            elif hasattr(packet, 'highest_layer'):
                packet_dict['protocol'] = packet.highest_layer

            if hasattr(packet, 'ip'):
                packet_dict.update({
                    'source_ip': packet.ip.src,
                    'destination_ip': packet.ip.dst
                })
            else:
                packet_dict.update({
                    'source_ip': None,
                    'destination_ip': None
                })

            if hasattr(packet, 'transport_layer') and packet.transport_layer:
                try:
                    transport_obj = getattr(packet, packet.transport_layer.lower())
                    packet_dict.update({
                        'source_port': transport_obj.srcport,
                        'destination_port': transport_obj.dstport
                    })
                except AttributeError:
                    packet_dict.update({
                        'source_port': None,
                        'destination_port': None
                    })
            else:
                packet_dict.update({
                    'source_port': None,
                    'destination_port': None
                })

            # Callback for UI update
            if self.ui:
                self.ui.process_packet(packet_dict)

            return json.dumps(packet_dict) + '\n'
        except Exception as e:
            self.log(f"Error serializing packet: {e}")
            return json.dumps({
                'timestamp': str(datetime.now()),
                'protocol': 'ERROR',
                'error': str(e),
                'packet_length': packet.length if hasattr(packet, 'length') else 0
            }) + '\n'

    def capture_and_send(self):
        """Capture live packets and send to server"""
        # Ensure an event loop exists in this thread
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            # If there's no event loop, create one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        while self.running:
            try:
                # Attempt to connect if not connected
                if not self.client_socket:
                    self.log(f"Attempting to connect to {self.server_host}:{self.server_port}")
                    if not self.connect_to_server():
                        time.sleep(self.reconnect_delay)
                        continue

                # Start capture
                # Use synchronous capture instead of async to avoid further event loop issues
                capture = pyshark.LiveCapture(interface=self.capture_interface, use_json=True)
                self.log(f"Starting capture on interface {self.capture_interface}")

                # Set a short timeout for the capture
                capture.set_debug()

                for packet in capture.sniff_continuously():
                    if not self.running:
                        break

                    try:
                        # Serialize and send packet
                        serialized_packet = self.serialize_packet(packet)

                        try:
                            self.client_socket.sendall(serialized_packet.encode('utf-8'))
                        except (socket.error, BrokenPipeError) as send_error:
                            self.log(f"Send error: {send_error}")
                            self.connected = False
                            if self.client_socket:
                                self.client_socket.close()
                            self.client_socket = None
                            break

                        # Non-blocking receive for acknowledgment
                        try:
                            ready = select.select([self.client_socket], [], [], 0.1)  # Short timeout
                            if ready[0]:
                                ack_data = self.client_socket.recv(1024).decode('utf-8')
                                if not ack_data:
                                    raise socket.error("No acknowledgment received")

                                # Parse server packet count
                                if '|' in ack_data:
                                    ack_parts = ack_data.strip().split('|')
                                    if len(ack_parts) == 2:
                                        try:
                                            self.packet_count = int(ack_parts[1])
                                        except ValueError:
                                            pass
                        except (socket.error, socket.timeout):
                            # Timeout on receive is okay
                            pass

                    except Exception as e:
                        self.log(f"Error processing packet: {e}")
                        continue  # Try next packet instead of breaking

            except Exception as e:
                self.log(f"Capture error: {e}")
                self.connected = False
                time.sleep(self.reconnect_delay)
            finally:
                # Ensure socket is closed
                if self.client_socket:
                    try:
                        self.client_socket.close()
                    except:
                        pass
                    self.client_socket = None
                    self.connected = False


# Alternative Scapy implementation - can be enabled in main.py if needed
class ScapyPacketCaptureBackend(PacketCaptureBackend):
    def capture_and_send(self):
        """Capture live packets using Scapy instead of PyShark"""
        from scapy.all import sniff

        def packet_handler(packet):
            if not self.running:
                return

            try:
                # Convert Scapy packet to dict
                packet_dict = self.scapy_packet_to_dict(packet)

                # Callback for UI update
                if self.ui:
                    self.ui.process_packet(packet_dict)

                # Serialize and send
                serialized_packet = json.dumps(packet_dict) + '\n'

                try:
                    if self.client_socket:
                        self.client_socket.sendall(serialized_packet.encode('utf-8'))
                    else:
                        # Try to reconnect
                        if self.connect_to_server():
                            self.client_socket.sendall(serialized_packet.encode('utf-8'))
                except Exception as e:
                    self.log(f"Send error: {e}")
                    self.connected = False
                    if self.client_socket:
                        self.client_socket.close()
                    self.client_socket = None

            except Exception as e:
                self.log(f"Error processing packet: {e}")

        while self.running:
            try:
                # Attempt to connect if not connected
                if not self.client_socket:
                    self.log(f"Attempting to connect to {self.server_host}:{self.server_port}")
                    if not self.connect_to_server():
                        time.sleep(self.reconnect_delay)
                        continue

                self.log(f"Starting capture on interface {self.capture_interface}")
                # Start sniffing with Scapy - this doesn't have event loop issues
                sniff(iface=self.capture_interface, prn=packet_handler, store=0)

            except Exception as e:
                self.log(f"Capture error: {e}")
                self.connected = False
                time.sleep(self.reconnect_delay)

    def scapy_packet_to_dict(self, packet):
        """Convert a Scapy packet to dictionary"""
        packet_dict = {
            'timestamp': str(datetime.now()),
            'protocol': 'UNKNOWN',
            'highest_layer': 'UNKNOWN',
            'packet_length': len(packet),
            'env_name': self.env_name,
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
        elif 'ICMP' in packet:
            packet_dict['highest_layer'] = 'ICMP'

        return packet_dict