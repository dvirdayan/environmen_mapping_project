import pyshark
import socket
import json
import select
import time
import psutil
import threading


class LivePacketCaptureClient:
    def __init__(self, capture_interface=None, server_host='localhost', server_port=65432,
                 env_name=None, env_password=None):
        self.capture_interface = capture_interface
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = None
        self.reconnect_delay = 2
        # Add environment credentials
        self.env_name = env_name
        self.env_password = env_password
        # Add packet counter
        self.packet_count = 0
        self.running = True

        # Start packet count display thread
        self.display_thread = threading.Thread(target=self.display_packet_count)
        self.display_thread.daemon = True
        self.display_thread.start()

    def display_packet_count(self):
        """Display packet count every 5 seconds"""
        while self.running:
            time.sleep(5)
            print(f"\n[STATS] Total packets captured and sent: {self.packet_count}")

    @staticmethod
    def list_interfaces():
        """List all available network interfaces using tshark"""
        try:
            # Use PyShark to get interfaces
            interfaces = list(psutil.net_if_addrs().keys())
            print("\nAvailable Network Interfaces:")
            print("-----------------------------")
            for idx, iface in enumerate(interfaces, 1):
                print(f"{idx}. {iface}")
            return interfaces
        except Exception as e:
            print(f"Error listing interfaces: {e}")
            return []

    def connect_to_server(self):
        try:
            if self.client_socket:
                self.client_socket.close()

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_host, self.server_port))

            # Send environment credentials if available
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
                    print(f"Authentication failed: {response_data.get('message', 'Unknown error')}")
                    self.client_socket.close()
                    return False

            print(f"Connected to server {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    # Modify serialize_packet to include environment information
    def serialize_packet(self, packet):
        """Convert packet to a serializable dictionary"""
        try:
            packet_dict = {
                'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else None,
                'protocol': 'UNKNOWN',
                'highest_layer': packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN',
                'packet_length': packet.length if hasattr(packet, 'length') else 0,
                'env_name': self.env_name  # Add environment name to packet data
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

            return json.dumps(packet_dict) + '\n'
        except Exception as e:
            print(f"Error serializing packet: {e}")
            return json.dumps({
                'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else None,
                'protocol': 'ERROR',
                'error': str(e),
                'packet_length': packet.length if hasattr(packet, 'length') else 0
            }) + '\n'

    def capture_and_send(self):
        """Capture live packets and send to server with improved connection handling"""
        while self.running:
            try:
                # Attempt to connect to the server
                if not self.client_socket:
                    print(f"Attempting to connect to {self.server_host}:{self.server_port}")
                    try:
                        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.client_socket.settimeout(10)  # Set connection timeout
                        self.client_socket.connect((self.server_host, self.server_port))
                        print(f"Connected to server {self.server_host}:{self.server_port}")

                        # Set socket to non-blocking mode after connection
                        self.client_socket.setblocking(False)
                    except (socket.error, socket.timeout) as conn_error:
                        print(f"Connection error: {conn_error}")
                        # Wait before retrying
                        time.sleep(self.reconnect_delay)
                        self.client_socket = None
                        continue

                # Start packet capture
                capture = pyshark.LiveCapture(interface=self.capture_interface)
                print(f"Starting capture on interface {self.capture_interface}")

                for packet in capture:
                    if not self.running:
                        break

                    try:
                        # Serialize and send packet
                        serialized_packet = self.serialize_packet(packet) + '\n'

                        # Try to send the packet
                        try:
                            self.client_socket.sendall(serialized_packet.encode('utf-8'))
                        except (socket.error, BrokenPipeError) as send_error:
                            print(f"Send error: {send_error}")
                            # Close and reset socket
                            self.client_socket.close()
                            self.client_socket = None
                            break

                        # Non-blocking receive for acknowledgment
                        try:
                            ready = select.select([self.client_socket], [], [], 5)
                            if ready[0]:
                                ack_data = self.client_socket.recv(1024).decode('utf-8')
                                if not ack_data:
                                    raise socket.error("No acknowledgment received")

                                # Parse server packet count from acknowledgment
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
                        print(f"Error processing packet: {e}")
                        break

            except Exception as e:
                print(f"Capture error: {e}")
                time.sleep(self.reconnect_delay)
            finally:
                # Ensure socket is closed
                if self.client_socket:
                    try:
                        self.client_socket.close()
                    except:
                        pass
                    self.client_socket = None

    def close(self):
        self.running = False
        if self.client_socket:
            self.client_socket.close()
        print("Connection closed")


if __name__ == "__main__":
    # Try to list interfaces
    print("Attempting to list network interfaces...")
    interfaces = LivePacketCaptureClient.list_interfaces()

    if not interfaces:
        print("\nFailed to automatically detect interfaces.")
        interface_name = input(
            "Please enter your network interface name manually (e.g., 'Wi-Fi', 'Ethernet', 'eth0'): ")
    else:
        while True:
            try:
                choice = int(input("\nEnter the number of the interface you want to capture from: "))
                if 1 <= choice <= len(interfaces):
                    interface_name = interfaces[choice - 1]
                    break
                else:
                    print("Invalid choice. Please select a valid number.")
            except ValueError:
                print("Please enter a valid number.")

    print(f"\nSelected interface: {interface_name}")

    # Make sure server is running
    input("Make sure the server is running and press Enter to continue...")

    use_env = input("\nDo you want to connect to a specific environment? (y/n): ").lower()
    env_name = None
    env_password = None

    if use_env == 'y' or use_env == 'yes':
        env_name = input("Enter environment name: ")
        env_password = input("Enter environment password: ")

    print(f"\nSelected interface: {interface_name}")
    if env_name:
        print(f"Using environment: {env_name}")

    # Make sure server is running
    input("Make sure the server is running and press Enter to continue...")

    client = LivePacketCaptureClient(
        capture_interface=interface_name,
        env_name=env_name,
        env_password=env_password
    )
    try:
        client.capture_and_send()
    except KeyboardInterrupt:
        print("\nStopping capture...")
        client.close()