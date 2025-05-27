import threading
import time
import queue
from datetime import datetime


class RealPacketHandler:
    def __init__(self, interface, callback=None):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.thread = None
        self.packet_queue = queue.Queue(maxsize=1000)  # Increased queue size
        self.processing_thread = None
        self.use_real_capture = True  # Enable real capture by default

    def start(self):
        """Start packet capture - real or test based on configuration"""
        self.running = True
        if self.use_real_capture:
            self.thread = threading.Thread(target=self._capture_real_packets)
        else:
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
            self.thread.join(timeout=2.0)
        if self.processing_thread:
            self.processing_thread.join(timeout=2.0)

    def _capture_real_packets(self):
        """Capture real network packets using Scapy"""
        try:
            from scapy.all import sniff, IP, TCP, UDP, Raw
            print(f"Starting real packet capture on interface: {self.interface}")

            def packet_handler(packet):
                if not self.running:
                    return False  # Stop sniffing
                try:
                    # Convert Scapy packet to our format
                    packet_dict = self._scapy_to_dict(packet)

                    # Add to queue (non-blocking)
                    try:
                        self.packet_queue.put_nowait(packet_dict)
                    except queue.Full:
                        # Drop oldest packet and add new one
                        try:
                            self.packet_queue.get_nowait()
                            self.packet_queue.put_nowait(packet_dict)
                        except queue.Empty:
                            pass

                except Exception as e:
                    print(f"Error processing captured packet: {e}")

            # Start sniffing - this blocks until stopped
            sniff(iface=self.interface,
                  prn=packet_handler,
                  store=0,
                  stop_filter=lambda x: not self.running)

        except ImportError:
            print("Scapy not available, falling server_side to test packets")
            self._generate_test_packets()
        except Exception as e:
            print(f"Error in real packet capture: {e}")
            print("Falling server_side to test packets")
            self._generate_test_packets()

    def _scapy_to_dict(self, packet):
        """Convert a Scapy packet to our dictionary format"""
        packet_dict = {
            'timestamp': datetime.now().isoformat(),
            'protocol': 'Other',  # Default to 'Other'
            'highest_layer': 'Other',
            'packet_length': len(packet),
            'source_ip': None,
            'destination_ip': None,
            'source_port': None,
            'destination_port': None
        }

        # Extract IP layer info
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            packet_dict['source_ip'] = ip_layer.src
            packet_dict['destination_ip'] = ip_layer.dst
            packet_dict['protocol'] = 'TCP'  # Will be overridden below if UDP

        # Extract TCP info and classify application protocols
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            packet_dict['source_port'] = tcp_layer.sport
            packet_dict['destination_port'] = tcp_layer.dport
            packet_dict['protocol'] = 'TCP'
            packet_dict['highest_layer'] = 'TCP'

            # Classify by port numbers
            ports = [tcp_layer.sport, tcp_layer.dport]
            if 80 in ports:
                packet_dict['highest_layer'] = 'HTTP'
                packet_dict['protocol'] = 'HTTP'
            elif 443 in ports:
                packet_dict['highest_layer'] = 'HTTPS'
                packet_dict['protocol'] = 'HTTPS'
            elif 21 in ports:
                packet_dict['highest_layer'] = 'FTP'
                packet_dict['protocol'] = 'FTP'
            elif 25 in ports or 587 in ports:
                packet_dict['highest_layer'] = 'SMTP'
                packet_dict['protocol'] = 'SMTP'

        # Extract UDP info
        elif packet.haslayer('UDP'):
            udp_layer = packet['UDP']
            packet_dict['source_port'] = udp_layer.sport
            packet_dict['destination_port'] = udp_layer.dport
            packet_dict['protocol'] = 'UDP'
            packet_dict['highest_layer'] = 'UDP'

            # Check for DNS
            if 53 in [udp_layer.sport, udp_layer.dport]:
                packet_dict['highest_layer'] = 'DNS'

        # Ensure we return a known protocol
        known_protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SMTP']
        if packet_dict['protocol'] not in known_protocols:
            packet_dict['protocol'] = 'Other'
        if packet_dict['highest_layer'] not in known_protocols + ['DNS']:
            packet_dict['highest_layer'] = 'Other'

        return packet_dict

    def _generate_test_packets(self):
        """Generate test packets for testing when real capture isn't available"""
        counter = 0
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SMTP']

        while self.running:
            try:
                counter += 1
                protocol = protocols[counter % len(protocols)]

                # Create varied test packets
                packet = {
                    'timestamp': datetime.now().isoformat(),
                    'protocol': protocol,
                    'highest_layer': protocol,
                    'packet_length': 64 + (counter % 1000),
                    'source_ip': f'192.168.{(counter % 254) + 1}.{(counter % 100) + 1}',
                    'destination_ip': f'10.0.{(counter % 50) + 1}.{(counter % 200) + 1}',
                    'source_port': 1024 + (counter % 30000),
                    'destination_port': [80, 443, 21, 25, 53, 8080][counter % 6],
                    'test_counter': counter
                }

                # Add to queue
                try:
                    self.packet_queue.put_nowait(packet)
                except queue.Full:
                    # Drop oldest and add new
                    try:
                        self.packet_queue.get_nowait()
                        self.packet_queue.put_nowait(packet)
                    except queue.Empty:
                        pass

                # Generate packets more frequently for better demo
                time.sleep(0.1)  # 10 packets per second

            except Exception as e:
                print(f"Error generating test packet: {e}")
                time.sleep(1.0)

    def _process_packets(self):
        """Process packets from the queue"""
        while self.running:
            try:
                # Process packets in batches for better performance
                packets_processed = 0
                max_packets_per_batch = 10

                while packets_processed < max_packets_per_batch and self.running:
                    try:
                        packet = self.packet_queue.get(timeout=0.5)
                    except queue.Empty:
                        break

                    # Process packet
                    if self.callback:
                        try:
                            self.callback(packet)
                            packets_processed += 1
                        except Exception as e:
                            print(f"Error in packet callback: {e}")

                # Small delay between batches
                time.sleep(0.05)

            except Exception as e:
                print(f"Error processing packets: {e}")
                time.sleep(0.5)

    def set_real_capture(self, enabled=True):
        """Enable or disable real packet capture"""
        self.use_real_capture = enabled


# For backward compatibility
class SimplePacketHandler(RealPacketHandler):
    def __init__(self, interface, callback=None):
        super().__init__(interface, callback)
        self.use_real_capture = False  # Default to test packets for compatibility