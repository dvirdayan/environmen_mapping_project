import threading
from datetime import datetime

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
