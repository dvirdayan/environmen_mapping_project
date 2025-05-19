import threading
import time
import queue
from datetime import datetime


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