import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import time
import psutil
from datetime import datetime


class PacketCaptureClientUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Capture Client")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        self.capture_running = False
        self.log_queue = queue.Queue(maxsize=500)  # Reasonable queue size
        self.packet_queue = queue.Queue(maxsize=200)  # Increased for better buffering
        self.backend = None

        # Protocol count data
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'FTP': 0,
            'SMTP': 0,
            'Other': 0
        }

        # Optimized update intervals - much more responsive
        self.last_ui_update = 0
        self.ui_update_interval = 0.5  # Update UI every 500ms (was 2 seconds)

        # Setup UI components
        self.setup_ui()

        # Start processing with better responsiveness
        self.start_log_consumer()
        self.start_processing_packets()

        # When closing the window
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Populate interface list
        self.populate_interfaces()

        # Add initial log message
        self.log_message("Application started. Logging system initialized.")

    def setup_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # User information section
        user_info_frame = ttk.LabelFrame(main_frame, text="User Information", padding="10")
        user_info_frame.pack(fill=tk.X, pady=5)

        info_grid = ttk.Frame(user_info_frame)
        info_grid.pack(fill=tk.X, pady=5, padx=5)

        ttk.Label(info_grid, text="Username:", anchor=tk.E).grid(row=0, column=0, sticky=tk.E, padx=(5, 2), pady=2)
        self.username_var = tk.StringVar(value="Not logged in")
        ttk.Label(info_grid, textvariable=self.username_var).grid(row=0, column=1, sticky=tk.W, padx=(0, 20), pady=2)

        ttk.Label(info_grid, text="Environment:", anchor=tk.E).grid(row=0, column=2, sticky=tk.E, padx=(5, 2), pady=2)
        self.env_var = tk.StringVar(value="Not connected")
        ttk.Label(info_grid, textvariable=self.env_var).grid(row=0, column=3, sticky=tk.W, padx=(0, 5), pady=2)

        # Connection settings
        connection_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        connection_frame.pack(fill=tk.X, pady=5)

        ttk.Label(connection_frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(connection_frame, textvariable=self.interface_var, state="readonly",
                                            width=30)
        self.interface_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(connection_frame, text="Refresh", command=self.populate_interfaces).grid(row=0, column=2, padx=5,
                                                                                            pady=5)

        ttk.Label(connection_frame, text="Server Host:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.server_host_var = tk.StringVar(value="176.9.45.249")
        ttk.Entry(connection_frame, textvariable=self.server_host_var, width=30).grid(row=1, column=1, sticky=tk.W,
                                                                                      padx=5, pady=5)

        ttk.Label(connection_frame, text="Server Port:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.server_port_var = tk.IntVar(value=9007)
        ttk.Entry(connection_frame, textvariable=self.server_port_var, width=10).grid(row=1, column=3, sticky=tk.W,
                                                                                      padx=5, pady=5)

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)

        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)

        # Toggle between real and test packet capture
        self.capture_mode_var = tk.StringVar(value="Real Capture")
        self.capture_mode_button = ttk.Button(control_frame, text="Real Capture",
                                              command=self.toggle_capture_mode)
        self.capture_mode_button.pack(side=tk.LEFT, padx=5)

        # Stats frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)

        # Basic stats
        basic_stats_frame = ttk.Frame(stats_frame)
        basic_stats_frame.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

        ttk.Label(basic_stats_frame, text="Packets Captured:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.packet_count_var = tk.StringVar(value="0")
        ttk.Label(basic_stats_frame, textvariable=self.packet_count_var).grid(row=0, column=1, sticky=tk.W, padx=5,
                                                                              pady=5)

        ttk.Label(basic_stats_frame, text="Connection Status:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.connection_status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(basic_stats_frame, textvariable=self.connection_status_var)
        self.status_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.update_status_indicator("Disconnected")

        # Protocol counts
        protocol_frame = ttk.LabelFrame(stats_frame, text="Protocol Distribution", padding="5")
        protocol_frame.grid(row=0, column=1, sticky=tk.E, padx=5, pady=5)

        self.protocol_labels = {}
        for i, protocol in enumerate(['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'Other']):
            ttk.Label(protocol_frame, text=f"{protocol}:").grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
            var = tk.StringVar(value="0")
            self.protocol_labels[protocol] = var
            ttk.Label(protocol_frame, textvariable=var, width=8).grid(row=i, column=1, sticky=tk.E, padx=5, pady=2)

        # Create notebook for additional tabs (like pie chart)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Log tab
        log_tab = ttk.Frame(self.notebook)
        self.notebook.add(log_tab, text="Logs")

        log_frame = ttk.LabelFrame(log_tab, text="Application Logs", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15,
                                                  background="white")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, "Log system initialized...\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_capture_mode(self):
        """Toggle between real and test packet capture"""
        if hasattr(self, 'backend') and self.backend and hasattr(self.backend, 'packet_handler'):
            if hasattr(self.backend.packet_handler, 'use_real_capture'):
                current_mode = self.backend.packet_handler.use_real_capture
                new_mode = not current_mode
                self.backend.packet_handler.set_real_capture(new_mode)

                mode_text = "Real Capture" if new_mode else "Test Packets"
                self.capture_mode_button.config(text=mode_text)
                self.log_message(f"Switched to: {mode_text}")

    def update_user_info(self, username=None, user_id=None, environment=None):
        """Update the user information display"""
        if username:
            self.username_var.set(username)
        if environment:
            self.env_var.set(environment)

    def set_backend(self, backend):
        """Set the backend reference"""
        self.backend = backend

        # Update user info from backend
        if hasattr(backend, 'username') and backend.username:
            # Get environment names from the backend
            env_names = []
            if hasattr(backend, 'environments') and backend.environments:
                env_names = [env.get('env_name') for env in backend.environments if env.get('env_name')]

            # Use the first environment for display
            primary_env = env_names[0] if env_names else "default"

            self.update_user_info(
                username=backend.username,
                environment=primary_env
            )

    def populate_interfaces(self):
        """Populate the interface dropdown with available network interfaces"""
        try:
            interfaces = list(psutil.net_if_addrs().keys())
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_combo.current(0)
            self.log_message("Network interfaces refreshed")
        except Exception as e:
            self.log_message(f"Error listing interfaces: {e}")

    def start_capture(self):
        """Start packet capture"""
        if self.capture_running or not self.backend:
            return

        # Get values from UI
        interface = self.interface_var.get()
        server_host = self.server_host_var.get()
        server_port = self.server_port_var.get()

        # Check if interface is selected
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return

        # Update UI state
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.capture_running = True
        self.update_status_indicator("Connecting...")

        # Configure and start the backend
        self.backend.configure(
            capture_interface=interface,
            server_host=server_host,
            server_port=server_port
        )
        self.backend.start()

        self.log_message("Packet capture started")
        self.status_var.set(f"Capturing on {interface}")

    def stop_capture(self):
        """Stop packet capture"""
        if not self.capture_running or not self.backend:
            return

        self.backend.stop()
        self.capture_running = False

        # Update UI state
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.update_status_indicator("Disconnected")
        self.status_var.set("Ready")
        self.log_message("Packet capture stopped")

    def update_status_indicator(self, status):
        """Update connection status indicator"""
        self.connection_status_var.set(status)
        if status == "Connected":
            self.status_label.config(foreground="green")
        elif status == "Disconnected":
            self.status_label.config(foreground="red")
        else:
            self.status_label.config(foreground="orange")

    def update_connection_status(self, is_connected):
        """Update the connection status based on backend state"""
        # More responsive status updates
        if is_connected:
            self.update_status_indicator("Connected")
        else:
            self.update_status_indicator("Reconnecting...")

    def update_packet_count(self, count):
        """Update the packet count display"""
        # More responsive packet count updates
        self.packet_count_var.set(str(count))

    def update_protocol_counts(self, protocol_counts):
        """Update the protocol distribution display"""
        current_time = time.time()
        if current_time - self.last_ui_update < 0.2:
            return
        self.last_ui_update = current_time
        self.protocol_counts = protocol_counts
        for protocol, count in protocol_counts.items():
            if protocol in self.protocol_labels:
                self.protocol_labels[protocol].set(str(count))
        if hasattr(self, 'protocol_pie_chart') and self.protocol_pie_chart:
            self.protocol_pie_chart.update_plot(protocol_counts)

    def update_protocol_counts_for_env(self, protocol_counts, environment=None):
        """Update protocol counts - only for global stats"""
        if environment is None:  # Only update for global stats
            self.update_protocol_counts(protocol_counts)

    def process_packet(self, packet_data):
        """Process received packet data"""
        # Better queue management
        try:
            self.packet_queue.put_nowait(packet_data)
        except queue.Full:
            # Remove oldest and add new
            try:
                self.packet_queue.get_nowait()
                self.packet_queue.put_nowait(packet_data)
            except queue.Empty:
                pass
        except Exception as e:
            print(f"Error queuing packet: {str(e)}")

    def process_packet_with_environments(self, packet_data, environments=None):
        """Process packet with environment information"""
        self.process_packet(packet_data)

    def start_processing_packets(self):
        """Process packets from the queue and update UI"""
        # More responsive packet processing
        packets_processed = 0
        max_packets_per_cycle = 20  # Process more packets per cycle

        while not self.packet_queue.empty() and packets_processed < max_packets_per_cycle:
            try:
                packet_data = self.packet_queue.get_nowait()
                packets_processed += 1
                # Process packet data if needed
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error processing packet: {str(e)}")
                break

        # More responsive scheduling
        self.root.after(100, self.start_processing_packets)  # 100ms instead of 500ms

    def log_message(self, message):
        """Add message to log queue"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"

        # Better log queue management
        if self.log_queue.qsize() > 400:
            try:
                # Remove multiple old entries
                for _ in range(50):
                    self.log_queue.get_nowait()
            except queue.Empty:
                pass

        self.log_queue.put(log_entry)
        print(log_entry)  # Also print to console

    def start_log_consumer(self):
        """Start consuming messages from the log queue"""

        def consume():
            try:
                # Process more log messages at once for better responsiveness
                messages_processed = 0
                max_messages = 10

                while not self.log_queue.empty() and messages_processed < max_messages:
                    try:
                        message = self.log_queue.get_nowait()
                        self.log_text.config(state=tk.NORMAL)
                        self.log_text.insert(tk.END, message + "\n")

                        # Better log management
                        lines = self.log_text.get("1.0", tk.END).split('\n')
                        if len(lines) > 200:  # Keep more lines for better context
                            self.log_text.delete("1.0", f"{len(lines) - 150}.0")

                        self.log_text.see(tk.END)
                        self.log_text.config(state=tk.DISABLED)
                        messages_processed += 1
                    except queue.Empty:
                        break
            except Exception as e:
                print(f"Error consuming log: {e}")

            # More responsive log updates
            self.root.after(500, consume)  # 500ms instead of 1 second

        # Start consumption
        self.root.after(500, consume)

    def clear_logs(self):
        """Clear the log text area"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.log_message("Logs cleared")

    def on_closing(self):
        """Handle window closing"""
        if self.capture_running:
            if messagebox.askyesno("Quit", "Packet capture is still running. Are you sure you want to quit?"):
                self.stop_capture()
                self.root.destroy()
        else:
            self.root.destroy()

    def debug_protocol_update(self, source, protocol_counts):
        """Debug method to track protocol updates"""
        total = sum(protocol_counts.values())
        if total > 0:
            print(f"[DEBUG] Protocol update from {source}: Total={total}")
            for proto, count in protocol_counts.items():
                if count > 0:
                    percentage = (count / total) * 100
                    print(f"  {proto}: {count} ({percentage:.1f}%)")
        else:
            print(f"[DEBUG] Protocol update from {source}: No packets yet")