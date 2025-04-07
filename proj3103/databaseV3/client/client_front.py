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
        self.log_queue = queue.Queue()
        self.packet_queue = queue.Queue(maxsize=1000)  # Limit queue size to prevent memory issues
        self.backend = None  # Will be set by main.py

        # Setup UI components
        self.setup_ui()

        # Start log consumer
        self.start_log_consumer()

        # When closing the window
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Populate interface list
        self.populate_interfaces()

    def setup_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create top frame for connection settings
        connection_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        connection_frame.pack(fill=tk.X, pady=5)

        # Network interface selection
        ttk.Label(connection_frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(connection_frame, textvariable=self.interface_var, state="readonly",
                                            width=30)
        self.interface_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(connection_frame, text="Refresh", command=self.populate_interfaces).grid(row=0, column=2, padx=5,
                                                                                            pady=5)

        # Server settings
        ttk.Label(connection_frame, text="Server Host:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.server_host_var = tk.StringVar(value="192.168.0.113")
        ttk.Entry(connection_frame, textvariable=self.server_host_var, width=30).grid(row=1, column=1, sticky=tk.W,
                                                                                      padx=5, pady=5)

        ttk.Label(connection_frame, text="Server Port:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.server_port_var = tk.IntVar(value=65432)
        ttk.Entry(connection_frame, textvariable=self.server_port_var, width=10).grid(row=1, column=3, sticky=tk.W,
                                                                                      padx=5, pady=5)

        # Environment settings
        env_frame = ttk.LabelFrame(main_frame, text="Environment Settings", padding="10")
        env_frame.pack(fill=tk.X, pady=5)

        self.use_env_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(env_frame, text="Use Environment Authentication", variable=self.use_env_var,
                        command=self.toggle_env_fields).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

        ttk.Label(env_frame, text="Environment Name:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.env_name_var = tk.StringVar()
        self.env_name_entry = ttk.Entry(env_frame, textvariable=self.env_name_var, width=30, state="disabled")
        self.env_name_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(env_frame, text="Environment Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.env_password_var = tk.StringVar()
        self.env_password_entry = ttk.Entry(env_frame, textvariable=self.env_password_var, width=30, show="*",
                                            state="disabled")
        self.env_password_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)

        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)

        # Stats frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)

        ttk.Label(stats_frame, text="Packets Captured:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.packet_count_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.packet_count_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(stats_frame, text="Connection Status:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.connection_status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(stats_frame, textvariable=self.connection_status_var)
        self.status_label.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        self.update_status_indicator("Disconnected")

        # Setup notebook with tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Log tab
        log_frame = ttk.Frame(notebook, padding="10")
        notebook.add(log_frame, text="Logs")

        # Create log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)

        # Packet tab
        packet_frame = ttk.Frame(notebook, padding="10")
        notebook.add(packet_frame, text="Packet Data")

        # Create packet treeview
        columns = ("timestamp", "protocol", "source", "destination", "length")
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings")

        # Define headings
        self.packet_tree.heading("timestamp", text="Timestamp")
        self.packet_tree.heading("protocol", text="Protocol")
        self.packet_tree.heading("source", text="Source")
        self.packet_tree.heading("destination", text="Destination")
        self.packet_tree.heading("length", text="Length")

        # Define columns
        self.packet_tree.column("timestamp", width=150)
        self.packet_tree.column("protocol", width=100)
        self.packet_tree.column("source", width=200)
        self.packet_tree.column("destination", width=200)
        self.packet_tree.column("length", width=100)

        # Add scrollbar to treeview
        tree_scrollbar = ttk.Scrollbar(packet_frame, orient="vertical", command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=tree_scrollbar.set)

        # Pack treeview and scrollbar
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Status bar at bottom
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def set_backend(self, backend):
        """Set the backend reference"""
        self.backend = backend

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

    def toggle_env_fields(self):
        """Enable or disable environment fields based on checkbox state"""
        state = "normal" if self.use_env_var.get() else "disabled"
        self.env_name_entry.config(state=state)
        self.env_password_entry.config(state=state)

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

        # Get environment settings if enabled
        env_name = None
        env_password = None
        if self.use_env_var.get():
            env_name = self.env_name_var.get()
            env_password = self.env_password_var.get()
            if not env_name or not env_password:
                messagebox.showerror("Error", "Please enter both environment name and password")
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
            server_port=server_port,
            env_name=env_name,
            env_password=env_password
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
        if is_connected:
            self.update_status_indicator("Connected")
        else:
            self.update_status_indicator("Reconnecting...")

    def update_packet_count(self, count):
        """Update the packet count display"""
        self.packet_count_var.set(str(count))

    def process_packet(self, packet_data):
        """Process received packet data"""
        try:
            if not self.packet_queue.full():
                self.packet_queue.put_nowait(packet_data)
            else:
                # Skip oldest packet if queue is full
                try:
                    self.packet_queue.get_nowait()
                    self.packet_queue.put_nowait(packet_data)
                except queue.Empty:
                    pass
        except Exception as e:
            self.log_message(f"Error queuing packet: {str(e)}")

    def start_processing_packets(self):
        """Process packets from the queue and update UI"""
        if not self.packet_queue.empty():
            try:
                packet_data = self.packet_queue.get_nowait()
                self.add_packet_to_tree(packet_data)
            except queue.Empty:
                pass
            except Exception as e:
                self.log_message(f"Error processing packet: {str(e)}")

        # Schedule next processing
        self.root.after(10, self.start_processing_packets)

    def add_packet_to_tree(self, packet_data):
        """Add packet data to the treeview"""
        try:
            # Format source and destination
            source = f"{packet_data.get('source_ip', 'Unknown')}"
            if packet_data.get('source_port'):
                source += f":{packet_data.get('source_port')}"

            destination = f"{packet_data.get('destination_ip', 'Unknown')}"
            if packet_data.get('destination_port'):
                destination += f":{packet_data.get('destination_port')}"

            # Add to treeview
            self.packet_tree.insert("", 0, values=(
                packet_data.get('timestamp', 'Unknown'),
                packet_data.get('protocol', 'Unknown'),
                source,
                destination,
                packet_data.get('packet_length', 0)
            ))

            # Limit number of items in tree to prevent memory issues
            if self.packet_tree.get_children():
                items = self.packet_tree.get_children()
                if len(items) > 1000:
                    self.packet_tree.delete(items[-1])
        except Exception as e:
            self.log_message(f"Error adding packet to tree: {str(e)}")

    def log_message(self, message):
        """Add message to log queue"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put(f"[{timestamp}] {message}")

    def start_log_consumer(self):
        """Start consuming messages from the log queue"""

        def consume():
            try:
                # Process all available messages
                while not self.log_queue.empty():
                    message = self.log_queue.get_nowait()
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, message + "\n")
                    self.log_text.see(tk.END)
                    self.log_text.config(state=tk.DISABLED)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"Error consuming log: {e}")

            # Schedule next check
            self.root.after(100, consume)

        # Start initial consumption
        self.root.after(100, consume)

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