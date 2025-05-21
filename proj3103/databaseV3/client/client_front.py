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

        # Setup UI components
        self.setup_ui()

        # Start log consumer
        self.start_log_consumer()

        # Start packet processing
        self.start_processing_packets()  # Make sure this gets called on init

        # When closing the window
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Populate interface list
        self.populate_interfaces()

        # Add initial log message to confirm logging works
        self.log_message("Application started. Logging system initialized.")

    def setup_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # User information section with grid layout
        user_info_frame = ttk.LabelFrame(main_frame, text="User Information", padding="10")
        user_info_frame.pack(fill=tk.X, pady=5)

        # Create a grid layout with 4 columns
        info_grid = ttk.Frame(user_info_frame)
        info_grid.pack(fill=tk.X, pady=5, padx=5)

        # Column headers and labels
        ttk.Label(info_grid, text="Username:", anchor=tk.E).grid(row=0, column=0, sticky=tk.E, padx=(5, 2), pady=2)
        self.username_var = tk.StringVar(value="Not logged in")
        ttk.Label(info_grid, textvariable=self.username_var).grid(row=0, column=1, sticky=tk.W, padx=(0, 20), pady=2)

        ttk.Label(info_grid, text="Environment:", anchor=tk.E).grid(row=0, column=2, sticky=tk.E, padx=(5, 2), pady=2)
        self.env_var = tk.StringVar(value="Not connected")
        ttk.Label(info_grid, textvariable=self.env_var).grid(row=0, column=3, sticky=tk.W, padx=(0, 5), pady=2)

        ttk.Label(info_grid, text="User ID:", anchor=tk.E).grid(row=1, column=0, sticky=tk.E, padx=(5, 2), pady=2)
        self.userid_var = tk.StringVar(value="N/A")
        ttk.Label(info_grid, textvariable=self.userid_var).grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=2)

        ttk.Label(info_grid, text="Role:", anchor=tk.E).grid(row=1, column=2, sticky=tk.E, padx=(5, 2), pady=2)
        self.role_var = tk.StringVar(value="N/A")
        ttk.Label(info_grid, textvariable=self.role_var).grid(row=1, column=3, sticky=tk.W, padx=(0, 5), pady=2)

        # Set column weights to ensure proper spacing
        info_grid.columnconfigure(0, weight=1)  # Username label
        info_grid.columnconfigure(1, weight=2)  # Username value
        info_grid.columnconfigure(2, weight=1)  # Environment label
        info_grid.columnconfigure(3, weight=2)  # Environment value

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

        # Stats frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)

        # Left side - basic stats
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

        # Right side - protocol counts
        protocol_frame = ttk.LabelFrame(stats_frame, text="Protocol Distribution", padding="5")
        protocol_frame.grid(row=0, column=1, sticky=tk.E, padx=5, pady=5)

        # Create protocol count labels
        self.protocol_labels = {}
        for i, protocol in enumerate(['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'Other']):
            ttk.Label(protocol_frame, text=f"{protocol}:").grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
            var = tk.StringVar(value="0")
            self.protocol_labels[protocol] = var
            ttk.Label(protocol_frame, textvariable=var, width=8).grid(row=i, column=1, sticky=tk.E, padx=5, pady=2)

        # Setup notebook with tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Log tab
        log_frame = ttk.Frame(notebook, padding="10")
        notebook.add(log_frame, text="Logs")

        # Create log text area with white background for better visibility
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, background="white")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.NORMAL)  # Make sure it's initially NORMAL so we can write to it
        self.log_text.insert(tk.END, "Log system initialized...\n")  # Add initial text
        self.log_text.see(tk.END)  # Scroll to end
        self.log_text.config(state=tk.DISABLED)  # Then disable it

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

    def update_user_info(self, username=None, user_id=None, environment=None, is_admin=False):
        """Update the user information display"""
        if username:
            self.username_var.set(username)

        if user_id:
            self.userid_var.set(str(user_id))

        if environment:
            self.env_var.set(environment)

        # Set the role based on admin status
        self.role_var.set("Admin" if is_admin else "Member")

    def set_backend(self, backend):
        """Set the backend reference"""
        self.backend = backend

        # Debug print
        print("Setting backend with data:")
        print(f"Username: {getattr(backend, 'username', 'Not set')}")
        print(f"Account info: {getattr(backend, 'account_info', 'Not set')}")

        # Update user info from backend
        if hasattr(backend, 'username') and backend.username:
            account_info = getattr(backend, 'account_info', {}) or {}

            # Debug print
            print(f"Extracted account_info: {account_info}")

            # Extract user information
            user_id = None
            is_admin = False
            env_name = getattr(backend, 'env_name', 'Not set')

            if isinstance(account_info, dict):
                user_id = account_info.get('user_id')
                is_admin = account_info.get('is_admin', False)
                print(f"Extracted user_id: {user_id}, is_admin: {is_admin}")

            # Update the UI with user information
            self.log_message(f"Updating UI with: username={backend.username}, user_id={user_id}, env={env_name}")
            self.update_user_info(
                username=backend.username,
                user_id=user_id,
                environment=env_name,
                is_admin=is_admin
            )
        else:
            self.log_message("No username found in backend when setting backend")

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

        # Update environment information in the UI again to ensure it's displayed
        if hasattr(self.backend, 'username') and self.backend.username:
            account_info = getattr(self.backend, 'account_info', {}) or {}
            user_id = None
            is_admin = False

            if isinstance(account_info, dict):
                user_id = account_info.get('user_id')
                is_admin = account_info.get('is_admin', False)

            # Get environment names from the backend
            env_names = []
            if hasattr(self.backend, 'environments') and self.backend.environments:
                env_names = [env.get('env_name') for env in self.backend.environments if env.get('env_name')]

            # Create environment string for display
            env_str = "default"
            if env_names:
                env_str = ", ".join(env_names)

            # Use the first environment for backward compatibility with UI display
            primary_env = env_names[0] if env_names else "default"

            self.log_message(f"Starting capture as: {self.backend.username} in environments: {env_str}")
            self.update_user_info(
                username=self.backend.username,
                user_id=user_id,
                environment=primary_env,  # Just use the first environment for the UI display
                is_admin=is_admin
            )

        # Configure and start the backend
        self.backend.configure(
            capture_interface=interface,
            server_host=server_host,
            server_port=server_port
            # Note: keep existing username and env data that was loaded from config
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

    def update_protocol_counts(self, protocol_counts):
        """Update the protocol distribution display"""
        # Store current protocol counts
        self.protocol_counts = protocol_counts

        # Update the labels with new values
        for protocol, count in protocol_counts.items():
            if protocol in self.protocol_labels:
                self.protocol_labels[protocol].set(str(count))

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
        log_entry = f"[{timestamp}] {message}"

        # Add to queue
        self.log_queue.put(log_entry)

        # Also print to console for debugging
        print(log_entry)

    def start_log_consumer(self):
        """Start consuming messages from the log queue"""

        def consume():
            try:
                # Process all available messages
                processed = False
                while not self.log_queue.empty():
                    try:
                        message = self.log_queue.get_nowait()
                        self.log_text.config(state=tk.NORMAL)
                        self.log_text.insert(tk.END, message + "\n")
                        self.log_text.see(tk.END)
                        self.log_text.config(state=tk.DISABLED)
                        processed = True
                    except queue.Empty:
                        break

                # Force UI update if we processed any messages
                if processed:
                    self.root.update_idletasks()

            except Exception as e:
                print(f"Error consuming log: {e}")
                import traceback
                traceback.print_exc()

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