import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import time
from datetime import datetime
import threading


class AdminDashboard(ttk.Frame):
    """Admin dashboard for monitoring all connected clients - Enhanced with debugging"""

    def __init__(self, parent, backend=None):
        super().__init__(parent)
        self.backend = backend
        self.parent = parent

        # Data storage
        self.client_data = {}
        self.global_protocol_counts = {
            'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0,
            'FTP': 0, 'SMTP': 0, 'Other': 0
        }

        # Update tracking
        self.last_update = 0
        self.update_interval = 1.0
        self.stats_requests_sent = 0
        self.stats_responses_received = 0

        # Debug info
        self.debug_messages = []
        self.max_debug_messages = 100

        self.setup_ui()
        self.start_auto_refresh()

    def setup_ui(self):
        """Setup the admin dashboard UI"""
        # Main container
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title with debug info
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(title_frame, text="Admin Dashboard - Network Monitor",
                                font=("Helvetica", 16, "bold"))
        title_label.pack(side=tk.LEFT)

        # Debug info in title
        self.debug_info_var = tk.StringVar(value="Debug: Starting...")
        debug_label = ttk.Label(title_frame, textvariable=self.debug_info_var,
                                font=("Helvetica", 9), foreground="blue")
        debug_label.pack(side=tk.RIGHT)

        # Stats summary frame
        stats_frame = ttk.LabelFrame(main_frame, text="Global Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))

        # Create stats grid
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)

        # Stats variables
        ttk.Label(stats_grid, text="Connected Clients:", font=("Helvetica", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, padx=5)
        self.total_clients_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.total_clients_var, font=("Helvetica", 10)).grid(
            row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(stats_grid, text="Total Packets:", font=("Helvetica", 10, "bold")).grid(
            row=0, column=2, sticky=tk.W, padx=20)
        self.total_packets_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.total_packets_var, font=("Helvetica", 10)).grid(
            row=0, column=3, sticky=tk.W, padx=5)

        ttk.Label(stats_grid, text="Requests/Responses:", font=("Helvetica", 10, "bold")).grid(
            row=0, column=4, sticky=tk.W, padx=20)
        self.requests_var = tk.StringVar(value="0/0")
        ttk.Label(stats_grid, textvariable=self.requests_var, font=("Helvetica", 10)).grid(
            row=0, column=5, sticky=tk.W, padx=5)

        # Last update time
        ttk.Label(stats_grid, text="Last Update:", font=("Helvetica", 10, "bold")).grid(
            row=1, column=0, sticky=tk.W, padx=5)
        self.last_update_var = tk.StringVar(value="Never")
        ttk.Label(stats_grid, textvariable=self.last_update_var, font=("Helvetica", 10)).grid(
            row=1, column=1, sticky=tk.W, padx=5)

        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Connected Clients Tab
        clients_tab = ttk.Frame(self.notebook)
        self.notebook.add(clients_tab, text="Connected Clients")
        self.setup_clients_tab(clients_tab)

        # Debug Tab
        debug_tab = ttk.Frame(self.notebook)
        self.notebook.add(debug_tab, text="Debug Log")
        self.setup_debug_tab(debug_tab)

        # Protocol Distribution Tab
        protocol_tab = ttk.Frame(self.notebook)
        self.notebook.add(protocol_tab, text="Protocol Distribution")
        self.setup_protocol_tab(protocol_tab)

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(control_frame, text="Refresh Now",
                   command=self.request_admin_stats).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Test Connection",
                   command=self.test_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Debug",
                   command=self.clear_debug_log).pack(side=tk.LEFT, padx=5)

        # Auto-refresh checkbox
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(control_frame, text="Auto Refresh (5s)",
                        variable=self.auto_refresh_var).pack(side=tk.LEFT, padx=20)

    def setup_clients_tab(self, parent):
        """Setup the connected clients tab"""
        # Status frame
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, padx=5, pady=5)

        self.client_status_var = tk.StringVar(value="No client data received yet")
        ttk.Label(status_frame, textvariable=self.client_status_var,
                  font=("Helvetica", 10, "italic")).pack()

        # Create treeview for clients
        columns = ("username", "ip", "port", "packets", "protocols", "environments", "status", "uptime")
        self.clients_tree = ttk.Treeview(parent, columns=columns, show="headings", height=15)

        # Configure columns
        self.clients_tree.heading("username", text="Username")
        self.clients_tree.heading("ip", text="IP Address")
        self.clients_tree.heading("port", text="Port")
        self.clients_tree.heading("packets", text="Packets")
        self.clients_tree.heading("protocols", text="Top Protocol")
        self.clients_tree.heading("environments", text="Environments")
        self.clients_tree.heading("status", text="Status")
        self.clients_tree.heading("uptime", text="Uptime")

        # Column widths
        self.clients_tree.column("username", width=120)
        self.clients_tree.column("ip", width=120)
        self.clients_tree.column("port", width=60)
        self.clients_tree.column("packets", width=80)
        self.clients_tree.column("protocols", width=100)
        self.clients_tree.column("environments", width=150)
        self.clients_tree.column("status", width=80)
        self.clients_tree.column("uptime", width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.clients_tree.yview)
        self.clients_tree.configure(yscrollcommand=scrollbar.set)

        # Pack
        self.clients_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

    def setup_debug_tab(self, parent):
        """Setup the debug log tab"""
        # Debug log
        self.debug_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, height=20, width=80)
        self.debug_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add initial debug message
        self.add_debug_message("Admin Dashboard initialized")
        if self.backend:
            self.add_debug_message(f"Backend connected: {type(self.backend).__name__}")
            self.add_debug_message(f"Backend is_admin: {getattr(self.backend, 'is_admin', 'Unknown')}")
            self.add_debug_message(f"Backend username: {getattr(self.backend, 'username', 'Unknown')}")
        else:
            self.add_debug_message("WARNING: No backend provided!")

    def setup_protocol_tab(self, parent):
        """Setup the protocol distribution tab"""
        # Protocol treeview
        columns = ("protocol", "count", "percentage")
        self.protocol_tree = ttk.Treeview(parent, columns=columns, show="headings", height=10)

        self.protocol_tree.heading("protocol", text="Protocol")
        self.protocol_tree.heading("count", text="Total Count")
        self.protocol_tree.heading("percentage", text="Percentage")

        self.protocol_tree.column("protocol", width=100)
        self.protocol_tree.column("count", width=100)
        self.protocol_tree.column("percentage", width=100)

        self.protocol_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def add_debug_message(self, message):
        """Add a debug message to the log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}"

        self.debug_messages.append(full_message)
        if len(self.debug_messages) > self.max_debug_messages:
            self.debug_messages.pop(0)

        # Update debug text widget
        try:
            self.debug_text.insert(tk.END, full_message + "\n")
            self.debug_text.see(tk.END)
        except:
            pass  # Widget might not be ready yet

        print(f"[ADMIN_DEBUG] {full_message}")

    def clear_debug_log(self):
        """Clear the debug log"""
        self.debug_messages.clear()
        self.debug_text.delete(1.0, tk.END)
        self.add_debug_message("Debug log cleared")

    def test_connection(self):
        """Test the connection to backend"""
        self.add_debug_message("Testing connection...")

        if not self.backend:
            self.add_debug_message("ERROR: No backend available")
            return

        # Check backend attributes
        attrs_to_check = ['is_admin', 'username', 'client', 'running', 'connected']
        for attr in attrs_to_check:
            value = getattr(self.backend, attr, 'Not found')
            self.add_debug_message(f"Backend.{attr}: {value}")

        # Test admin stats request
        self.request_admin_stats()

    def start_auto_refresh(self):
        """Start automatic refresh of admin stats"""

        def auto_refresh_worker():
            while True:
                try:
                    if self.auto_refresh_var.get():
                        self.request_admin_stats()
                    time.sleep(5)  # Refresh every 5 seconds
                except Exception as e:
                    self.add_debug_message(f"Auto-refresh error: {e}")
                    time.sleep(5)

        refresh_thread = threading.Thread(target=auto_refresh_worker, daemon=True)
        refresh_thread.start()
        self.add_debug_message("Auto-refresh started (5 second interval)")

    def request_admin_stats(self):
        """Request admin statistics from server"""
        self.stats_requests_sent += 1
        self.requests_var.set(f"{self.stats_requests_sent}/{self.stats_responses_received}")

        self.add_debug_message(f"Requesting admin stats (#{self.stats_requests_sent})")

        if not self.backend:
            self.add_debug_message("ERROR: No backend to request stats from")
            return

        if not hasattr(self.backend, 'request_admin_stats'):
            self.add_debug_message("ERROR: Backend has no request_admin_stats method")
            return

        try:
            self.backend.request_admin_stats()
            self.add_debug_message("Admin stats request sent to backend")
        except Exception as e:
            self.add_debug_message(f"ERROR requesting admin stats: {e}")

    def update_admin_data(self, admin_data):
        """Update dashboard with admin data from server"""
        self.stats_responses_received += 1
        self.requests_var.set(f"{self.stats_requests_sent}/{self.stats_responses_received}")

        current_time = time.time()
        self.last_update = current_time
        self.last_update_var.set(datetime.now().strftime("%H:%M:%S"))

        self.add_debug_message(f"Received admin data (#{self.stats_responses_received})")
        self.add_debug_message(
            f"Data keys: {list(admin_data.keys()) if isinstance(admin_data, dict) else type(admin_data)}")

        # Log the data structure for debugging
        if isinstance(admin_data, dict):
            if 'clients' in admin_data:
                client_count = len(admin_data['clients']) if isinstance(admin_data['clients'], dict) else 0
                self.add_debug_message(f"Clients in data: {client_count}")

                # Log client details
                if isinstance(admin_data['clients'], dict):
                    for client_id, client_info in admin_data['clients'].items():
                        username = client_info.get('username', 'Unknown')
                        ip = client_info.get('ip', 'Unknown')
                        self.add_debug_message(f"  Client {client_id}: {username} @ {ip}")
            else:
                self.add_debug_message("No 'clients' key in admin data")

            if 'global_protocols' in admin_data:
                self.add_debug_message(f"Protocol data: {admin_data['global_protocols']}")

        # Update client data
        if isinstance(admin_data, dict) and 'clients' in admin_data:
            self.client_data = admin_data['clients']
            self.update_clients_display()
        else:
            self.add_debug_message("WARNING: No client data in response")

        # Update protocol counts
        if isinstance(admin_data, dict) and 'global_protocols' in admin_data:
            self.global_protocol_counts = admin_data['global_protocols']
            self.update_protocol_display()

        # Update summary stats
        self.update_summary_stats()

        # Update debug info
        self.debug_info_var.set(
            f"Last update: {datetime.now().strftime('%H:%M:%S')} | Clients: {len(self.client_data)}")

    def update_clients_display(self):
        """Update the clients treeview"""
        # Clear existing items
        for item in self.clients_tree.get_children():
            self.clients_tree.delete(item)

        client_count = len(self.client_data) if isinstance(self.client_data, dict) else 0
        self.add_debug_message(f"Updating client display with {client_count} clients")

        if not self.client_data:
            self.client_status_var.set("No clients connected")
            return

        # Add clients
        displayed_count = 0
        for client_id, client_info in self.client_data.items():
            try:
                username = client_info.get('username', 'Unknown')
                ip = client_info.get('ip', '')
                port = client_info.get('port', '')
                packet_count = client_info.get('packet_count', 0)

                # Find top protocol
                protocols = client_info.get('protocol_counts', {})
                if protocols:
                    top_protocol = max(protocols.items(), key=lambda x: x[1])[0]
                else:
                    top_protocol = "N/A"

                environments = ", ".join(client_info.get('environments', []))
                status = "Connected" if client_info.get('connected', False) else "Disconnected"

                # Calculate uptime
                connect_time = client_info.get('connect_time')
                if connect_time:
                    uptime = self.format_uptime(time.time() - connect_time)
                else:
                    uptime = "N/A"

                self.clients_tree.insert("", tk.END, values=(
                    username, ip, port, packet_count, top_protocol,
                    environments, status, uptime
                ))
                displayed_count += 1

            except Exception as e:
                self.add_debug_message(f"Error displaying client {client_id}: {e}")

        self.client_status_var.set(f"Displaying {displayed_count} clients")
        self.add_debug_message(f"Successfully displayed {displayed_count} clients")

    def update_protocol_display(self):
        """Update protocol distribution display"""
        # Clear existing items
        for item in self.protocol_tree.get_children():
            self.protocol_tree.delete(item)

        # Calculate total
        total_packets = sum(self.global_protocol_counts.values())

        # Add protocol stats
        for protocol, count in sorted(self.global_protocol_counts.items(),
                                      key=lambda x: x[1], reverse=True):
            if count > 0:
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                self.protocol_tree.insert("", tk.END, values=(
                    protocol, count, f"{percentage:.1f}%"
                ))

    def update_summary_stats(self):
        """Update summary statistics"""
        total_clients = len([c for c in self.client_data.values() if c.get('connected', False)]) if isinstance(
            self.client_data, dict) else 0
        total_packets = sum(self.global_protocol_counts.values())

        self.total_clients_var.set(str(total_clients))
        self.total_packets_var.set(str(total_packets))

    def format_uptime(self, seconds):
        """Format uptime in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def view_client_details(self):
        """View detailed information about selected client"""
        selected = self.clients_tree.selection()
        if not selected:
            return

        # Get client info
        item = self.clients_tree.item(selected[0])
        username = item['values'][0]

        # Create detail window
        detail_window = tk.Toplevel(self)
        detail_window.title(f"Client Details - {username}")
        detail_window.geometry("600x400")

        # Add detailed information
        text = tk.Text(detail_window, wrap=tk.WORD, padx=10, pady=10)
        text.pack(fill=tk.BOTH, expand=True)

        # Find client data
        for client_id, client_info in self.client_data.items():
            if client_info.get('username') == username:
                text.insert(tk.END, f"Username: {username}\n")
                text.insert(tk.END, f"IP Address: {client_info.get('ip', 'N/A')}\n")
                text.insert(tk.END, f"Port: {client_info.get('port', 'N/A')}\n")
                text.insert(tk.END, f"Total Packets: {client_info.get('packet_count', 0)}\n")
                text.insert(tk.END, f"Environments: {', '.join(client_info.get('environments', []))}\n")
                text.insert(tk.END, f"\nProtocol Distribution:\n")

                for protocol, count in client_info.get('protocol_counts', {}).items():
                    text.insert(tk.END, f"  {protocol}: {count}\n")

                break

        text.config(state=tk.DISABLED)

    def export_stats(self):
        """Export statistics to file"""
        from tkinter import filedialog

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'clients': self.client_data,
                'global_protocols': self.global_protocol_counts,
                'total_clients': self.total_clients_var.get(),
                'total_packets': self.total_packets_var.get(),
                'debug_messages': self.debug_messages
            }

            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)

            from tkinter import messagebox
            messagebox.showinfo("Export Complete", f"Stats exported to {filename}")