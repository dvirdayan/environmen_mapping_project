import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import time
from datetime import datetime
import threading


class AdminDashboard(ttk.Frame):
    """Admin dashboard for monitoring all connected clients"""

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
        self.update_interval = 1.0  # Update every second

        self.setup_ui()

    def setup_ui(self):
        """Setup the admin dashboard UI"""
        # Main container
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Admin Dashboard - Network Monitor",
                                font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 10))

        # Stats summary frame
        stats_frame = ttk.LabelFrame(main_frame, text="Global Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))

        # Create stats grid
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)

        # Total clients
        ttk.Label(stats_grid, text="Connected Clients:", font=("Helvetica", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, padx=5)
        self.total_clients_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.total_clients_var, font=("Helvetica", 10)).grid(
            row=0, column=1, sticky=tk.W, padx=5)

        # Total packets
        ttk.Label(stats_grid, text="Total Packets:", font=("Helvetica", 10, "bold")).grid(
            row=0, column=2, sticky=tk.W, padx=20)
        self.total_packets_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.total_packets_var, font=("Helvetica", 10)).grid(
            row=0, column=3, sticky=tk.W, padx=5)

        # Packets per second
        ttk.Label(stats_grid, text="Packets/sec:", font=("Helvetica", 10, "bold")).grid(
            row=0, column=4, sticky=tk.W, padx=20)
        self.pps_var = tk.StringVar(value="0")
        ttk.Label(stats_grid, textvariable=self.pps_var, font=("Helvetica", 10)).grid(
            row=0, column=5, sticky=tk.W, padx=5)

        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Connected Clients Tab
        clients_tab = ttk.Frame(self.notebook)
        self.notebook.add(clients_tab, text="Connected Clients")
        self.setup_clients_tab(clients_tab)

        # Protocol Distribution Tab
        protocol_tab = ttk.Frame(self.notebook)
        self.notebook.add(protocol_tab, text="Protocol Distribution")
        self.setup_protocol_tab(protocol_tab)

        # Environment Stats Tab
        env_tab = ttk.Frame(self.notebook)
        self.notebook.add(env_tab, text="Environment Stats")
        self.setup_environment_tab(env_tab)

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(control_frame, text="Refresh Now",
                   command=self.request_admin_stats).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Stats",
                   command=self.export_stats).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Stats",
                   command=self.clear_stats).pack(side=tk.LEFT, padx=5)

        # Auto-refresh checkbox
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(control_frame, text="Auto Refresh",
                        variable=self.auto_refresh_var).pack(side=tk.LEFT, padx=20)

    def setup_clients_tab(self, parent):
        """Setup the connected clients tab"""
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
        self.clients_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Context menu
        self.create_client_context_menu()

    def setup_protocol_tab(self, parent):
        """Setup the protocol distribution tab"""
        # Create two frames - one for global stats, one for per-client
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Global protocol stats
        global_frame = ttk.LabelFrame(paned, text="Global Protocol Distribution", padding="10")
        paned.add(global_frame, weight=1)

        # Protocol treeview
        columns = ("protocol", "count", "percentage", "rate")
        self.protocol_tree = ttk.Treeview(global_frame, columns=columns, show="headings", height=10)

        self.protocol_tree.heading("protocol", text="Protocol")
        self.protocol_tree.heading("count", text="Total Count")
        self.protocol_tree.heading("percentage", text="Percentage")
        self.protocol_tree.heading("rate", text="Rate/sec")

        self.protocol_tree.column("protocol", width=100)
        self.protocol_tree.column("count", width=100)
        self.protocol_tree.column("percentage", width=100)
        self.protocol_tree.column("rate", width=100)

        self.protocol_tree.pack(fill=tk.BOTH, expand=True)

        # Per-client protocol frame
        client_frame = ttk.LabelFrame(paned, text="Per-Client Protocol Breakdown", padding="10")
        paned.add(client_frame, weight=1)

        # Client protocol treeview
        columns = ("client", "tcp", "udp", "http", "https", "other")
        self.client_protocol_tree = ttk.Treeview(client_frame, columns=columns, show="headings", height=10)

        self.client_protocol_tree.heading("client", text="Client")
        self.client_protocol_tree.heading("tcp", text="TCP")
        self.client_protocol_tree.heading("udp", text="UDP")
        self.client_protocol_tree.heading("http", text="HTTP")
        self.client_protocol_tree.heading("https", text="HTTPS")
        self.client_protocol_tree.heading("other", text="Other")

        self.client_protocol_tree.pack(fill=tk.BOTH, expand=True)

    def setup_environment_tab(self, parent):
        """Setup the environment statistics tab"""
        # Environment stats treeview
        columns = ("environment", "clients", "packets", "top_protocol", "activity")
        self.env_tree = ttk.Treeview(parent, columns=columns, show="headings")

        self.env_tree.heading("environment", text="Environment")
        self.env_tree.heading("clients", text="Active Clients")
        self.env_tree.heading("packets", text="Total Packets")
        self.env_tree.heading("top_protocol", text="Top Protocol")
        self.env_tree.heading("activity", text="Activity Level")

        self.env_tree.column("environment", width=150)
        self.env_tree.column("clients", width=100)
        self.env_tree.column("packets", width=100)
        self.env_tree.column("top_protocol", width=100)
        self.env_tree.column("activity", width=120)

        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.env_tree.yview)
        self.env_tree.configure(yscrollcommand=scrollbar.set)

        self.env_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_client_context_menu(self):
        """Create context menu for client actions"""
        self.context_menu = tk.Menu(self.clients_tree, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.view_client_details)
        self.context_menu.add_command(label="Disconnect Client", command=self.disconnect_client)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Info", command=self.copy_client_info)

        self.clients_tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """Show context menu"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def request_admin_stats(self):
        """Request admin statistics from server"""
        if self.backend and hasattr(self.backend, 'request_admin_stats'):
            self.backend.request_admin_stats()

    def update_admin_data(self, admin_data):
        """Update dashboard with admin data from server"""
        current_time = time.time()
        if current_time - self.last_update < 0.5:  # Throttle updates
            return

        self.last_update = current_time

        # Update client data
        if 'clients' in admin_data:
            self.client_data = admin_data['clients']
            self.update_clients_display()

        # Update protocol counts
        if 'global_protocols' in admin_data:
            self.global_protocol_counts = admin_data['global_protocols']
            self.update_protocol_display()

        # Update environment data
        if 'environments' in admin_data:
            self.update_environment_display(admin_data['environments'])

        # Update summary stats
        self.update_summary_stats()

    def update_clients_display(self):
        """Update the clients treeview"""
        # Clear existing items
        for item in self.clients_tree.get_children():
            self.clients_tree.delete(item)

        # Add clients
        for client_id, client_info in self.client_data.items():
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
                rate = count / max(1, time.time() - self.last_update)

                self.protocol_tree.insert("", tk.END, values=(
                    protocol, count, f"{percentage:.1f}%", f"{rate:.1f}"
                ))

    def update_environment_display(self, env_data):
        """Update environment statistics display"""
        # Clear existing items
        for item in self.env_tree.get_children():
            self.env_tree.delete(item)

        # Add environment stats
        for env_name, env_info in env_data.items():
            client_count = len(env_info.get('clients', {}))
            packet_count = env_info.get('packet_count', 0)

            # Find top protocol
            protocols = env_info.get('protocol_counts', {})
            if protocols:
                top_protocol = max(protocols.items(), key=lambda x: x[1])[0]
            else:
                top_protocol = "N/A"

            # Activity level
            if packet_count > 1000:
                activity = "High"
            elif packet_count > 100:
                activity = "Medium"
            elif packet_count > 0:
                activity = "Low"
            else:
                activity = "Idle"

            self.env_tree.insert("", tk.END, values=(
                env_name, client_count, packet_count, top_protocol, activity
            ))

    def update_summary_stats(self):
        """Update summary statistics"""
        total_clients = len([c for c in self.client_data.values() if c.get('connected', False)])
        total_packets = sum(self.global_protocol_counts.values())

        self.total_clients_var.set(str(total_clients))
        self.total_packets_var.set(str(total_packets))

        # Calculate packets per second (rough estimate)
        if hasattr(self, '_last_packet_count'):
            pps = (total_packets - self._last_packet_count) / max(1, time.time() - self.last_update)
            self.pps_var.set(f"{pps:.1f}")
        self._last_packet_count = total_packets

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

    def disconnect_client(self):
        """Disconnect selected client (admin action)"""
        selected = self.clients_tree.selection()
        if not selected:
            return

        item = self.clients_tree.item(selected[0])
        username = item['values'][0]

        # Confirm action
        from tkinter import messagebox
        if messagebox.askyesno("Disconnect Client",
                               f"Are you sure you want to disconnect {username}?"):
            if self.backend and hasattr(self.backend, 'admin_disconnect_client'):
                self.backend.admin_disconnect_client(username)

    def copy_client_info(self):
        """Copy selected client information to clipboard"""
        selected = self.clients_tree.selection()
        if not selected:
            return

        item = self.clients_tree.item(selected[0])
        info = f"Username: {item['values'][0]}, IP: {item['values'][1]}, Packets: {item['values'][3]}"

        self.clipboard_clear()
        self.clipboard_append(info)

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
                'total_packets': self.total_packets_var.get()
            }

            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)

            from tkinter import messagebox
            messagebox.showinfo("Export Complete", f"Stats exported to {filename}")

    def clear_stats(self):
        """Clear all statistics (admin action)"""
        from tkinter import messagebox
        if messagebox.askyesno("Clear Stats",
                               "Are you sure you want to clear all statistics?"):
            if self.backend and hasattr(self.backend, 'admin_clear_stats'):
                self.backend.admin_clear_stats()