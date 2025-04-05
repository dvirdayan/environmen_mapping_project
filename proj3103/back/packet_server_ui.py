import tkinter as tk
from tkinter import ttk
import threading
import time


class PacketMonitorUI:
    def __init__(self, root, server):
        self.root = root
        self.server = server
        self.ui_running = True

        # Register callback for server data updates
        self.server.register_ui_callback(self.schedule_update)

        self.setup_ui()

    def setup_ui(self):
        """Set up the UI components"""
        self.root.title("Packet Monitor Server")
        self.root.geometry("1000x700")  # Increased size for additional information

        # Create notebook (tabbed interface) for environments
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create a default tab for all traffic
        self.all_traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.all_traffic_frame, text="All Traffic")

        # Setup the all traffic tab
        self.setup_traffic_tab(self.all_traffic_frame, "all")

        # Environment tabs will be added dynamically
        self.env_tabs = {}  # To track environment tabs

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Server running. Waiting for connections...")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Set up a periodic update for the UI
        self.schedule_periodic_update()

        # Set up window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_traffic_tab(self, parent_frame, env_name):
        """Set up a tab for traffic (either all or environment-specific)"""
        # Create main frame
        main_frame = ttk.Frame(parent_frame)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create a frame for the client list
        client_frame = ttk.LabelFrame(main_frame, text="Connected Clients", padding="10")
        client_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Create a treeview to display client information
        columns = ("ip", "port", "packets", "environment", "status")
        client_tree = ttk.Treeview(client_frame, columns=columns, show="headings")

        # Define column headings
        client_tree.heading("ip", text="Client IP")
        client_tree.heading("port", text="Port")
        client_tree.heading("packets", text="Packet Count")
        client_tree.heading("environment", text="Environment")
        client_tree.heading("status", text="Status")

        # Define column widths
        client_tree.column("ip", width=150)
        client_tree.column("port", width=100)
        client_tree.column("packets", width=100)
        client_tree.column("environment", width=100)
        client_tree.column("status", width=100)

        # Add a scrollbar
        scrollbar = ttk.Scrollbar(client_frame, orient=tk.VERTICAL, command=client_tree.yview)
        client_tree.configure(yscroll=scrollbar.set)

        # Pack the treeview and scrollbar
        client_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create a frame for protocol statistics
        protocol_frame = ttk.LabelFrame(main_frame, text="Protocol Statistics", padding="10")
        protocol_frame.pack(fill=tk.BOTH, expand=True)

        # Create a treeview for protocol statistics
        protocol_columns = ("protocol", "count", "percentage")
        protocol_tree = ttk.Treeview(protocol_frame, columns=protocol_columns, show="headings")

        # Define protocol column headings
        protocol_tree.heading("protocol", text="Protocol")
        protocol_tree.heading("count", text="Packet Count")
        protocol_tree.heading("percentage", text="Percentage")

        # Define protocol column widths
        protocol_tree.column("protocol", width=150)
        protocol_tree.column("count", width=100)
        protocol_tree.column("percentage", width=100)

        # Add a scrollbar for protocol treeview
        protocol_scrollbar = ttk.Scrollbar(protocol_frame, orient=tk.VERTICAL, command=protocol_tree.yview)
        protocol_tree.configure(yscroll=protocol_scrollbar.set)

        # Pack the protocol treeview and scrollbar
        protocol_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        protocol_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Add initial protocol items
        if env_name == "all":
            protocol_counts = self.server.get_protocol_data()
        else:
            protocol_counts = self.server.get_environment_protocol_data(env_name)

        for protocol in protocol_counts:
            protocol_tree.insert("", tk.END, iid=f"{env_name}_{protocol}", values=(protocol, 0, "0.0%"))

        # Store the trees in a dictionary
        if env_name == "all":
            self.client_tree = client_tree
            self.protocol_tree = protocol_tree
        else:
            self.env_tabs[env_name] = {
                'client_tree': client_tree,
                'protocol_tree': protocol_tree
            }

    def schedule_update(self):
        """Schedule an update on the main thread"""
        if self.ui_running:
            self.root.after(10, self.update_display)

    def schedule_periodic_update(self):
        """Schedule periodic updates every second"""
        if self.ui_running:
            self.root.after(1000, self.periodic_update)

    def periodic_update(self):
        """Periodic update function that reschedules itself"""
        if self.ui_running:
            self.update_display()
            self.root.after(1000, self.periodic_update)

    def update_display(self):
        """Update both client and protocol displays"""
        # Check for new environments and create tabs if needed
        self.update_environment_tabs()

        # Update the main "All Traffic" display
        self.update_client_display()
        self.update_protocol_display()

        # Update each environment tab
        for env_name in self.env_tabs:
            self.update_environment_client_display(env_name)
            self.update_environment_protocol_display(env_name)

    def update_environment_client_display(self, env_name):
        """Update the client display for a specific environment"""
        try:
            # Get all clients data
            clients_copy = self.server.get_clients_data()

            # Filter clients for this environment
            env_clients = {addr: info for addr, info in clients_copy.items()
                           if info.get('environment') == env_name}

            # Get the client tree for this environment
            client_tree = self.env_tabs[env_name]['client_tree']

            # Get all current items in the treeview
            current_items = set(client_tree.get_children())

            # Update existing clients and add new ones for this environment
            for client_addr, client_info in env_clients.items():
                # Check if this client is already in the treeview
                item_exists = False
                for item_id in current_items:
                    values = client_tree.item(item_id, "values")
                    if values[0] == client_addr[0] and values[1] == str(client_addr[1]):
                        # Update existing item
                        client_tree.item(
                            item_id,
                            values=(
                                client_addr[0],
                                client_addr[1],
                                client_info['packet_count'],
                                env_name,
                                "Connected" if client_info['connected'] else "Disconnected"
                            )
                        )
                        current_items.remove(item_id)
                        item_exists = True
                        break

                # Add new item if it doesn't exist
                if not item_exists:
                    client_tree.insert(
                        "",
                        tk.END,
                        values=(
                            client_addr[0],
                            client_addr[1],
                            client_info['packet_count'],
                            env_name,
                            "Connected" if client_info['connected'] else "Disconnected"
                        )
                    )

            # Remove items that no longer exist
            for item_id in current_items:
                client_tree.delete(item_id)

        except Exception as e:
            print(f"Error updating environment client display for {env_name}: {e}")

    def update_environment_protocol_display(self, env_name):
        """Update the protocol statistics display for a specific environment"""
        try:
            # Get protocol counts for this environment
            protocol_counts = self.server.get_environment_protocol_data(env_name)

            # Calculate total packets for percentage
            total_packets = sum(protocol_counts.values())

            # Get the protocol tree for this environment
            protocol_tree = self.env_tabs[env_name]['protocol_tree']

            # Update protocol statistics
            for protocol, count in protocol_counts.items():
                percentage = (count / total_packets * 100) if total_packets > 0 else 0

                # Use the correct item identifier
                item_id = f"{env_name}_{protocol}"

                protocol_tree.item(
                    item_id,
                    values=(protocol, count, f"{percentage:.1f}%")
                )

        except Exception as e:
            print(f"Error updating environment protocol display for {env_name}: {e}")

    def update_environment_tabs(self):
        """Check for new environments and create tabs if needed"""
        # Get current environments
        env_data = self.server.get_environment_data()

        # Create tabs for new environments
        for env_name in env_data:
            if env_name != "default" and env_name not in self.env_tabs:
                # Create a new tab for this environment
                env_frame = ttk.Frame(self.notebook)
                self.notebook.add(env_frame, text=f"Environment: {env_name}")

                # Setup the environment tab
                self.setup_traffic_tab(env_frame, env_name)

    def update_client_display(self):
        """Update the client display with current information"""
        try:
            # Get a copy of the current clients data
            clients_copy = self.server.get_clients_data()

            # Get all current items in the treeview
            current_items = set(self.client_tree.get_children())

            # Update existing clients and add new ones
            for client_addr, client_info in clients_copy.items():
                client_id = f"{client_addr[0]}:{client_addr[1]}"

                # Check if this client is already in the treeview
                item_exists = False
                for item_id in current_items:
                    if self.client_tree.item(item_id, "values")[0] == client_addr[0] and \
                            self.client_tree.item(item_id, "values")[1] == str(client_addr[1]):
                        # Update existing item
                        self.client_tree.item(
                            item_id,
                            values=(
                                client_addr[0],
                                client_addr[1],
                                client_info['packet_count'],
                                client_info.get('environment', 'default'),
                                "Connected" if client_info['connected'] else "Disconnected"
                            )
                        )
                        current_items.remove(item_id)
                        item_exists = True
                        break

                # Add new item if it doesn't exist
                if not item_exists:
                    self.client_tree.insert(
                        "",
                        tk.END,
                        values=(
                            client_addr[0],
                            client_addr[1],
                            client_info['packet_count'],
                            client_info.get('environment', 'default'),
                            "Connected" if client_info['connected'] else "Disconnected"
                        )
                    )

            # Remove items that no longer exist in the clients dictionary
            for item_id in current_items:
                self.client_tree.delete(item_id)

            # Update status bar with total count
            total_clients = len([c for c in clients_copy.values() if c['connected']])
            total_packets = sum(c['packet_count'] for c in clients_copy.values())
            self.status_var.set(f"Active clients: {total_clients} | Total packets: {total_packets}")

        except Exception as e:
            print(f"Error updating client display: {e}")

    def update_protocol_display(self):
        """Update the protocol statistics display"""
        try:
            # Get a copy of the current protocol counts
            protocol_counts_copy = self.server.get_protocol_data()

            # Calculate total packets for percentage
            total_packets = sum(protocol_counts_copy.values())

            # Update protocol statistics
            for protocol, count in protocol_counts_copy.items():
                percentage = (count / total_packets * 100) if total_packets > 0 else 0

                # Use the correct item identifier format
                item_id = f"all_{protocol}"

                self.protocol_tree.item(
                    item_id,
                    values=(protocol, count, f"{percentage:.1f}%")
                )

        except Exception as e:
            print(f"Error updating protocol display: {e}")

    def on_close(self):
        """Handle UI window close event"""
        self.ui_running = False
        self.server.stop()
        self.root.destroy()


def start_ui(server):
    """Start the UI with a reference to the server"""
    root = tk.Tk()
    app = PacketMonitorUI(root, server)
    root.mainloop()


if __name__ == "__main__":
    # If this file is run directly (which shouldn't be the case),
    # print an error message
    print("This file should be imported by packet_server.py, not run directly.")
    print("Please run packet_server.py instead.")