import tkinter as tk
from tkinter import ttk


class PacketMonitorUI:
    def __init__(self, root, server):
        self.root = root
        self.server = server
        self.ui_running = True

        # **LAG FIX: Add throttling for server UI updates**
        self.last_ui_update = 0
        self.ui_update_interval = 3.0  # Only update every 3 seconds

        # Register callback for server data updates
        self.server.register_ui_callback(self.schedule_update)

        self.setup_ui()

    def setup_ui(self):
        """Set up the UI components"""
        self.root.title("Packet Monitor Server")
        self.root.geometry("1000x700")

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

        # **LAG FIX: Less frequent periodic updates**
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
        columns = ("username", "ip", "port", "packets", "environments", "account", "status")
        client_tree = ttk.Treeview(client_frame, columns=columns, show="headings")

        # Define column headings
        client_tree.heading("username", text="Username")
        client_tree.heading("ip", text="Client IP")
        client_tree.heading("port", text="Port")
        client_tree.heading("packets", text="Packet Count")
        client_tree.heading("environments", text="Environments")
        client_tree.heading("account", text="Account")
        client_tree.heading("status", text="Status")

        # Define column widths
        client_tree.column("username", width=150)
        client_tree.column("ip", width=120)
        client_tree.column("port", width=60)
        client_tree.column("packets", width=80)
        client_tree.column("environments", width=150)
        client_tree.column("account", width=150)
        client_tree.column("status", width=80)

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

    def format_account_info(self, account_info):
        """Format account information for display in the UI"""
        # Handle empty account info
        if account_info is None or account_info == {}:
            return "N/A"

        # If it's already a string, return it
        if isinstance(account_info, str):
            return account_info

        # If it's a dictionary, try to extract meaningful info
        if isinstance(account_info, dict):
            # First check for user_id and username which is in our structure
            user_id = account_info.get('user_id')
            username = account_info.get('username')
            env = account_info.get('environment')

            if username or user_id:
                parts = []
                if username:
                    parts.append(f"User: {username}")
                if user_id:
                    parts.append(f"ID: {user_id}")
                if env:
                    parts.append(f"Env: {env}")
                return " | ".join(parts)

            # Try standard fields as fallback
            name = account_info.get('name', '')
            email = account_info.get('email', '')
            id = account_info.get('id', '')

            # Return formatted string with available info
            if name and email:
                return f"{name} ({email})"
            elif name:
                return name
            elif email:
                return email
            elif id:
                return f"ID: {id}"
            else:
                # If none of the above fields exist, find any non-empty values
                result = []
                for key, value in account_info.items():
                    if value is not None and value != "":
                        result.append(f"{key}: {value}")

                if result:
                    return ", ".join(result)

        # If all else fails, return string representation but limit length
        result = str(account_info)
        if len(result) > 30:
            return result[:27] + "..."
        return result

    def update_client_display(self):
        """Update the client display with current information"""
        # **LAG FIX: Add throttling**
        import time
        current_time = time.time()
        if current_time - self.last_ui_update < self.ui_update_interval:
            return

        try:
            # Get a copy of the current clients data
            clients_copy = self.server.get_clients_data()

            # Get all current items in the treeview
            current_items = set(self.client_tree.get_children())

            # Update existing clients and add new ones
            for client_addr, client_info in clients_copy.items():
                client_id = f"{client_addr[0]}:{client_addr[1]}"
                username = client_info.get('username', 'Unknown')

                # Get environments for this client
                client_environments = client_info.get('environments', [])
                environment_str = ", ".join(client_environments) if client_environments else "default"

                # Check if this client is already in the treeview
                item_exists = False
                for item_id in current_items:
                    values = self.client_tree.item(item_id, "values")
                    if len(values) >= 3 and values[1] == client_addr[0] and values[2] == str(client_addr[1]):
                        # Format account info properly
                        account_info = client_info.get('account_info', 'Unknown')
                        formatted_account = self.format_account_info(account_info)

                        # Update existing item
                        self.client_tree.item(
                            item_id,
                            values=(
                                username,
                                client_addr[0],
                                client_addr[1],
                                client_info['packet_count'],
                                environment_str,
                                formatted_account,
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
                            username,
                            client_addr[0],
                            client_addr[1],
                            client_info['packet_count'],
                            environment_str,
                            client_info.get('account_info', 'Unknown'),
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

            self.last_ui_update = current_time

        except Exception as e:
            print(f"Error updating client display: {e}")

    def schedule_update(self):
        """Schedule an update on the main thread"""
        # **LAG FIX: Don't schedule immediate updates, let periodic handle it**
        pass

    def schedule_periodic_update(self):
        """Schedule periodic updates"""
        if self.ui_running:
            # **LAG FIX: Much longer intervals between updates**
            self.root.after(5000, self.periodic_update)  # 5 seconds instead of 1

    def periodic_update(self):
        """Periodic update function that reschedules itself"""
        if self.ui_running:
            try:
                self.update_display()
            except Exception as e:
                print(f"Error in periodic update: {e}")

            # **LAG FIX: Schedule next update**
            self.root.after(5000, self.periodic_update)  # 5 seconds

    def update_display(self):
        """Update both client and protocol displays"""
        # Check for new environments and create tabs if needed
        self.update_environment_tabs()

        # Update the main "All Traffic" display
        self.update_client_display()
        self.update_protocol_display()

        # **LAG FIX: Only update environment tabs occasionally**
        # Update each environment tab less frequently
        for env_name in list(self.env_tabs.keys())[:2]:  # Only update first 2 env tabs
            try:
                self.update_environment_client_display(env_name)
                self.update_environment_protocol_display(env_name)
            except Exception as e:
                print(f"Error updating environment {env_name}: {e}")

    def update_environment_client_display(self, env_name):
        """Update the client display for a specific environment"""
        try:
            # Get all clients data
            clients_copy = self.server.get_clients_data()

            # Filter clients for this environment
            env_clients = {}
            for addr, info in clients_copy.items():
                client_environments = info.get('environments', [])
                if env_name in client_environments:
                    env_clients[addr] = info

            # Get the client tree for this environment
            client_tree = self.env_tabs[env_name]['client_tree']

            # **LAG FIX: Limit number of items processed**
            items_to_process = list(env_clients.items())[:10]  # Only process first 10 clients

            # Clear and rebuild (simpler than complex updating)
            for item in client_tree.get_children():
                client_tree.delete(item)

            # Add all clients for this environment
            for client_addr, client_info in items_to_process:
                username = client_info.get('username', 'Unknown')
                client_environments = client_info.get('environments', [])
                environment_str = ", ".join(client_environments) if client_environments else "default"

                client_tree.insert(
                    "",
                    tk.END,
                    values=(
                        username,
                        client_addr[0],
                        client_addr[1],
                        client_info['packet_count'],
                        environment_str,
                        client_info.get('account_info', 'Unknown'),
                        "Connected" if client_info['connected'] else "Disconnected"
                    )
                )

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

                # **LAG FIX: Simple try/except for item updates**
                try:
                    protocol_tree.item(
                        item_id,
                        values=(protocol, count, f"{percentage:.1f}%")
                    )
                except tk.TclError:
                    # Item doesn't exist, skip it
                    pass

        except Exception as e:
            print(f"Error updating environment protocol display for {env_name}: {e}")

    def update_environment_tabs(self):
        """Check for new environments and create tabs if needed"""
        # **LAG FIX: Limit how many environment tabs we create**
        try:
            # Get current environments
            env_data = self.server.get_environment_data()

            # Only create tabs for first 3 environments to avoid UI overload
            env_names = list(env_data.keys())[:3]

            # Create tabs for new environments
            for env_name in env_names:
                if env_name != "default" and env_name not in self.env_tabs:
                    # Create a new tab for this environment
                    env_frame = ttk.Frame(self.notebook)
                    self.notebook.add(env_frame, text=f"Env: {env_name}")

                    # Setup the environment tab
                    self.setup_traffic_tab(env_frame, env_name)
        except Exception as e:
            print(f"Error updating environment tabs: {e}")

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

                # **LAG FIX: Simple try/except for updates**
                try:
                    self.protocol_tree.item(
                        item_id,
                        values=(protocol, count, f"{percentage:.1f}%")
                    )
                except tk.TclError:
                    # Item doesn't exist, skip it
                    pass

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