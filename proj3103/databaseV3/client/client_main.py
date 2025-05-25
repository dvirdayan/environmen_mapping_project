import tkinter as tk
import sys
import os
import json
import argparse
import traceback

# Import the UI and integration components
from client_front import PacketCaptureClientUI
from pie_chart import integrate_pie_chart_to_ui
from capture_backend import OptimizedPacketCaptureBackend
from environment_selector import enhance_client_ui_with_environment_selector
from proj3103.databaseV3.admin.admin_dashboard import AdminDashboard  # Import admin dashboard
# Add the current directory to the path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


# Set up debug logging
DEBUG = True


def debug_log(message):
    """Print debug messages if debugging is enabled"""
    if DEBUG:
        print(f"[DEBUG] {message}")


def main():
    # Parse command line arguments for config
    parser = argparse.ArgumentParser(description='Packet Capture Client')
    parser.add_argument('--config', type=str, help='Path to user config file')
    parser.add_argument('--server', type=str, default="localhost", help='Server hostname or IP')
    parser.add_argument('--port', type=int, default=9007, help='Server port')
    parser.add_argument('--distribution', type=str, default="all",
                        choices=["all", "round-robin", "random", "specific"],
                        help='Packet distribution strategy')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    if args.debug:
        global DEBUG
        DEBUG = True

    # Default settings
    username = None
    environments = []
    account_info = None
    is_admin = False  # Track admin status
    server_host = args.server
    server_port = args.port
    distribution_strategy = args.distribution

    debug_log(f"Starting client with server={server_host}, port={server_port}")

    # If config file is provided, load settings from it
    if args.config and os.path.exists(args.config):
        try:
            debug_log(f"Loading config file: {args.config}")
            with open(args.config, 'r') as f:
                config_content = f.read()
                debug_log(f"Raw config content: {config_content}")
                config = json.loads(config_content)
                debug_log(f"Parsed config: {json.dumps(config, indent=2)}")

                username = config.get('username')
                user_id = config.get('user_id')
                debug_log(f"Loaded user: {username}, ID: {user_id}")

                # Create account_info dictionary
                if user_id:
                    account_info = {
                        "user_id": user_id,
                        "username": username
                    }
                    debug_log(f"Created account_info: {account_info}")

                # Get environments from the config
                config_environments = config.get('environments', [])
                debug_log(f"Found {len(config_environments)} environments in config")

                if config_environments:
                    for env in config_environments:
                        # Add each environment to our list
                        env_name = env.get('env_name')
                        env_password = env.get('env_password')

                        # Check if this environment makes the user an admin
                        if env.get('is_admin', False):
                            is_admin = True
                            debug_log(f"User is admin of environment: {env_name}")

                        # Log with masked password for security
                        masked_pw = '*' * len(env_password) if env_password else None
                        debug_log(
                            f"Loading environment: {env_name}, password: {masked_pw}, is_admin: {env.get('is_admin', False)}")

                        environments.append({
                            'env_name': env_name,
                            'env_password': env_password
                        })

                    # Update account_info with admin status
                    if account_info:
                        account_info["is_admin"] = is_admin
                        # Use the first environment for display
                        account_info["environment"] = environments[0].get('env_name') if environments else None

                    print(f"Loaded {len(environments)} environments for user '{username}' (Admin: {is_admin})")
                    debug_log(f"Environment names: {[env.get('env_name') for env in environments]}")
                else:
                    print(f"No environments found for user '{username}', using default")
                    debug_log("No environments found, setting default")
                    environments = [{'env_name': 'default', 'env_password': 'default_password'}]
        except Exception as e:
            print(f"Error loading config: {e}")
            debug_log(f"Exception during config loading: {str(e)}")
            debug_log(traceback.format_exc())
            # Set defaults if config loading fails
            environments = [{'env_name': 'default', 'env_password': 'default_password'}]
            account_info = None
    else:
        # Set defaults if no config
        debug_log("No config file provided or file not found. Using defaults.")
        environments = [{'env_name': 'default', 'env_password': 'default_password'}]
        print("No config file provided, using default environment")

    print(f"Configuration: Username={username}, Environments={[env.get('env_name') for env in environments]}")
    print(f"Distribution strategy: {distribution_strategy}")
    if account_info:
        print(f"Account info: {account_info}")
    if is_admin:
        print("*** ADMIN MODE ENABLED ***")

    # Create the root window
    root = tk.Tk()
    window_title = f"Network Packet Capture - {username or 'Anonymous'}"
    if is_admin:
        window_title += " [ADMIN]"
    root.title(window_title)

    try:
        # Enhance the UI class with pie chart and multi-environment support
        debug_log("Enhancing UI class...")

        # Create a custom enhanced UI class that includes admin support
        class AdminEnhancedUI(PacketCaptureClientUI):
            def __init__(self, root):
                super().__init__(root)
                self.is_admin = is_admin
                self.admin_dashboard = None

            def show_admin_dashboard(self):
                """Show the admin dashboard in a new tab"""
                if not self.is_admin or self.admin_dashboard:
                    return

                # Create admin tab
                admin_frame = ttk.Frame(self.notebook)
                self.notebook.add(admin_frame, text="🔧 Admin Dashboard")

                # Create admin dashboard
                self.admin_dashboard = AdminDashboard(admin_frame, backend=self.backend)
                self.admin_dashboard.pack(fill=tk.BOTH, expand=True)

                # Switch to admin tab
                self.notebook.select(admin_frame)

                # Request initial admin stats
                if self.backend:
                    self.backend.request_admin_stats()

            def update_admin_stats(self, admin_data):
                """Update admin dashboard with new data"""
                if self.admin_dashboard:
                    self.admin_dashboard.update_admin_data(admin_data)

            def set_backend(self, backend):
                """Override to add admin functionality"""
                super().set_backend(backend)

                # If admin, show dashboard after UI is ready
                if self.is_admin:
                    self.root.after(1000, self.show_admin_dashboard)

                    # Set admin callback
                    if hasattr(backend, 'set_admin_stats_callback'):
                        backend.set_admin_stats_callback(self.update_admin_stats)

        # Use the admin-enhanced UI class
        enhanced_ui_class = enhance_client_ui_with_environment_selector(
            enhance_client_ui_with_environments(
                integrate_pie_chart_to_ui(AdminEnhancedUI)
            )
        )

        # Create the enhanced UI
        debug_log("Creating UI instance...")
        ui = enhanced_ui_class(root)

        # Create the backend
        debug_log("Creating backend instance...")
        backend = OptimizedPacketCaptureBackend(ui=ui)

        # Configure with the environment info and account info
        debug_log("Configuring backend...")
        backend.configure(
            capture_interface=None,  # Will be selected in UI
            server_host=server_host,
            server_port=server_port,
            username=username,
            environments=environments,
            account_info=account_info,
            distribution_strategy=distribution_strategy
        )

        # Log the configuration details
        print(
            f"Configured backend with: username={username}, environments={[env.get('env_name') for env in environments]}")
        print(f"Account info: {account_info}")

        # Connect UI and backend
        debug_log("Setting backend in UI...")
        ui.set_backend(backend)

        # Log startup information
        if ui:
            ui.log_message(f"Application started - User: {username}")
            if is_admin:
                ui.log_message("*** ADMIN MODE ACTIVE ***")
                ui.log_message("Admin dashboard will load shortly...")
            ui.log_message(f"Environments: {[env.get('env_name') for env in environments]}")
            ui.log_message(f"Distribution strategy: {distribution_strategy}")
            ui.log_message(f"Connecting to server: {server_host}:{server_port}")
            if DEBUG:
                ui.log_message("DEBUG MODE ENABLED - Check console for detailed logs")

        # Start the main loop
        debug_log("Starting main loop...")
        root.mainloop()

    except Exception as e:
        print(f"Error during UI setup: {e}")
        debug_log(traceback.format_exc())

        # Try to show a simple error dialog
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Error", f"Failed to start application: {e}")
        except:
            pass


def enhance_client_ui_with_environments(ui_class):
    """Enhance the UI class with multi-environment support"""
    debug_log("Enhancing UI with multi-environment support")

    # Store original update protocol counts method
    if hasattr(ui_class, 'update_protocol_counts'):
        original_update_protocol_counts = ui_class.update_protocol_counts
    else:
        def original_update_protocol_counts(self, protocol_counts):
            pass

    # Add a new method for environment-specific protocol counts
    def update_protocol_counts_for_env(self, protocol_counts, environment=None):
        """Update protocol counts for a specific environment"""
        # Update global counts using the original method
        original_update_protocol_counts(self, protocol_counts)

        # If environment is specified and we have environment tabs
        if environment and hasattr(self, 'environment_tabs'):
            # If this environment doesn't have a tab yet, create one
            if environment not in self.environment_tabs:
                if hasattr(self, 'create_environment_tab'):
                    self.create_environment_tab(environment)

            # Update the environment tab
            if environment in self.environment_tabs:
                for protocol, count in protocol_counts.items():
                    if protocol in self.environment_tabs[environment]['protocol_labels']:
                        self.environment_tabs[environment]['protocol_labels'][protocol].set(str(count))

    # Add method to process packets with environment info
    def process_packet_with_environments(self, packet_data, environments=None):
        """Process packet with environment information"""
        # First call the original process_packet method
        if hasattr(self, 'process_packet'):
            self.process_packet(packet_data)

        # If environments are specified, log them
        if environments and hasattr(self, 'log_message'):
            env_str = ", ".join(environments)
            self.log_message(f"Packet {packet_data.get('packet_id', 'unknown')} sent to environments: {env_str}")

    # Update the UI class with the new methods
    ui_class.update_protocol_counts_for_env = update_protocol_counts_for_env
    ui_class.process_packet_with_environments = process_packet_with_environments

    # Store the original set_backend method
    original_set_backend = None
    if hasattr(ui_class, 'set_backend'):
        original_set_backend = ui_class.set_backend

    def enhanced_set_backend(self, backend):
        """Enhanced version of set_backend that handles environments"""
        if DEBUG:
            print("[DEBUG] Setting backend in enhanced UI")

        # Call the original method first if it exists
        if original_set_backend:
            original_set_backend(self, backend)
        else:
            # Basic implementation if original doesn't exist
            self.backend = backend

        # Create tabs for each environment if supported
        if hasattr(backend, 'get_environments'):
            environments = backend.get_environments()
            if DEBUG:
                print(f"[DEBUG] Retrieved environments from backend: {environments}")

    ui_class.set_backend = enhanced_set_backend

    return ui_class


if __name__ == "__main__":
    # Add import for ttk at module level
    from tkinter import ttk

    # Enable exception tracing
    try:
        main()
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}")
        print("Detailed traceback:")
        traceback.print_exc()