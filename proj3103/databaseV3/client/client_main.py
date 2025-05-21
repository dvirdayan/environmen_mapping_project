import tkinter as tk
import sys
import os
import json
import argparse
import traceback  # Added for detailed error tracing

# Import the UI and the pie chart integration
from client_front import PacketCaptureClientUI
from pie_chart import integrate_pie_chart_to_ui
from capture_backend import StablePacketCaptureBackend
from capture_upgrades import upgrade_to_real_capture
from packet_handler import SimplePacketHandler
from environment_selector import enhance_client_ui_with_environment_selector

# Add the current directory to the path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up debug logging
DEBUG = True  # Set to True to enable detailed logging


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

                        # Log with masked password for security
                        masked_pw = '*' * len(env_password) if env_password else None
                        debug_log(f"Loading environment: {env_name}, password: {masked_pw}")

                        environments.append({
                            'env_name': env_name,
                            'env_password': env_password
                        })

                        # Add environment info to account_info
                        if account_info:
                            account_info["environment"] = env_name
                            account_info["is_admin"] = env.get('is_admin', False)

                    print(f"Loaded {len(environments)} environments for user '{username}'")
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

    # Create the root window
    root = tk.Tk()
    root.title(f"Network Packet Capture - {username or 'Anonymous'}")

    # Enhance the UI class with pie chart and multi-environment support
    EnhancedPacketCaptureClientUI = enhance_client_ui_with_environment_selector(
        enhance_client_ui_with_environments(
            integrate_pie_chart_to_ui(PacketCaptureClientUI)
        )
    )

    # Create the enhanced UI
    ui = EnhancedPacketCaptureClientUI(root)

    # Create the backend with debug mode enabled
    backend = StablePacketCaptureBackend(ui=ui)

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
    print(f"Configured backend with: username={username}, environments={[env.get('env_name') for env in environments]}")
    print(f"Account info: {account_info}")

    # Connect UI and backend
    debug_log("Setting backend in UI...")
    ui.set_backend(backend)

    # Optional: Set a timer to upgrade to real packet capture after connection stability is confirmed
    # This will switch from test packets to real packet capture after 10 seconds
    debug_log("Scheduling upgrade to real packet capture...")
    root.after(10000, lambda: upgrade_to_real_capture(backend))

    # Log startup information
    if ui:
        ui.log_message(f"Application started - User: {username}")
        ui.log_message(f"Environments: {[env.get('env_name') for env in environments]}")
        ui.log_message(f"Distribution strategy: {distribution_strategy}")
        ui.log_message(f"Connecting to server: {server_host}:{server_port}")
        ui.log_message("DEBUG MODE ENABLED - Check console for detailed logs")

    # Start the main loop
    debug_log("Starting main loop...")
    root.mainloop()


def enhance_client_ui_with_environments(ui_class):
    """Enhance the UI class with multi-environment support"""
    debug_log("Enhancing UI with multi-environment support")

    # Store original update protocol counts method
    original_update_protocol_counts = ui_class.update_protocol_counts

    # Add a new method for environment-specific protocol counts
    def update_protocol_counts_for_env(self, protocol_counts, environment=None):
        """Update protocol counts for a specific environment"""
        # Update global counts using the original method
        original_update_protocol_counts(self, protocol_counts)

        # If environment is specified, check if we have environment tabs
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
        self.process_packet(packet_data)

        # If environments are specified, log them
        if environments:
            env_str = ", ".join(environments)
            self.log_message(f"Packet {packet_data.get('packet_id', 'unknown')} sent to environments: {env_str}")

    # Add method to create environment tabs
    def create_environment_tab(self, environment):
        """Create a new tab for an environment"""
        if not hasattr(self, 'environment_tabs'):
            self.environment_tabs = {}

        # Skip if this environment already has a tab
        if environment in self.environment_tabs:
            return

        # Find the notebook by searching through the UI hierarchy
        notebook = None
        # First look in the root window's children
        for child in self.root.winfo_children():
            # Look for frames that might contain our notebook
            if isinstance(child, tk.Frame) or isinstance(child, tk.Frame):
                # Check this frame's children for the notebook
                for grandchild in child.winfo_children():
                    # Look for the notebook in grandchildren
                    if isinstance(grandchild, tk.Notebook):
                        notebook = grandchild
                        break
                    # Also check one level deeper if needed
                    if isinstance(grandchild, (tk.Frame, tk.Frame, tk.LabelFrame, tk.LabelFrame)):
                        for great_grandchild in grandchild.winfo_children():
                            if isinstance(great_grandchild, tk.Notebook):
                                notebook = great_grandchild
                                break
                if notebook:
                    break

        if not notebook:
            self.log_message(f"Could not find notebook to add environment tab: {environment}")
            return

        try:
            # Import ttk inside function to avoid potential import issues
            from tkinter import ttk

            # Create a new frame for this environment
            env_frame = ttk.Frame(notebook, padding="10")
            notebook.add(env_frame, text=f"Env: {environment}")

            # Create protocol count labels for this environment
            protocol_frame = ttk.LabelFrame(env_frame, text=f"Protocol Distribution - {environment}", padding="5")
            protocol_frame.pack(fill=tk.X, pady=5)

            protocol_labels = {}
            for i, protocol in enumerate(['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'Other']):
                ttk.Label(protocol_frame, text=f"{protocol}:").grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
                var = tk.StringVar(value="0")
                protocol_labels[protocol] = var
                ttk.Label(protocol_frame, textvariable=var, width=8).grid(row=i, column=1, sticky=tk.E, padx=5, pady=2)

            # Store the labels in the environment tabs dictionary
            self.environment_tabs[environment] = {
                'frame': env_frame,
                'protocol_labels': protocol_labels
            }

            self.log_message(f"Created environment tab for: {environment}")
        except Exception as e:
            self.log_message(f"Error creating environment tab: {str(e)}")
            if DEBUG:
                print(f"[DEBUG] Error in create_environment_tab: {str(e)}")
                print(traceback.format_exc())

    # Update the UI class with the new methods
    ui_class.update_protocol_counts_for_env = update_protocol_counts_for_env
    ui_class.process_packet_with_environments = process_packet_with_environments
    ui_class.create_environment_tab = create_environment_tab

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

        # Create tabs for each environment
        if hasattr(backend, 'get_environments'):
            environments = backend.get_environments()
            if DEBUG:
                print(f"[DEBUG] Retrieved environments from backend: {environments}")
            for env in environments:
                if hasattr(self, 'create_environment_tab'):
                    if DEBUG:
                        print(f"[DEBUG] Creating tab for environment: {env}")
                    self.create_environment_tab(env)

    ui_class.set_backend = enhanced_set_backend

    return ui_class


if __name__ == "__main__":
    # Enable exception tracing
    try:
        main()
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}")
        print("Detailed traceback:")
        traceback.print_exc()