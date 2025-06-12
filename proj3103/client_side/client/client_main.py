import tkinter as tk
import sys
import os
import json
import argparse
import traceback
import tempfile
from pathlib import Path

# Import the UI and integration components
try:
    from client_dashboard import PacketCaptureClientUI
    from pie_chart import integrate_pie_chart_to_ui
    from capture_backend import PacketCaptureBackend
    from environment_selector import enhance_client_ui_with_environment_selector
    from proj3103.client_side.admin.admin_dashboard import AdminDashboard
except ImportError as e:
    print(f"WARNING: Some imports failed: {e}")
    print("Some features may not be available")


    # Create dummy classes if imports fail
    class PacketCaptureClientUI:
        def __init__(self, root):
            self.root = root
            self.backend = None
            print("Using basic UI fallback")


    def integrate_pie_chart_to_ui(ui_class):
        return ui_class


    def enhance_client_ui_with_environment_selector(ui_class):
        return ui_class


    class OptimizedPacketCaptureBackend:
        def __init__(self, ui=None):
            print("Using basic backend fallback")
            self.ui = ui
            self.username = None
            self.environments = []
            self.is_running = False

        def configure(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)
            print(f"Backend configured with: {kwargs}")

        def start(self):
            self.is_running = True
            print("Backend started (fallback mode)")
            if self.ui:
                self.ui.log_message("Backend started in fallback mode")

        def stop(self):
            self.is_running = False
            print("Backend stopped")
            if self.ui:
                self.ui.log_message("Backend stopped")

        def get_environments(self):
            return self.environments or []

# Add the current directory to the path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up debug logging
DEBUG = True


def debug_log(message):
    """Print debug messages if debugging is enabled"""
    if DEBUG:
        print(f"[DEBUG] {message}")


def safe_cleanup_temp_file(file_path, delay_seconds=5):
    """Safely cleanup temp file after a delay"""
    import threading
    import time

    def cleanup():
        try:
            time.sleep(delay_seconds)
            if os.path.exists(file_path):
                os.unlink(file_path)
                debug_log(f"Cleaned up temp file: {file_path}")
        except Exception as e:
            debug_log(f"Could not cleanup temp file {file_path}: {e}")

    cleanup_thread = threading.Thread(target=cleanup, daemon=True)
    cleanup_thread.start()


def load_config_safely(config_path):
    """load configuration from file with error handling"""
    config = {
        'username': None,
        'user_id': None,
        'session_token': None,
        'is_admin': False,
        'environments': []
    }

    try:
        if not os.path.exists(config_path):
            debug_log(f"Config file does not exist: {config_path}")
            return config

        debug_log(f"Loading config file: {config_path}")

        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                debug_log("Config file is empty")
                return config

            debug_log(f"Raw config content: {content[:200]}...")

            try:
                loaded_config = json.loads(content)
                debug_log(f"Successfully parsed JSON config")

                # Safely extract values with defaults
                config['username'] = loaded_config.get('username')
                config['user_id'] = loaded_config.get('user_id')
                config['session_token'] = loaded_config.get('session_token')
                config['is_admin'] = loaded_config.get('is_admin', False)

                # Handle environments safely
                environments = loaded_config.get('environments', [])
                if isinstance(environments, list):
                    for env in environments:
                        if isinstance(env, dict):
                            env_name = env.get('env_name')
                            env_password = env.get('env_password')
                            if env_name and env_password:
                                config['environments'].append({
                                    'env_name': env_name,
                                    'env_password': env_password,
                                    'is_admin': env.get('is_admin', False)
                                })

                                # Update global admin status
                                if env.get('is_admin', False):
                                    config['is_admin'] = True

                debug_log(f"Loaded config: username={config['username']}, "
                          f"environments={len(config['environments'])}, "
                          f"is_admin={config['is_admin']}")

            except json.JSONDecodeError as e:
                debug_log(f"JSON decode error: {e}")
                debug_log("Using default config")

    except Exception as e:
        debug_log(f"Error loading config file: {e}")
        debug_log(traceback.format_exc())

    # Ensure we have at least one environment
    if not config['environments']:
        config['environments'] = [{
            'env_name': 'default',
            'env_password': 'default_password',
            'is_admin': False
        }]
        debug_log("Added default environment")

    return config


def create_enhanced_ui_class(is_admin=False):
    """Create an enhanced UI class with admin support"""

    class AdminEnhancedUI(PacketCaptureClientUI):
        def __init__(self, root):
            try:
                super().__init__(root)
                self.is_admin = is_admin
                self.admin_dashboard = None
                debug_log(f"AdminEnhancedUI initialized, is_admin={is_admin}")
            except Exception as e:
                debug_log(f"Error initializing AdminEnhancedUI: {e}")
                raise

        def show_admin_dashboard(self):
            """Show the admin dashboard in a new tab"""
            if not self.is_admin or self.admin_dashboard:
                return

            try:
                # Check if we have the notebook widget
                if not hasattr(self, 'notebook'):
                    debug_log("No notebook widget found, cannot add admin tab")
                    return

                # Create admin tab
                admin_frame = ttk.Frame(self.notebook)
                self.notebook.add(admin_frame, text="🔧 Admin Dashboard")

                # Create admin dashboard if available
                try:
                    self.admin_dashboard = AdminDashboard(admin_frame, backend=self.backend)
                    self.admin_dashboard.pack(fill=tk.BOTH, expand=True)
                    debug_log("Admin dashboard created successfully")
                except Exception as e:
                    debug_log(f"Could not create admin dashboard: {e}")
                    # Create a simple admin placeholder
                    tk.Label(admin_frame, text="Admin Dashboard\n(Limited functionality)",
                             font=('Arial', 12)).pack(expand=True)

                # Switch to admin tab
                self.notebook.select(admin_frame)

                # Request initial admin stats if backend supports it
                if self.backend and hasattr(self.backend, 'request_admin_stats'):
                    try:
                        self.backend.request_admin_stats()
                    except Exception as e:
                        debug_log(f"Could not request admin stats: {e}")

            except Exception as e:
                debug_log(f"Error showing admin dashboard: {e}")

        def update_admin_stats(self, admin_data):
            """Update admin dashboard with new data"""
            try:
                if self.admin_dashboard and hasattr(self.admin_dashboard, 'update_admin_data'):
                    self.admin_dashboard.update_admin_data(admin_data)
            except Exception as e:
                debug_log(f"Error updating admin stats: {e}")

        def set_backend(self, backend):
            """Override to add admin functionality"""
            try:
                super().set_backend(backend)
                debug_log("Backend set in AdminEnhancedUI")

                # If admin, schedule dashboard creation
                if self.is_admin:
                    self.root.after(2000, self.show_admin_dashboard)  # Delay to ensure UI is ready

                    # Set admin callback if supported
                    if hasattr(backend, 'set_admin_stats_callback'):
                        backend.set_admin_stats_callback(self.update_admin_stats)

            except Exception as e:
                debug_log(f"Error setting backend in AdminEnhancedUI: {e}")
                # Fallback - set backend directly
                self.backend = backend

        def log_message(self, message):
            """Enhanced log message with error handling"""
            try:
                super().log_message(message)
            except Exception as e:
                print(f"[LOG] {message}")  # Fallback to console
                debug_log(f"Error logging message: {e}")

    return AdminEnhancedUI


def enhance_client_ui_with_environments(ui_class):
    """Enhance the UI class with multi-environment support"""
    debug_log("Enhancing UI with multi-environment support")

    # Store original methods
    original_methods = {}

    if hasattr(ui_class, 'update_protocol_counts'):
        original_methods['update_protocol_counts'] = ui_class.update_protocol_counts

    if hasattr(ui_class, 'set_backend'):
        original_methods['set_backend'] = ui_class.set_backend

    def update_protocol_counts_for_env(self, protocol_counts, environment=None):
        """Update protocol counts for a specific environment"""
        try:
            # Update global counts first
            if 'update_protocol_counts' in original_methods:
                original_methods['update_protocol_counts'](self, protocol_counts)
            else:
                # Fallback implementation
                if hasattr(self, 'protocol_counts'):
                    self.protocol_counts.update(protocol_counts)
                    if hasattr(self, 'protocol_labels'):
                        for protocol, count in protocol_counts.items():
                            if protocol in self.protocol_labels:
                                self.protocol_labels[protocol].set(str(count))

            # Log environment-specific update
            if environment:
                debug_log(f"Updated protocol counts for environment: {environment}")

        except Exception as e:
            debug_log(f"Error updating protocol counts: {e}")

    def process_packet_with_environments(self, packet_data, environments=None):
        """Process packet with environment information"""
        try:
            # Call original process_packet if available
            if hasattr(self, 'process_packet'):
                self.process_packet(packet_data)

            # Log environment information
            if environments and hasattr(self, 'log_message'):
                env_str = ", ".join(environments) if isinstance(environments, list) else str(environments)
                packet_id = packet_data.get('packet_id', 'unknown')
                self.log_message(f"Packet {packet_id} processed for environments: {env_str}")

        except Exception as e:
            debug_log(f"Error processing packet with environments: {e}")

    def enhanced_set_backend(self, backend):
        """Enhanced version of set_backend that handles environments safely"""
        try:
            # Call original set_backend if it exists
            if 'set_backend' in original_methods:
                original_methods['set_backend'](self, backend)
            else:
                # Basic fallback implementation
                self.backend = backend

            # Update user info from backend if available
            if hasattr(backend, 'username') and backend.username:
                env_names = []
                if hasattr(backend, 'environments') and backend.environments:
                    env_names = [env.get('env_name') for env in backend.environments
                                 if isinstance(env, dict) and env.get('env_name')]

                primary_env = env_names[0] if env_names else "default"

                # Update user info if method exists
                if hasattr(self, 'update_user_info'):
                    self.update_user_info(username=backend.username, environment=primary_env)

                debug_log(f"Backend set with username: {backend.username}, environment: {primary_env}")

        except Exception as e:
            debug_log(f"Error in enhanced_set_backend: {e}")
            # Minimal fallback
            self.backend = backend

    # Safely add new methods to the class
    ui_class.update_protocol_counts_for_env = update_protocol_counts_for_env
    ui_class.process_packet_with_environments = process_packet_with_environments
    ui_class.set_backend = enhanced_set_backend

    return ui_class


def main():
    """Main entry point with comprehensive error handling"""

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Packet Capture Client')
    parser.add_argument('--config', type=str, help='Path to user config file')
    parser.add_argument('--server', type=str, default="176.9.45.249", help='Server hostname or IP')
    parser.add_argument('--port', type=int, default=9007, help='Server port')
    parser.add_argument('--distribution', type=str, default="all",
                        choices=["all", "round-robin", "random", "specific"],
                        help='Packet distribution strategy')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    try:
        args = parser.parse_args()
    except Exception as e:
        print(f"Error parsing arguments: {e}")
        args = argparse.Namespace(
            config=None, server="176.9.45.249", port=9007,
            distribution="all", debug=True
        )

    if args.debug:
        global DEBUG
        DEBUG = True

    debug_log("Starting packet capture client...")
    debug_log(f"Arguments: server={args.server}, port={args.port}, config={args.config}")

    # Load configuration
    config = {'username': None, 'environments': [], 'is_admin': False}

    if args.config:
        config = load_config_safely(args.config)
        # Schedule cleanup of temp config file
        if os.path.exists(args.config) and 'tmp' in args.config:
            safe_cleanup_temp_file(args.config)

    # Extract configuration values
    username = config.get('username')
    environments = config.get('environments', [])
    is_admin = config.get('is_admin', False)

    # Create account info
    account_info = None
    if config.get('user_id'):
        account_info = {
            "user_id": config.get('user_id'),
            "username": username,
            "is_admin": is_admin,
            "environment": environments[0].get('env_name') if environments else None
        }

    debug_log(f"Configuration loaded - Username: {username}, Admin: {is_admin}, "
              f"Environments: {len(environments)}")

    # Create the root window
    try:
        root = tk.Tk()
        window_title = f"Network Packet Capture - {username or 'Anonymous'}"
        if is_admin:
            window_title += " [ADMIN]"
        root.title(window_title)

        # Set window properties
        root.geometry("1000x800")
        root.minsize(800, 600)

        debug_log("Root window created successfully")

    except Exception as e:
        print(f"FATAL: Could not create root window: {e}")
        return

    try:
        # Create enhanced UI class
        debug_log("Creating enhanced UI class...")
        base_ui_class = create_enhanced_ui_class(is_admin)

        # Apply enhancements safely
        try:
            enhanced_ui_class = enhance_client_ui_with_environment_selector(
                enhance_client_ui_with_environments(
                    integrate_pie_chart_to_ui(base_ui_class)
                )
            )
        except Exception as e:
            debug_log(f"Error applying UI enhancements: {e}")
            enhanced_ui_class = base_ui_class

        # Create the UI instance
        debug_log("Creating UI instance...")
        ui = enhanced_ui_class(root)
        debug_log("UI created successfully")

        # Create the backend
        debug_log("Creating backend instance...")
        backend = PacketCaptureBackend(ui=ui)
        debug_log("Backend created successfully")

        # Configure the backend
        debug_log("Configuring backend...")
        backend.configure(
            capture_interface=None,  # Will be selected in UI
            server_host=args.server,
            server_port=args.port,
            username=username,
            environments=environments,
            account_info=account_info,
            distribution_strategy=args.distribution
        )
        debug_log("Backend configured successfully")

        # Connect UI and backend
        debug_log("Connecting UI and backend...")
        ui.set_backend(backend)
        debug_log("UI and backend connected")

        # Log startup information
        if hasattr(ui, 'log_message'):
            ui.log_message(f"Application started - User: {username or 'Anonymous'}")
            if is_admin:
                ui.log_message("*** ADMIN MODE ACTIVE ***")
            ui.log_message(f"Environments: {[env.get('env_name') for env in environments]}")
            ui.log_message(f"Distribution strategy: {args.distribution}")
            ui.log_message(f"Server: {args.server}:{args.port}")
            if DEBUG:
                ui.log_message("DEBUG MODE ENABLED")

        # Additional UI setup for admin users
        if is_admin and hasattr(ui, 'log_message'):
            ui.log_message("Admin dashboard will be available after initialization")

        debug_log("Starting main loop...")
        root.mainloop()
        debug_log("Main loop ended")

    except Exception as e:
        error_msg = f"Error during application setup: {e}"
        print(error_msg)
        debug_log(f"Exception traceback: {traceback.format_exc()}")

        # Try to show error dialog
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Application Error", f"Failed to start application:\n\n{str(e)}")
        except:
            print("Could not show error dialog")

        # Keep console open for debugging
        if DEBUG:
            input("Press Enter to exit...")


if __name__ == "__main__":
    try:
        # Import ttk at module level
        from tkinter import ttk

        main()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}")
        print("Detailed traceback:")
        traceback.print_exc()
        if DEBUG:
            input("Press Enter to exit...")