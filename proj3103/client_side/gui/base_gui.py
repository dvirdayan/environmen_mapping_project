import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os
import json
import tempfile
import threading
import time

# Import the database client instead of direct database access
from proj3103.client_side.database_client import DatabaseClient

# Import GUI components (assuming these exist from your original code)
from proj3103.client_side.gui.auth_frames import AuthFrame, LoginFrame, RegisterFrame
from proj3103.client_side.gui.dashboard import DashboardFrame


class CredentialManagerGUI:
    def __init__(self, root, server_host='localhost', server_port=9008):
        self.root = root
        self.root.title("Credential Manager")
        self.root.geometry("800x500")
        self.root.resizable(True, True)

        # Initialize database client instead of direct database connection
        self.db_client = DatabaseClient(server_host, server_port)

        # Keep track of temporary files for cleanup
        self.temp_files = []
        self.client_processes = []

        # Set up the main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create the initial login/register frame
        self.show_auth_frame()

        # Set up a protocol for when the window is closed
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def cleanup_temp_files(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files[:]:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    print(f"Cleaned up temp file: {temp_file}")
                self.temp_files.remove(temp_file)
            except Exception as e:
                print(f"Could not cleanup temp file {temp_file}: {e}")

    def cleanup_processes(self):
        """Clean up any running client processes"""
        for process in self.client_processes[:]:
            try:
                if process.poll() is None:  # Process is still running
                    process.terminate()
                    # Wait a bit for graceful termination
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()  # Force kill if needed
                self.client_processes.remove(process)
            except Exception as e:
                print(f"Error cleaning up process: {e}")

    def on_close(self):
        """Handle closing the application."""
        if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
            # Clean up processes and temp files
            self.cleanup_processes()
            self.cleanup_temp_files()

            # Logout from database
            if self.db_client.is_authenticated():
                self.db_client.logout()

            self.root.destroy()

    def clear_frame(self, frame):
        """Clear all widgets from a frame."""
        for widget in frame.winfo_children():
            widget.destroy()

    def show_auth_frame(self):
        """Display the authentication frame with login and register options."""
        self.clear_frame(self.main_frame)
        auth_frame = AuthFrame(self.main_frame, self.show_login_form, self.show_register_form, self.on_close)

    def show_login_form(self):
        """Display the login form."""
        self.clear_frame(self.main_frame)
        login_frame = LoginFrame(self.main_frame, self.login_user, self.show_auth_frame)
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: login_frame.trigger_login())

    def show_register_form(self):
        """Display the registration form."""
        self.clear_frame(self.main_frame)
        RegisterFrame(self.main_frame, self.register_user, self.show_auth_frame)

    def login_user(self, username, password):
        """Attempt to log in a user."""
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        # Attempt authentication through the client
        if self.db_client.authenticate(username, password):
            self.root.unbind('<Return>')  # Unbind the Enter key
            self.show_main_dashboard()
            messagebox.showinfo("Login Successful", f"Welcome {self.db_client.username}!")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password, or server unavailable.")

    def create_config_file(self):
        """Create a temporary configuration file with user information"""
        try:
            # Get user environments from the database client
            user_environments = self.db_client.get_environments()
            if user_environments is None:
                user_environments = []

            # Create configuration data
            config_data = {
                "username": self.db_client.username,
                "user_id": self.db_client.user_id,
                "session_token": self.db_client.session_token,
                "is_admin": self.db_client.is_admin,
                "environments": []
            }

            # Add environment data
            for env in user_environments:
                if isinstance(env, dict):
                    env_config = {
                        "env_name": env.get('env_name', env.get('name', 'default')),
                        "env_password": env.get('env_password', env.get('password', 'default')),
                        "is_admin": env.get('is_admin', False)
                    }
                    config_data["environments"].append(env_config)

            # If no environments, add a default one
            if not config_data["environments"]:
                config_data["environments"].append({
                    "env_name": "default",
                    "env_password": "default_password",
                    "is_admin": False
                })

            # Create temporary config file with proper cleanup
            temp_fd, temp_path = tempfile.mkstemp(suffix='.json', prefix='packet_client_config_')

            try:
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as temp_file:
                    json.dump(config_data, temp_file, indent=2, ensure_ascii=False)

                # Add to cleanup list
                self.temp_files.append(temp_path)

                print(f"Created config file: {temp_path}")
                print(f"Config data: {json.dumps(config_data, indent=2)}")

                return temp_path, config_data

            except Exception as e:
                # If writing failed, clean up the file descriptor
                try:
                    os.close(temp_fd)
                    os.unlink(temp_path)
                except:
                    pass
                raise e

        except Exception as e:
            print(f"Error creating config file: {e}")
            import traceback
            traceback.print_exc()
            return None, None

    def start_client(self):
        """Start the packet capture client by creating a config file with user info."""
        try:
            # Find the client script
            client_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client",
                                       "client_main.py")

            if not os.path.exists(client_path):
                # Try alternative paths
                alternative_paths = [
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "client_main.py"),
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client_main.py"),
                    "client_main.py"
                ]

                client_path = None
                for alt_path in alternative_paths:
                    if os.path.exists(alt_path):
                        client_path = alt_path
                        break

                if not client_path:
                    messagebox.showerror("Error", f"Client script not found. Searched paths:\n" +
                                         "\n".join(alternative_paths))
                    return

            print(f"Using client script: {client_path}")

            # Create configuration file
            config_file_path, config_data = self.create_config_file()

            if not config_file_path:
                messagebox.showerror("Error", "Failed to create configuration file.")
                return

            # Prepare command line arguments
            args = [
                sys.executable, client_path,
                "--config", config_file_path,
                "--server", self.db_client.host,
                "--port", str(self.db_client.port),
                "--debug"  # Enable debug mode for troubleshooting
            ]

            print(f"Starting client with args: {' '.join(args)}")

            # Start the client process with better error handling
            try:
                process = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=os.path.dirname(client_path) if client_path != "client_main.py" else None
                )

                # Add to process list for cleanup
                self.client_processes.append(process)

                # Create a thread to monitor the process and handle output
                def monitor_process():
                    try:
                        stdout, stderr = process.communicate(timeout=2)  # Quick check
                        if process.returncode != 0:
                            print(f"Client process stderr: {stderr}")
                            print(f"Client process stdout: {stdout}")
                    except subprocess.TimeoutExpired:
                        # Process is running normally
                        print("Client process started successfully")
                    except Exception as e:
                        print(f"Error monitoring process: {e}")

                monitor_thread = threading.Thread(target=monitor_process, daemon=True)
                monitor_thread.start()

                messagebox.showinfo(
                    "Client Started",
                    f"The packet capture client has been started for user '{self.db_client.username}'.\n\n"
                    f"Environments: {[env['env_name'] for env in config_data['environments']]}\n\n"
                    f"The client window should appear shortly. If it doesn't appear within 10 seconds, "
                    f"check the console for error messages."
                )

            except FileNotFoundError:
                messagebox.showerror("Error", f"Python executable not found or client script not accessible.\n"
                                              f"Python: {sys.executable}\n"
                                              f"Client: {client_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start client process: {str(e)}")
                print(f"Detailed error: {e}")
                import traceback
                traceback.print_exc()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start client: {str(e)}")
            import traceback
            print(f"Full error traceback: {traceback.format_exc()}")

    def start_admin_dashboard(self):
        """Start the admin dashboard by creating a config file with user info."""
        try:
            # Find the admin dashboard script
            dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../admin", "standalone_admin_dashboard.py")

            if not os.path.exists(dashboard_path):
                # Try alternative paths
                alternative_paths = [
                    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "standalone_admin_dashboard.py"),
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "standalone_admin_dashboard.py"),
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin", "standalone_admin_dashboard.py"),
                    "standalone_admin_dashboard.py"
                ]

                dashboard_path = None
                for alt_path in alternative_paths:
                    if os.path.exists(alt_path):
                        dashboard_path = alt_path
                        break

                if not dashboard_path:
                    messagebox.showerror("Error", f"Admin dashboard script not found. Searched paths:\n" +
                                         "\n".join(alternative_paths))
                    return

            print(f"Using admin dashboard script: {dashboard_path}")

            # Create configuration file
            config_file_path, config_data = self.create_config_file()

            if not config_file_path:
                messagebox.showerror("Error", "Failed to create configuration file.")
                return

            # Prepare command line arguments for admin dashboard
            args = [
                sys.executable, dashboard_path,
                "--config", config_file_path,
                "--server", "localhost",  # Admin dashboard connects to capture server
                "--port", "9007"  # Default capture server port
            ]

            print(f"Starting admin dashboard with args: {' '.join(args)}")

            # Start the admin dashboard process
            try:
                process = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=os.path.dirname(dashboard_path) if dashboard_path != "standalone_admin_dashboard.py" else None
                )

                # Add to process list for cleanup
                self.client_processes.append(process)

                # Create a thread to monitor the process and handle output
                def monitor_process():
                    try:
                        stdout, stderr = process.communicate(timeout=2)  # Quick check
                        if process.returncode != 0:
                            print(f"Admin dashboard process stderr: {stderr}")
                            print(f"Admin dashboard process stdout: {stdout}")
                    except subprocess.TimeoutExpired:
                        # Process is running normally
                        print("Admin dashboard process started successfully")
                    except Exception as e:
                        print(f"Error monitoring admin dashboard process: {e}")

                monitor_thread = threading.Thread(target=monitor_process, daemon=True)
                monitor_thread.start()

                messagebox.showinfo(
                    "Admin Dashboard Started",
                    f"The admin dashboard has been started for user '{self.db_client.username}'.\n\n"
                    f"Admin Status: {'Yes' if self.db_client.is_admin else 'No'}\n"
                    f"Environments: {[env['env_name'] for env in config_data['environments']]}\n\n"
                    f"The admin dashboard window should appear shortly. If it doesn't appear within 10 seconds, "
                    f"check the console for error messages."
                )

            except FileNotFoundError:
                messagebox.showerror("Error", f"Python executable not found or admin dashboard script not accessible.\n"
                                              f"Python: {sys.executable}\n"
                                              f"Dashboard: {dashboard_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start admin dashboard process: {str(e)}")
                print(f"Detailed error: {e}")
                import traceback
                traceback.print_exc()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start admin dashboard: {str(e)}")
            import traceback
            print(f"Full error traceback: {traceback.format_exc()}")

    def register_user(self, username, password, confirm_password, is_admin=False):
        """Register a new user."""
        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # Use database client to register user
        if self.db_client.register_user(username, password, is_admin):
            messagebox.showinfo("Success",
                                f"User '{username}' registered successfully{' as Admin' if is_admin else ''}!")
            self.show_login_form()
        else:
            messagebox.showerror("Error",
                                 f"Username '{username}' already exists or server error occurred. Please choose another username.")

    def logout_user(self):
        """Log out the current user."""
        if self.db_client.logout():
            self.show_auth_frame()

    def show_main_dashboard(self):
        """Display the main dashboard after login."""
        self.clear_frame(self.main_frame)

        # Get all current user information from the database client
        user_info = self.db_client.get_user_info()

        DashboardFrame(
            self.main_frame,
            user_info['username'],
            user_info['is_admin'],
            self.logout_user,
            user_info['user_id'],
            self.db_client,
            self.start_client,
            self.start_admin_dashboard  # Add admin dashboard callback
        )

    # Helper methods that delegate to database client
    def get_current_user_id(self):
        """Get current user ID from database client."""
        return self.db_client.user_id if self.db_client.is_authenticated() else None

    def get_current_username(self):
        """Get current username from database client."""
        return self.db_client.username if self.db_client.is_authenticated() else None

    def get_is_admin(self):
        """Get admin status from database client."""
        return self.db_client.is_admin if self.db_client.is_authenticated() else False

    def get_user_environments(self):
        """Get user environments from database client."""
        return self.db_client.get_environments()

    def add_environment(self, env_name, env_password):
        """Add environment through database client."""
        return self.db_client.add_environment(env_name, env_password)

    def join_environment(self, env_name, env_password):
        """Join environment through database client."""
        return self.db_client.join_environment(env_name, env_password)

    def store_packet_data(self, env_name, packet_data):
        """Store packet data through database client."""
        return self.db_client.store_packet_data(env_name, packet_data)

    def get_packet_data(self, env_name, limit=100):
        """Get packet data through database client."""
        return self.db_client.get_packet_data(env_name, limit)


def main():
    """Main entry point for the Credential Manager application."""
    root = tk.Tk()

    # Optional: Set icon if available
    try:
        root.iconbitmap('tree.ico')
    except:
        pass  # Ignore if icon file doesn't exist

    # You can customize server connection here
    app = CredentialManagerGUI(root, server_host='localhost', server_port=9008)
    root.mainloop()


if __name__ == "__main__":
    main()