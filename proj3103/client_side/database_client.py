import socket
import json
import logging
from typing import Dict, Any, Optional, List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DatabaseClient:
    def __init__(self, host='176.9.45.249', port=9008):
        self.host = host
        self.port = port
        self.session_token = None
        self.username = None
        self.user_id = None
        self.is_admin = False

    def _send_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send a request to the database server and return the response."""
        try:
            # Create socket connection
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))

            # Send request
            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))

            # Receive response
            response_data = client_socket.recv(4096)
            response = json.loads(response_data.decode('utf-8'))

            client_socket.close()
            return response

        except ConnectionRefusedError:
            logger.error(f"Could not connect to database server at {self.host}:{self.port}")
            return {'success': False, 'error': 'Database server unavailable'}
        except json.JSONDecodeError:
            logger.error("Invalid JSON response from server")
            return {'success': False, 'error': 'Invalid server response'}
        except Exception as e:
            logger.error(f"Error communicating with database server: {e}")
            return {'success': False, 'error': 'Communication error'}

    def register_user(self, username: str, password: str, is_admin: bool = False) -> bool:
        """Register a new user with the database server."""
        request = {
            'action': 'register',
            'username': username,
            'password': password,
            'is_admin': is_admin
        }

        response = self._send_request(request)

        if response.get('success'):
            logger.info(f"Successfully registered user: {username}")
            return True
        else:
            logger.warning(f"Registration failed: {response.get('error', 'Unknown error')}")
            return False

    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with the database server."""
        request = {
            'action': 'authenticate',
            'username': username,
            'password': password
        }

        response = self._send_request(request)

        if response.get('success'):
            self.session_token = response.get('session_token')
            self.username = response.get('username')
            self.user_id = response.get('user_id')
            self.is_admin = response.get('is_admin', False)
            logger.info(f"Successfully authenticated as {username}")
            return True
        else:
            logger.warning(f"Authentication failed: {response.get('error', 'Unknown error')}")
            return False

    def get_environments(self) -> Optional[List[Dict[str, Any]]]:
        """Get user environments from the server."""
        if not self.session_token:
            logger.error("Not authenticated")
            return None

        request = {
            'action': 'get_environments',
            'session_token': self.session_token
        }

        response = self._send_request(request)

        if response.get('success'):
            return response.get('environments', [])
        else:
            logger.error(f"Failed to get environments: {response.get('error', 'Unknown error')}")
            return None

    def add_environment(self, env_name: str, env_password: str) -> bool:
        """Add a new environment."""
        if not self.session_token:
            logger.error("Not authenticated")
            return False

        request = {
            'action': 'add_environment',
            'session_token': self.session_token,
            'env_name': env_name,
            'env_password': env_password
        }

        response = self._send_request(request)

        if response.get('success'):
            logger.info(f"Successfully added environment: {env_name}")
            return True
        else:
            logger.error(f"Failed to add environment: {response.get('error', 'Unknown error')}")
            return False

    def join_environment(self, env_name: str, env_password: str) -> bool:
        """Join an existing environment."""
        if not self.session_token:
            logger.error("Not authenticated")
            return False

        request = {
            'action': 'join_environment',
            'session_token': self.session_token,
            'env_name': env_name,
            'env_password': env_password
        }

        response = self._send_request(request)

        if response.get('success'):
            logger.info(f"Successfully joined environment: {env_name}")
            return True
        else:
            logger.error(f"Failed to join environment: {response.get('error', 'Unknown error')}")
            return False

    def store_packet_data(self, env_name: str, packet_data: Dict[str, Any]) -> bool:
        """Store packet capture data."""
        if not self.session_token:
            logger.error("Not authenticated")
            return False

        request = {
            'action': 'store_packet',
            'session_token': self.session_token,
            'env_name': env_name,
            'packet_data': packet_data
        }

        response = self._send_request(request)

        if response.get('success'):
            logger.debug(f"Successfully stored packet data for environment: {env_name}")
            return True
        else:
            logger.error(f"Failed to store packet data: {response.get('error', 'Unknown error')}")
            return False

    def get_packet_data(self, env_name: str, limit: int = 100) -> Optional[List[Dict[str, Any]]]:
        """Retrieve packet capture data for a specific environment."""
        if not self.session_token:
            logger.error("Not authenticated")
            return None

        request = {
            'action': 'get_packets',
            'session_token': self.session_token,
            'env_name': env_name,
            'limit': limit
        }

        response = self._send_request(request)

        if response.get('success'):
            logger.info(
                f"Successfully retrieved {len(response.get('packets', []))} packets from environment: {env_name}")
            return response.get('packets', [])
        else:
            logger.error(f"Failed to get packet data: {response.get('error', 'Unknown error')}")
            return None

    def logout(self) -> bool:
        """Logout from the server."""
        if not self.session_token:
            return True

        request = {
            'action': 'logout',
            'session_token': self.session_token
        }

        response = self._send_request(request)

        # Clear session data regardless of server response
        self.session_token = None
        self.username = None
        self.user_id = None
        self.is_admin = False

        if response.get('success'):
            logger.info("Successfully logged out")
            return True
        else:
            logger.warning(f"Logout response: {response.get('error', 'Unknown error')}")
            return False

    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self.session_token is not None

    def get_user_info(self) -> Dict[str, Any]:
        """Get current user information."""
        return {
            'username': self.username,
            'user_id': self.user_id,
            'is_admin': self.is_admin,
            'authenticated': self.is_authenticated()
        }


def main():
    """Example usage of the DatabaseClient with full feature support."""
    client = DatabaseClient()

    print("=== Database Client ===")
    print("Make sure the database server is running")

    while True:
        if not client.is_authenticated():
            print("\n=== Main Menu ===")
            print("1. Login")
            print("2. Register new user")
            print("3. Exit")

            choice = input("Enter choice (1-3): ")

            if choice == '1':
                username = input("Enter username: ")
                password = input("Enter password: ")

                if client.authenticate(username, password):
                    print(f"Login successful! Welcome {client.username}")
                    print(f"Admin status: {client.is_admin}")
                else:
                    print("Login failed!")

            elif choice == '2':
                username = input("Enter new username: ")
                password = input("Enter password: ")
                admin_choice = input("Register as admin? (y/n): ").lower()
                is_admin = admin_choice in ['y', 'yes']

                if client.register_user(username, password, is_admin):
                    print(f"User '{username}' registered successfully!")
                else:
                    print("Registration failed!")

            elif choice == '3':
                print("Goodbye!")
                break

            else:
                print("Invalid choice. Please try again.")

        else:
            # Authenticated user menu
            print(f"\n=== Logged in as {client.username} {'(Admin)' if client.is_admin else ''} ===")
            print("1. View environments")
            print("2. Add environment")
            print("3. Join environment")
            print("4. Store packet data")
            print("5. View packet data")
            print("6. Logout")

            choice = input("Enter choice (1-6): ")

            if choice == '1':
                environments = client.get_environments()
                if environments:
                    print("\nYour environments:")
                    for i, env in enumerate(environments, 1):
                        admin_status = " (Admin)" if env.get('is_admin') else ""
                        print(f"{i}. {env['env_name']}: {env['env_password']}{admin_status}")
                else:
                    print("No environments found or error occurred.")

            elif choice == '2':
                env_name = input("Enter environment name: ")
                env_password = input("Enter environment password: ")
                if client.add_environment(env_name, env_password):
                    print("Environment added successfully!")
                else:
                    print("Failed to add environment.")

            elif choice == '3':
                env_name = input("Enter environment name to join: ")
                env_password = input("Enter environment password: ")
                if client.join_environment(env_name, env_password):
                    print("Successfully joined environment!")
                else:
                    print("Failed to join environment.")

            elif choice == '4':
                env_name = input("Enter environment name for packet storage: ")

                print("Enter packet data:")
                timestamp = input("Timestamp (YYYY-MM-DD HH:MM:SS): ") or "2024-01-01 12:00:00"
                src_ip = input("Source IP: ") or "192.168.1.100"
                dst_ip = input("Destination IP: ") or "192.168.1.200"
                protocol = input("Protocol: ") or "TCP"
                size = input("Packet size: ") or "1500"
                data = input("Packet data: ") or "test packet data"

                try:
                    size = int(size)
                except ValueError:
                    size = 1500

                packet_data = {
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'size': size,
                    'data': data
                }

                if client.store_packet_data(env_name, packet_data):
                    print("Packet data stored successfully!")
                else:
                    print("Failed to store packet data.")

            elif choice == '5':
                env_name = input("Enter environment name to view packets: ")
                limit_input = input("Number of packets to retrieve (default 100): ")

                try:
                    limit = int(limit_input) if limit_input else 100
                except ValueError:
                    limit = 100

                packets = client.get_packet_data(env_name, limit)
                if packets:
                    print(f"\nPacket data for environment '{env_name}':")
                    print("-" * 80)
                    for i, packet in enumerate(packets, 1):
                        print(f"Packet {i}:")
                        print(f"  Timestamp: {packet['timestamp']}")
                        print(f"  Source IP: {packet['src_ip']}")
                        print(f"  Destination IP: {packet['dst_ip']}")
                        print(f"  Protocol: {packet['protocol']}")
                        print(f"  Size: {packet['size']} bytes")
                        print(f"  Data: {packet['data']}")
                        print(f"  Captured at: {packet['captured_at']}")
                        print("-" * 40)
                else:
                    print("No packet data found or error occurred.")

            elif choice == '6':
                client.logout()
                print("Logged out successfully!")

            else:
                print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()