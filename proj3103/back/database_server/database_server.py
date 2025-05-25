import socket
import json
import threading
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
import logging

# Import the database class
from proj3103.databaseV3.cdatabase import CredentialDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DatabaseServer:
    def __init__(self, host='localhost', port=8888, secret_key=None):
        self.host = host
        self.port = port
        self.secret_key = secret_key or secrets.token_hex(32)
        self.db = CredentialDatabase()
        self.active_sessions = {}  # Store active user sessions
        self.session_timeout = 3600  # 1 hour session timeout

        # Socket setup
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False

        logger.info(f"Database server initialized on {host}:{port}")

    def generate_session_token(self, user_id: int) -> str:
        """Generate a secure session token for authenticated users."""
        timestamp = str(int(time.time()))
        session_data = f"{user_id}:{timestamp}"
        signature = hmac.new(
            self.secret_key.encode(),
            session_data.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{session_data}:{signature}"

    def verify_session_token(self, token: str) -> Optional[int]:
        """Verify session token and return user_id if valid."""
        try:
            parts = token.split(':')
            if len(parts) != 3:
                return None

            user_id, timestamp, signature = parts
            session_data = f"{user_id}:{timestamp}"

            # Verify signature
            expected_signature = hmac.new(
                self.secret_key.encode(),
                session_data.encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_signature):
                return None

            # Check if session has expired
            session_time = int(timestamp)
            if time.time() - session_time > self.session_timeout:
                return None

            return int(user_id)
        except (ValueError, IndexError):
            return None

    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user and return session info."""
        result = self.db.authenticate_user(username, password)
        if result:
            user_id, is_admin = result
            session_token = self.generate_session_token(user_id)

            # Store session info
            self.active_sessions[session_token] = {
                'user_id': user_id,
                'username': username,
                'is_admin': is_admin,
                'login_time': datetime.now(),
                'last_activity': datetime.now()
            }

            logger.info(f"User {username} authenticated successfully")
            return {
                'success': True,
                'session_token': session_token,
                'user_id': user_id,
                'username': username,
                'is_admin': is_admin
            }
        else:
            logger.warning(f"Failed authentication attempt for username: {username}")
            return {'success': False, 'error': 'Invalid credentials'}

    def get_user_environments(self, session_token: str) -> Dict[str, Any]:
        """Get environments for authenticated user."""
        user_id = self.verify_session_token(session_token)
        if not user_id:
            return {'success': False, 'error': 'Invalid or expired session'}

        try:
            environments = self.db.get_user_environments(user_id)
            return {'success': True, 'environments': environments}
        except Exception as e:
            logger.error(f"Error fetching environments for user {user_id}: {e}")
            return {'success': False, 'error': 'Database error'}

    def add_environment(self, session_token: str, env_name: str, env_password: str) -> Dict[str, Any]:
        """Add new environment for authenticated user."""
        user_id = self.verify_session_token(session_token)
        if not user_id:
            return {'success': False, 'error': 'Invalid or expired session'}

        try:
            success = self.db.add_environment(user_id, env_name, env_password)
            if success:
                logger.info(f"Environment '{env_name}' added for user {user_id}")
                return {'success': True, 'message': 'Environment added successfully'}
            else:
                return {'success': False, 'error': 'Environment already exists'}
        except Exception as e:
            logger.error(f"Error adding environment for user {user_id}: {e}")
            return {'success': False, 'error': 'Database error'}

    def store_packet_data(self, session_token: str, env_name: str, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store packet capture data for specified environment."""
        user_id = self.verify_session_token(session_token)
        if not user_id:
            return {'success': False, 'error': 'Invalid or expired session'}

        # Verify user has access to this environment
        try:
            environments = self.db.get_user_environments(user_id)
            env_exists = any(env['env_name'] == env_name for env in environments)

            if not env_exists:
                return {'success': False, 'error': 'Access denied to environment'}

            # Here you would implement packet data storage
            # For now, we'll just log it and return success
            logger.info(f"Packet data stored for user {user_id}, environment {env_name}")

            # You could extend the database schema to include a packets table:
            # CREATE TABLE packets (
            #     id INTEGER PRIMARY KEY AUTOINCREMENT,
            #     user_id INTEGER NOT NULL,
            #     env_name TEXT NOT NULL,
            #     packet_data TEXT NOT NULL,
            #     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            #     FOREIGN KEY (user_id) REFERENCES users (id)
            # )

            return {'success': True, 'message': 'Packet data stored successfully'}

        except Exception as e:
            logger.error(f"Error storing packet data: {e}")
            return {'success': False, 'error': 'Storage error'}

    def join_environment(self, session_token: str, env_name: str, env_password: str) -> Dict[str, Any]:
        """Join an existing environment."""
        user_id = self.verify_session_token(session_token)
        if not user_id:
            return {'success': False, 'error': 'Invalid or expired session'}

        try:
            success = self.db.join_environment(user_id, env_name, env_password)
            if success:
                logger.info(f"User {user_id} joined environment '{env_name}'")
                return {'success': True, 'message': 'Successfully joined environment'}
            else:
                return {'success': False, 'error': 'Invalid environment or password, or already joined'}
        except Exception as e:
            logger.error(f"Error joining environment: {e}")
            return {'success': False, 'error': 'Database error'}

    def logout(self, session_token: str) -> Dict[str, Any]:
        """Logout user and invalidate session."""
        if session_token in self.active_sessions:
            username = self.active_sessions[session_token]['username']
            del self.active_sessions[session_token]
            logger.info(f"User {username} logged out")
            return {'success': True, 'message': 'Logged out successfully'}
        return {'success': False, 'error': 'Invalid session'}

    def handle_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming client requests."""
        action = request_data.get('action')

        if action == 'authenticate':
            return self.authenticate_user(
                request_data.get('username'),
                request_data.get('password')
            )

        elif action == 'get_environments':
            return self.get_user_environments(request_data.get('session_token'))

        elif action == 'add_environment':
            return self.add_environment(
                request_data.get('session_token'),
                request_data.get('env_name'),
                request_data.get('env_password')
            )

        elif action == 'store_packet':
            return self.store_packet_data(
                request_data.get('session_token'),
                request_data.get('env_name'),
                request_data.get('packet_data')
            )

        elif action == 'join_environment':
            return self.join_environment(
                request_data.get('session_token'),
                request_data.get('env_name'),
                request_data.get('env_password')
            )

        elif action == 'logout':
            return self.logout(request_data.get('session_token'))

        else:
            return {'success': False, 'error': 'Unknown action'}

    def handle_client(self, client_socket, address):
        """Handle individual client connections."""
        logger.info(f"New client connected: {address}")

        try:
            while True:
                # Receive data from client
                data = client_socket.recv(4096)
                if not data:
                    break

                try:
                    # Parse JSON request
                    request_data = json.loads(data.decode('utf-8'))
                    logger.debug(f"Received request from {address}: {request_data.get('action')}")

                    # Process request
                    response = self.handle_request(request_data)

                    # Send response back to client
                    response_json = json.dumps(response)
                    client_socket.send(response_json.encode('utf-8'))

                except json.JSONDecodeError:
                    error_response = {'success': False, 'error': 'Invalid JSON format'}
                    client_socket.send(json.dumps(error_response).encode('utf-8'))
                except Exception as e:
                    logger.error(f"Error handling request from {address}: {e}")
                    error_response = {'success': False, 'error': 'Server error'}
                    client_socket.send(json.dumps(error_response).encode('utf-8'))

        except ConnectionResetError:
            logger.info(f"Client {address} disconnected")
        except Exception as e:
            logger.error(f"Error with client {address}: {e}")
        finally:
            client_socket.close()
            logger.info(f"Connection closed for {address}")

    def cleanup_expired_sessions(self):
        """Remove expired sessions periodically."""
        current_time = datetime.now()
        expired_sessions = []

        for token, session_info in self.active_sessions.items():
            if (current_time - session_info['last_activity']).seconds > self.session_timeout:
                expired_sessions.append(token)

        for token in expired_sessions:
            username = self.active_sessions[token]['username']
            del self.active_sessions[token]
            logger.info(f"Expired session for user {username}")

    def start(self):
        """Start the database server."""
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True

            logger.info(f"Database server listening on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, address = self.socket.accept()

                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                    # Cleanup expired sessions periodically
                    self.cleanup_expired_sessions()

                except socket.error as e:
                    if self.running:
                        logger.error(f"Socket error: {e}")
                    break

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the database server."""
        self.running = False
        try:
            self.socket.close()
            self.db.close()
            logger.info("Database server stopped")
        except Exception as e:
            logger.error(f"Error stopping server: {e}")


def main():
    """Main function to start the database server."""
    # You can customize these settings
    HOST = 'localhost'
    PORT = 9008

    # Create and start the server
    server = DatabaseServer(HOST, PORT)

    try:
        print(f"Starting Database Server on {HOST}:{PORT}")
        print("Press Ctrl+C to stop the server")
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()


if __name__ == "__main__":
    main()