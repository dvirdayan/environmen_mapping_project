import socket
import json
import threading
import hashlib
import hmac
import secrets
import time
import sqlite3
from datetime import datetime
from typing import Dict, Optional, Any, List, Tuple
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SecureCredentialDatabase:
    """Enhanced database class with packet data storage capabilities."""

    def __init__(self, db_file: str = "credentials.db"):
        """Initialize the database connection and create tables if they don't exist."""
        self.db_file = db_file
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.lock = threading.Lock()  # Thread safety for database operations
        self._create_tables()

    def _create_tables(self):
        """Create the necessary tables if they don't exist."""
        with self.lock:
            # Users table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0 NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # Environments table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS environments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                env_name TEXT NOT NULL,
                env_password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, env_name)
            )
            ''')

            # Check if created_at column exists in environments table, if not add it
            self.cursor.execute("PRAGMA table_info(environments)")
            columns = [column[1] for column in self.cursor.fetchall()]
            if 'created_at' not in columns:
                # SQLite doesn't support adding columns with CURRENT_TIMESTAMP as default
                # We need to recreate the table or add the column with NULL default
                # and then update existing records

                # Method 1: Add column with NULL default, then update existing records
                self.cursor.execute('ALTER TABLE environments ADD COLUMN created_at DATETIME DEFAULT NULL')

                # Update existing records to have the current timestamp
                current_timestamp = datetime.now().isoformat()
                self.cursor.execute('UPDATE environments SET created_at = ? WHERE created_at IS NULL',
                                    (current_timestamp,))

                print("Added created_at column to environments table and updated existing records")

            # Packet data table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                env_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                size INTEGER,
                data TEXT,
                captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')

            # Session logs table for security auditing
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT,
                ip_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                success INTEGER,
                details TEXT
            )
            ''')

            self.conn.commit()

    def _hash_password(self, password: str) -> str:
        """Hash a password for secure storage."""
        return hashlib.sha256(password.encode()).hexdigest()

    def add_user(self, username: str, password: str, is_admin: bool = False) -> bool:
        """Add a new user to the database."""
        with self.lock:
            try:
                password_hash = self._hash_password(password)
                self.cursor.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                    (username, password_hash, 1 if is_admin else 0)
                )
                self.conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def authenticate_user(self, username: str, password: str) -> Optional[Tuple[int, bool]]:
        """Authenticate a user and return (user_id, is_admin) if successful."""
        with self.lock:
            password_hash = self._hash_password(password)
            self.cursor.execute(
                "SELECT id, is_admin FROM users WHERE username = ? AND password_hash = ?",
                (username, password_hash)
            )
            result = self.cursor.fetchone()
            return (result[0], bool(result[1])) if result else None

    def add_environment(self, user_id: int, env_name: str, env_password: str) -> bool:
        """Add an environment for a specific user."""
        with self.lock:
            try:
                # Check if created_at column exists and handle accordingly
                self.cursor.execute("PRAGMA table_info(environments)")
                columns = [column[1] for column in self.cursor.fetchall()]

                if 'created_at' in columns:
                    self.cursor.execute(
                        "INSERT INTO environments (user_id, env_name, env_password, created_at) VALUES (?, ?, ?, ?)",
                        (user_id, env_name, env_password, datetime.now().isoformat())
                    )
                else:
                    self.cursor.execute(
                        "INSERT INTO environments (user_id, env_name, env_password) VALUES (?, ?, ?)",
                        (user_id, env_name, env_password)
                    )

                self.conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def get_user_environments(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all environments for a specific user."""
        with self.lock:
            try:
                # Check if user is system admin
                self.cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
                user_result = self.cursor.fetchone()
                is_system_admin = bool(user_result[0]) if user_result else False

                # Get environments this user has access to
                self.cursor.execute(
                    "SELECT env_name, env_password FROM environments WHERE user_id = ?",
                    (user_id,)
                )
                results = self.cursor.fetchall()

                environments = []
                for row in results:
                    env_name, env_password = row

                    # For each environment, check if user is the creator
                    # (first user to create an environment with that name)
                    # Check if created_at column exists
                    self.cursor.execute("PRAGMA table_info(environments)")
                    columns = [column[1] for column in self.cursor.fetchall()]

                    if 'created_at' in columns:
                        # Use created_at to determine the first creator
                        self.cursor.execute(
                            "SELECT user_id FROM environments WHERE env_name = ? ORDER BY created_at ASC LIMIT 1",
                            (env_name,)
                        )
                    else:
                        # Fallback: use ROWID (SQLite's implicit row identifier) to determine order
                        self.cursor.execute(
                            "SELECT user_id FROM environments WHERE env_name = ? ORDER BY ROWID ASC LIMIT 1",
                            (env_name,)
                        )

                    creator_result = self.cursor.fetchone()
                    is_creator = creator_result and creator_result[0] == user_id

                    environments.append({
                        "env_name": env_name,
                        "env_password": env_password,
                        "is_admin": is_system_admin or is_creator
                    })

                return environments

            except sqlite3.Error as e:
                logger.error(f"Database error in get_user_environments: {e}")
                raise Exception(f"Database error: {e}")

    def join_environment(self, user_id: int, env_name: str, env_password: str) -> bool:
        """Join an existing environment."""
        with self.lock:
            try:
                # Check if environment exists with correct password
                self.cursor.execute(
                    "SELECT env_password FROM environments WHERE env_name = ? LIMIT 1",
                    (env_name,)
                )
                result = self.cursor.fetchone()

                if not result or result[0] != env_password:
                    return False

                # Check if user is already in this environment
                self.cursor.execute(
                    "SELECT 1 FROM environments WHERE user_id = ? AND env_name = ?",
                    (user_id, env_name)
                )

                if self.cursor.fetchone():
                    return False  # Already in environment

                # Add user to environment
                # Check if created_at column exists and handle accordingly
                self.cursor.execute("PRAGMA table_info(environments)")
                columns = [column[1] for column in self.cursor.fetchall()]

                if 'created_at' in columns:
                    self.cursor.execute(
                        "INSERT INTO environments (user_id, env_name, env_password, created_at) VALUES (?, ?, ?, ?)",
                        (user_id, env_name, env_password, datetime.now().isoformat())
                    )
                else:
                    self.cursor.execute(
                        "INSERT INTO environments (user_id, env_name, env_password) VALUES (?, ?, ?)",
                        (user_id, env_name, env_password)
                    )

                self.conn.commit()
                return True

            except sqlite3.Error as e:
                logger.error(f"Database error in join_environment: {e}")
                return False

    def store_packet_data(self, user_id: int, env_name: str, packet_data: Dict[str, Any]) -> bool:
        """Store packet capture data."""
        with self.lock:
            try:
                # Verify user has access to this environment
                self.cursor.execute(
                    "SELECT 1 FROM environments WHERE user_id = ? AND env_name = ?",
                    (user_id, env_name)
                )

                if not self.cursor.fetchone():
                    return False  # User doesn't have access to this environment

                # Store packet data
                self.cursor.execute('''
                    INSERT INTO packet_data 
                    (user_id, env_name, timestamp, src_ip, dst_ip, protocol, size, data, captured_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    env_name,
                    packet_data.get('timestamp', ''),
                    packet_data.get('src_ip', ''),
                    packet_data.get('dst_ip', ''),
                    packet_data.get('protocol', ''),
                    packet_data.get('size', 0),
                    packet_data.get('data', ''),
                    datetime.now().isoformat()
                ))

                self.conn.commit()
                return True
            except sqlite3.Error as e:
                logger.error(f"Database error storing packet data: {e}")
                return False

    def get_packet_data(self, user_id: int, env_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve packet data for a specific environment."""
        with self.lock:
            try:
                # Verify user has access to this environment
                self.cursor.execute(
                    "SELECT 1 FROM environments WHERE user_id = ? AND env_name = ?",
                    (user_id, env_name)
                )

                if not self.cursor.fetchone():
                    return []

                # Get packet data
                self.cursor.execute('''
                    SELECT timestamp, src_ip, dst_ip, protocol, size, data, captured_at
                    FROM packet_data 
                    WHERE user_id = ? AND env_name = ?
                    ORDER BY captured_at DESC
                    LIMIT ?
                ''', (user_id, env_name, limit))

                results = self.cursor.fetchall()
                packets = []

                for row in results:
                    packets.append({
                        'timestamp': row[0],
                        'src_ip': row[1],
                        'dst_ip': row[2],
                        'protocol': row[3],
                        'size': row[4],
                        'data': row[5],
                        'captured_at': row[6]
                    })

                return packets

            except sqlite3.Error as e:
                logger.error(f"Database error in get_packet_data: {e}")
                return []

    def log_session_activity(self, user_id: Optional[int], username: str, action: str,
                             ip_address: str, success: bool, details: str = ""):
        """Log session activity for security auditing."""
        with self.lock:
            try:
                self.cursor.execute('''
                    INSERT INTO session_logs (user_id, username, action, ip_address, success, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (user_id, username, action, ip_address, int(success), details, datetime.now().isoformat()))
                self.conn.commit()
            except sqlite3.Error as e:
                logger.error(f"Failed to log session activity: {e}")

    def close(self):
        """Close the database connection."""
        self.conn.close()


class SecureDatabaseServer:
    def __init__(self, host='localhost', port=9008, secret_key=None):
        self.host = host
        self.port = port
        self.secret_key = secret_key or secrets.token_hex(32)
        self.db = SecureCredentialDatabase()
        self.active_sessions = {}
        self.session_timeout = 3600  # 1 hour

        # Socket setup
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False

        logger.info(f"Secure Database Server initialized on {host}:{port}")

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

    def authenticate_user(self, username: str, password: str, client_ip: str) -> Dict[str, Any]:
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
                'last_activity': datetime.now(),
                'client_ip': client_ip
            }

            # Log successful authentication
            self.db.log_session_activity(user_id, username, 'LOGIN', client_ip, True)

            logger.info(f"User {username} authenticated successfully from {client_ip}")
            return {
                'success': True,
                'session_token': session_token,
                'user_id': user_id,
                'username': username,
                'is_admin': is_admin
            }
        else:
            # Log failed authentication
            self.db.log_session_activity(None, username, 'FAILED_LOGIN', client_ip, False)

            logger.warning(f"Failed authentication attempt for username: {username} from {client_ip}")
            return {'success': False, 'error': 'Invalid credentials'}

    def register_user(self, username: str, password: str, is_admin: bool, client_ip: str) -> Dict[str, Any]:
        """Register a new user."""
        try:
            success = self.db.add_user(username, password, is_admin)
            if success:
                logger.info(f"New user registered: {username} from {client_ip}")
                self.db.log_session_activity(None, username, 'REGISTER', client_ip, True)
                return {'success': True, 'message': 'User registered successfully'}
            else:
                logger.warning(f"Failed registration attempt for username: {username} from {client_ip}")
                self.db.log_session_activity(None, username, 'FAILED_REGISTER', client_ip, False,
                                             'Username already exists')
                return {'success': False, 'error': 'Username already exists'}
        except Exception as e:
            logger.error(f"Error during user registration: {e}")
            return {'success': False, 'error': 'Registration failed'}

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
            return {'success': False, 'error': str(e)}

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

    def store_packet_data(self, session_token: str, env_name: str, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store packet capture data for specified environment."""
        user_id = self.verify_session_token(session_token)
        if not user_id:
            return {'success': False, 'error': 'Invalid or expired session'}

        try:
            success = self.db.store_packet_data(user_id, env_name, packet_data)
            if success:
                logger.debug(f"Packet data stored for user {user_id}, environment {env_name}")
                return {'success': True, 'message': 'Packet data stored successfully'}
            else:
                return {'success': False, 'error': 'Access denied to environment or storage failed'}
        except Exception as e:
            logger.error(f"Error storing packet data: {e}")
            return {'success': False, 'error': 'Storage error'}

    def get_packet_data(self, session_token: str, env_name: str, limit: int = 100) -> Dict[str, Any]:
        """Retrieve packet data for specified environment."""
        user_id = self.verify_session_token(session_token)
        if not user_id:
            return {'success': False, 'error': 'Invalid or expired session'}

        try:
            packets = self.db.get_packet_data(user_id, env_name, limit)
            return {'success': True, 'packets': packets}
        except Exception as e:
            logger.error(f"Error retrieving packet data: {e}")
            return {'success': False, 'error': 'Retrieval error'}

    def logout(self, session_token: str) -> Dict[str, Any]:
        """Logout user and invalidate session."""
        if session_token in self.active_sessions:
            session_info = self.active_sessions[session_token]
            username = session_info['username']
            client_ip = session_info.get('client_ip', 'unknown')

            # Log logout
            self.db.log_session_activity(
                session_info['user_id'], username, 'LOGOUT', client_ip, True
            )

            del self.active_sessions[session_token]
            logger.info(f"User {username} logged out from {client_ip}")
            return {'success': True, 'message': 'Logged out successfully'}
        return {'success': False, 'error': 'Invalid session'}

    def handle_request(self, request_data: Dict[str, Any], client_ip: str) -> Dict[str, Any]:
        """Handle incoming client requests."""
        action = request_data.get('action')

        if action == 'register':
            return self.register_user(
                request_data.get('username'),
                request_data.get('password'),
                request_data.get('is_admin', False),
                client_ip
            )

        elif action == 'authenticate':
            return self.authenticate_user(
                request_data.get('username'),
                request_data.get('password'),
                client_ip
            )

        elif action == 'get_environments':
            return self.get_user_environments(request_data.get('session_token'))

        elif action == 'add_environment':
            return self.add_environment(
                request_data.get('session_token'),
                request_data.get('env_name'),
                request_data.get('env_password')
            )

        elif action == 'join_environment':
            return self.join_environment(
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

        elif action == 'get_packets':
            return self.get_packet_data(
                request_data.get('session_token'),
                request_data.get('env_name'),
                request_data.get('limit', 100)
            )

        elif action == 'logout':
            return self.logout(request_data.get('session_token'))

        else:
            return {'success': False, 'error': 'Unknown action'}

    def handle_client(self, client_socket, address):
        """Handle individual client connections."""
        client_ip = address[0]
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
                    response = self.handle_request(request_data, client_ip)

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
            session_info = self.active_sessions[token]
            username = session_info['username']
            client_ip = session_info.get('client_ip', 'unknown')

            # Log session expiry
            self.db.log_session_activity(
                session_info['user_id'], username, 'SESSION_EXPIRED', client_ip, True
            )

            del self.active_sessions[token]
            logger.info(f"Expired session for user {username}")

    def start(self):
        """Start the database server."""
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True

            logger.info(f"Secure Database Server listening on {self.host}:{self.port}")
            print(f"Server started on {self.host}:{self.port}")
            print("Waiting for connections...")

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
            logger.info("Secure Database Server stopped")
        except Exception as e:
            logger.error(f"Error stopping server: {e}")


def create_default_users(db: SecureCredentialDatabase):
    """Create default users for testing."""
    # Create admin user
    if db.add_user("admin", "admin123", is_admin=True):
        print("Created default admin user: admin / admin123")

    # Create regular user
    if db.add_user("user", "user123", is_admin=False):
        print("Created default user: user / user123")


def main():
    """Main function to start the secure database server."""
    HOST = 'localhost'
    PORT = 9008

    print("=== Secure Database Server ===")

    # Create server instance
    server = SecureDatabaseServer(HOST, PORT)

    # Create default users if database is empty
    try:
        create_default_users(server.db)
    except Exception as e:
        logger.error(f"Error creating default users: {e}")

    try:
        print(f"\nStarting server on {HOST}:{PORT}")
        print("Default users created:")
        print("  Admin: admin / admin123")
        print("  User:  user / user123")
        print("\nPress Ctrl+C to stop the server\n")

        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()
    except Exception as e:
        print(f"Server error: {e}")
        server.stop()


if __name__ == "__main__":
    main()