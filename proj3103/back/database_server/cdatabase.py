import sqlite3
import hashlib
import os
import getpass
from typing import List, Dict, Optional, Tuple


class CredentialDatabase:
    def __init__(self, db_file: str = "credentials.db"):
        """Initialize the database connection and create tables if they don't exist."""
        self.db_file = db_file
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
        self._create_tables()
        self._ensure_admin_column()  # Add this line

    def _create_tables(self):
        """Create the necessary tables if they don't exist."""
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0 NOT NULL
        )
        ''')

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS environments (
            user_id INTEGER NOT NULL,
            env_name TEXT NOT NULL,
            env_password TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            PRIMARY KEY (user_id, env_name)
            UNIQUE(user_id, env_name)
        )
        ''')

        self.conn.commit()

    def _hash_password(self, password: str) -> str:
        """Hash a password for secure storage."""
        return hashlib.sha256(password.encode()).hexdigest()

    def add_user(self, username: str, password: str, is_admin: bool = False) -> bool:
        """Add a new user to the database."""
        try:
            password_hash = self._hash_password(password)
            self.cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                                (username, password_hash, 1 if is_admin else 0))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Username already exists
            return False

    def _ensure_admin_column(self):
        """Ensure the is_admin column exists in the users table."""
        # Check if is_admin column exists
        self.cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in self.cursor.fetchall()]

        if "is_admin" not in columns:
            print("Adding is_admin column to users table...")

            # SQLite doesn't support ALTER TABLE ADD COLUMN with constraints directly
            # We'll need to create a new table, copy data, and replace the old table

            # 1. Create new table with is_admin column
            self.cursor.execute('''
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0 NOT NULL
            )
            ''')

            # 2. Copy data from old table to new table
            self.cursor.execute('''
            INSERT INTO users_new (id, username, password_hash, is_admin)
            SELECT id, username, password_hash, 0 FROM users
            ''')

            # 3. Drop old table
            self.cursor.execute("DROP TABLE users")

            # 4. Rename new table to old table name
            self.cursor.execute("ALTER TABLE users_new RENAME TO users")

            self.conn.commit()
            print("Migration completed successfully.")

    def authenticate_user(self, username: str, password: str) -> Optional[Tuple[int, bool]]:
        """Authenticate a user and return (user_id, is_admin) if successful."""
        password_hash = self._hash_password(password)
        self.cursor.execute("SELECT id, is_admin FROM users WHERE username = ? AND password_hash = ?",
                            (username, password_hash))
        result = self.cursor.fetchone()
        return (result[0], bool(result[1])) if result else None

    def add_environment(self, user_id: int, env_name: str, env_password: str) -> bool:
        """Add an environment for a specific user."""
        try:
            self.cursor.execute(
                "INSERT INTO environments (user_id, env_name, env_password) VALUES (?, ?, ?)",
                (user_id, env_name, env_password)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Environment name already exists for this user
            return False

    def update_environment(self, user_id: int, env_name: str, env_password: str) -> bool:
        """Update an existing environment's password."""
        self.cursor.execute(
            "UPDATE environments SET env_password = ? WHERE user_id = ? AND env_name = ?",
            (env_password, user_id, env_name)
        )
        self.conn.commit()
        return self.cursor.rowcount > 0

    def get_user_environments(self, user_id: int) -> List[Dict[str, str]]:
        """Get all environments for a specific user."""
        # First get if this user is an admin in general
        self.cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        user_result = self.cursor.fetchone()
        is_system_admin = bool(user_result[0]) if user_result else False

        # Now get all environments for this user
        self.cursor.execute(
            "SELECT env_name, env_password FROM environments WHERE user_id = ?",
            (user_id,)
        )

        results = self.cursor.fetchall()
        environments = []

        for row in results:
            env_name = row[0]
            env_password = row[1]

            # For each environment, check if this user is the original creator
            self.cursor.execute("""
                SELECT MIN(rowid) 
                FROM environments 
                WHERE env_name = ?
                GROUP BY env_name
            """, (env_name,))

            first_entry = self.cursor.fetchone()

            # Get the user_id of the first entry for this environment
            is_creator = False
            if first_entry:
                self.cursor.execute("""
                    SELECT user_id
                    FROM environments
                    WHERE rowid = ?
                """, (first_entry[0],))

                creator_result = self.cursor.fetchone()
                is_creator = creator_result[0] == user_id if creator_result else False

            # User is admin of this environment if:
            # 1. They're a system admin (registered as admin), OR
            # 2. They're the creator of this environment
            is_admin_of_env = is_system_admin or is_creator

            environments.append({
                "env_name": env_name,
                "env_password": env_password,
                "is_admin": is_admin_of_env
            })

        return environments

    def get_admin_environments(self, user_id: int) -> List[Dict[str, str]]:
        """Get environments created by a specific admin user."""
        self.cursor.execute("""
            SELECT env_name, env_password
            FROM environments 
            WHERE user_id = ?
        """, (user_id,))

        results = self.cursor.fetchall()
        return [{"env_name": row[0], "env_password": row[1]} for row in results]

    def get_available_environments(self) -> List[Dict[str, str]]:
        """Get all available environments."""
        self.cursor.execute("""
            SELECT DISTINCT env_name
            FROM environments
        """)

        results = self.cursor.fetchall()
        return [{"env_name": row[0]} for row in results]

    def join_environment(self, user_id: int, env_name: str, env_password: str) -> bool:
        """Join an existing environment."""
        # Check if the environment exists and the password is correct
        self.cursor.execute("""
            SELECT env_password
            FROM environments
            WHERE env_name = ?
        """, (env_name,))

        result = self.cursor.fetchone()
        if not result or result[0] != env_password:
            return False

        # Check if the user is already in this environment
        self.cursor.execute("""
            SELECT 1
            FROM environments
            WHERE user_id = ? AND env_name = ?
        """, (user_id, env_name))

        if self.cursor.fetchone():
            return False  # User is already in this environment

        # Add the user to the environment
        try:
            self.cursor.execute("""
                INSERT INTO environments (user_id, env_name, env_password)
                VALUES (?, ?, ?)
            """, (user_id, env_name, env_password))

            self.conn.commit()
            return True
        except sqlite3.Error:
            return False

    def leave_environment(self, user_id: int, env_name: str) -> bool:
        """Leave an environment."""
        try:
            self.cursor.execute("""
                DELETE FROM environments
                WHERE user_id = ? AND env_name = ?
            """, (user_id, env_name))

            self.conn.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def get_environments(self, user_id: int) -> List[Dict[str, str]]:
        """Get all environments for a specific user."""
        self.cursor.execute(
            "SELECT env_name, env_password FROM environments WHERE user_id = ?",
            (user_id,)
        )
        results = self.cursor.fetchall()
        return [{"env_name": row[0], "env_password": row[1]} for row in results]

    def delete_environment(self, user_id: int, env_name: str) -> bool:
        """Delete an environment for a specific user."""
        self.cursor.execute(
            "DELETE FROM environments WHERE user_id = ? AND env_name = ?",
            (user_id, env_name)
        )
        self.conn.commit()
        return self.cursor.rowcount > 0

    def delete_user(self, user_id: int) -> bool:
        """Delete a user and all associated environments."""
        try:
            # Begin transaction
            self.cursor.execute("BEGIN TRANSACTION")

            # Delete all environments for this user
            self.cursor.execute("DELETE FROM environments WHERE user_id = ?", (user_id,))

            # Delete the user
            self.cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

            # Commit transaction
            self.conn.commit()
            return True
        except Exception as e:
            # Rollback in case of error
            self.conn.rollback()
            print(f"Error deleting user: {e}")
            return False

    def close(self):
        """Close the database connection."""
        self.conn.close()


def create_cli_menu():
    """Create a simple command-line interface for the credential database."""
    db = CredentialDatabase()

    current_user_id = None
    is_admin = False  # Add this line to track admin status

    def register_user():
        username = input("Enter new username: ")
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")

        if password != confirm_password:
            print("Passwords do not match. Registration failed.")
            return

        # Add option to register as admin
        admin_choice = input("Register as admin? (y/n): ").lower()
        is_admin = admin_choice == 'y' or admin_choice == 'yes'

        if db.add_user(username, password, is_admin):
            print(f"User '{username}' registered successfully{' as admin' if is_admin else ''}!")
        else:
            print(f"Username '{username}' already exists. Please choose another username.")

    def login_user():
        nonlocal current_user_id, is_admin  # Add is_admin to nonlocal declaration
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")

        result = db.authenticate_user(username, password)
        if result:
            current_user_id, is_admin = result  # Unpack the tuple
            print(f"Welcome, {username}!{' (Admin)' if is_admin else ''}")
            return True
        else:
            print("Invalid username or password.")
            return False

    def add_env():
        env_name = input("Enter environment name: ")
        env_password = getpass.getpass("Enter environment password: ")

        if db.add_environment(current_user_id, env_name, env_password):
            print(f"Environment '{env_name}' added successfully!")
        else:
            print(f"Environment '{env_name}' already exists. Use update option to change the password.")

    def update_env():
        env_name = input("Enter environment name: ")
        env_password = getpass.getpass("Enter new environment password: ")

        if db.update_environment(current_user_id, env_name, env_password):
            print(f"Environment '{env_name}' updated successfully!")
        else:
            print(f"Environment '{env_name}' not found.")

    def list_envs():
        environments = db.get_environments(current_user_id)
        if environments:
            print("\nYour environments:")
            for i, env in enumerate(environments, 1):
                print(f"{i}. {env['env_name']}: {env['env_password']}")
            print()
        else:
            print("You don't have any environments yet.")

    def delete_env():
        env_name = input("Enter environment name to delete: ")
        if db.delete_environment(current_user_id, env_name):
            print(f"Environment '{env_name}' deleted successfully!")
        else:
            print(f"Environment '{env_name}' not found.")

    def main_menu():
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n===== Credential Database System =====")
            print("1. Register")
            print("2. Login")
            print("3. Exit")

            choice = input("\nEnter your choice (1-3): ")

            if choice == "1":
                register_user()
                input("\nPress Enter to continue...")
            elif choice == "2":
                if login_user():
                    user_menu()
                input("\nPress Enter to continue...")
            elif choice == "3":
                print("Goodbye!")
                db.close()
                break
            else:
                print("Invalid choice. Please try again.")
                input("\nPress Enter to continue...")

    def user_menu():
        nonlocal current_user_id, is_admin  # Add is_admin to nonlocal declaration
        while current_user_id:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n===== User Menu =====")
            print(f"Logged in as{' admin' if is_admin else ''}")  # Show admin status
            print("1. Add Environment")
            print("2. Update Environment")
            print("3. List Environments")
            print("4. Delete Environment")
            print("5. Logout")

            choice = input("\nEnter your choice (1-5): ")

            if choice == "1":
                add_env()
            elif choice == "2":
                update_env()
            elif choice == "3":
                list_envs()
            elif choice == "4":
                delete_env()
            elif choice == "5":
                current_user_id = None
                is_admin = False  # Reset admin status on logout
                print("Logged out successfully!")
                break
            else:
                print("Invalid choice. Please try again.")

            input("\nPress Enter to continue...")

    # Start the application
    main_menu()


if __name__ == "__main__":
    create_cli_menu()
