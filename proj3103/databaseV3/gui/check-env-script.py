#!/usr/bin/env python3
"""
Script to check what environments are available in the database
"""

import sqlite3
import os
import sys


def check_environments(db_path="../credentials.db"):
    """Check what environments exist in the database"""
    try:
        # Ensure the database exists
        if not os.path.exists(db_path):
            print(f"Database file not found: {db_path}")
            print(f"Current working directory: {os.getcwd()}")
            print(f"Checking for db in: {os.path.abspath(db_path)}")
            return False

        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if the environments table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='environments'")
        if not cursor.fetchone():
            print("The 'environments' table does not exist in the database")
            return False

        # Query all environments
        cursor.execute("SELECT env_name, env_password FROM environments")

        environments = cursor.fetchall()

        if not environments:
            print("No environments found in the database")
            return False

        print(f"Found {len(environments)} environments:")
        for env_name, env_password in environments:
            print(f"  - Environment: '{env_name}', Password: '{env_password}'")

        # Also check for specific environments
        test_environments = ['C1', 'test', 'default']
        for env_name in test_environments:
            cursor.execute("SELECT env_password FROM environments WHERE env_name = ?", (env_name,))
            result = cursor.fetchone()
            if result:
                print(f"Found environment '{env_name}' with password '{result[0]}'")
            else:
                print(f"Environment '{env_name}' NOT found in database")

        conn.close()
        return True

    except Exception as e:
        print(f"Error checking environments: {e}")
        return False


if __name__ == "__main__":
    # Allow specifying a different database path
    db_path = sys.argv[1] if len(sys.argv) > 1 else "../credentials.db"

    print(f"Checking environments in database: {db_path}")
    if not check_environments(db_path):
        print("Environment check failed")