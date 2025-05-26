import re
from typing import Tuple, Optional


def is_safe_string(text: str, min_length: int = 3, max_length: int = 50) -> bool:
    """
    Check if a string contains only safe characters (alphanumeric).

    Args:
        text: The string to validate
        min_length: Minimum allowed length
        max_length: Maximum allowed length

    Returns:
        bool: True if string is safe, False otherwise
    """
    if not text or not isinstance(text, str):
        return False

    # Check length constraints
    if len(text) < min_length or len(text) > max_length:
        return False

    # Check if string contains only alphanumeric characters
    # This allows letters (a-z, A-Z) and numbers (0-9)
    return text.isalnum()


def validate_username(username: str) -> Tuple[bool, Optional[str]]:
    """
    Validate username for safe characters and appropriate length.

    Args:
        username: The username to validate

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)
    """
    if not username:
        return False, "Username cannot be empty"

    if not isinstance(username, str):
        return False, "Username must be a string"

    # Remove any whitespace
    username = username.strip()

    if len(username) < 3:
        return False, "Username must be at least 3 characters long"

    if len(username) > 30:
        return False, "Username must be no more than 30 characters long"

    if not username.isalnum():
        return False, "Username can only contain letters (a-z, A-Z) and numbers (0-9)"

    # Username should not be all numbers
    if username.isdigit():
        return False, "Username cannot be all numbers"

    return True, None


def validate_password(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validate password for safe characters and appropriate length.

    Args:
        password: The password to validate

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)
    """
    if not password:
        return False, "Password cannot be empty"

    if not isinstance(password, str):
        return False, "Password must be a string"

    if len(password) < 6:
        return False, "Password must be at least 6 characters long"

    if len(password) > 50:
        return False, "Password must be no more than 50 characters long"

    if not password.isalnum():
        return False, "Password can only contain letters (a-z, A-Z) and numbers (0-9)"

    # Password should contain both letters and numbers for better security
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)

    if not (has_letter and has_digit):
        return False, "Password must contain both letters and numbers"

    return True, None


def validate_environment_name(env_name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate environment name for safe characters.

    Args:
        env_name: The environment name to validate

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)
    """
    if not env_name:
        return False, "Environment name cannot be empty"

    if not isinstance(env_name, str):
        return False, "Environment name must be a string"

    # Remove any whitespace
    env_name = env_name.strip()

    if len(env_name) < 2:
        return False, "Environment name must be at least 2 characters long"

    if len(env_name) > 40:
        return False, "Environment name must be no more than 40 characters long"

    if not env_name.isalnum():
        return False, "Environment name can only contain letters (a-z, A-Z) and numbers (0-9)"

    return True, None


def sanitize_input(text: str) -> str:
    """
    Sanitize input by removing non-alphanumeric characters and trimming whitespace.

    Args:
        text: The text to sanitize

    Returns:
        str: Sanitized text containing only alphanumeric characters
    """
    if not text or not isinstance(text, str):
        return ""

    # Remove all non-alphanumeric characters
    sanitized = re.sub(r'[^a-zA-Z0-9]', '', text.strip())
    return sanitized


def get_validation_rules() -> dict:
    """
    Get a dictionary of validation rules for display to users.

    Returns:
        dict: Validation rules for each field type
    """
    return {
        "username": {
            "min_length": 3,
            "max_length": 30,
            "allowed_chars": "Letters (a-z, A-Z) and numbers (0-9) only",
            "restrictions": "Cannot be all numbers"
        },
        "password": {
            "min_length": 6,
            "max_length": 50,
            "allowed_chars": "Letters (a-z, A-Z) and numbers (0-9) only",
            "restrictions": "Must contain both letters and numbers"
        },
        "environment_name": {
            "min_length": 2,
            "max_length": 40,
            "allowed_chars": "Letters (a-z, A-Z) and numbers (0-9) only",
            "restrictions": "None"
        }
    }