#!/usr/bin/env python3
"""
Encryption module for secure communication between packet capture clients and server.
Uses RSA for key exchange and AES for data encryption.
"""

import os
import json
import base64

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad

    CRYPTO_AVAILABLE = True
except ImportError:
    print(ImportError)
    print("WARNING: pycryptodome not installed. Install with: pip install pycryptodome")
    CRYPTO_AVAILABLE = False

import hashlib


class CryptoHandler:
    """Handles RSA and AES encryption/decryption operations"""

    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.rsa_key = None
        self.rsa_public_key = None
        self.aes_key = None
        self.aes_iv = None

    def generate_rsa_keypair(self):
        """Generate a new RSA key pair"""
        self.rsa_key = RSA.generate(self.key_size)
        self.rsa_public_key = self.rsa_key.publickey()
        return self.get_public_key_pem()

    def load_rsa_private_key(self, key_path):
        """Load RSA private key from file"""
        try:
            with open(key_path, 'rb') as f:
                self.rsa_key = RSA.import_key(f.read())
                self.rsa_public_key = self.rsa_key.publickey()
            return True
        except Exception as e:
            print(f"Error loading RSA private key: {e}")
            return False

    def save_rsa_private_key(self, key_path):
        """Save RSA private key to file"""
        try:
            with open(key_path, 'wb') as f:
                f.write(self.rsa_key.export_key())
            return True
        except Exception as e:
            print(f"Error saving RSA private key: {e}")
            return False

    def load_rsa_public_key(self, public_key_pem):
        """Load RSA public key from PEM string"""
        try:
            self.rsa_public_key = RSA.import_key(public_key_pem)
            return True
        except Exception as e:
            print(f"Error loading RSA public key: {e}")
            return False

    def get_public_key_pem(self):
        """Get public key in PEM format"""
        if self.rsa_public_key:
            return self.rsa_public_key.export_key().decode('utf-8')
        return None

    def generate_aes_key(self):
        """Generate a new AES key and IV"""
        self.aes_key = get_random_bytes(32)  # 256-bit key
        self.aes_iv = get_random_bytes(16)  # 128-bit IV
        return self.aes_key, self.aes_iv

    def set_aes_key(self, key, iv):
        """Set AES key and IV"""
        self.aes_key = key
        self.aes_iv = iv

    def rsa_encrypt(self, data):
        """Encrypt data with RSA public key"""
        if not self.rsa_public_key:
            raise ValueError("RSA public key not loaded")

        cipher = PKCS1_OAEP.new(self.rsa_public_key)
        if isinstance(data, str):
            data = data.encode('utf-8')

        encrypted = cipher.encrypt(data)
        return base64.b64encode(encrypted).decode('utf-8')

    def rsa_decrypt(self, encrypted_data):
        """Decrypt data with RSA private key"""
        if not self.rsa_key:
            raise ValueError("RSA private key not loaded")

        cipher = PKCS1_OAEP.new(self.rsa_key)
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted = cipher.decrypt(encrypted_bytes)
        return decrypted

    def aes_encrypt(self, data):
        """Encrypt data with AES"""
        if not self.aes_key or not self.aes_iv:
            raise ValueError("AES key not set")

        if isinstance(data, str):
            data = data.encode('utf-8')

        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        padded_data = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded_data)

        return base64.b64encode(encrypted).decode('utf-8')

    def aes_decrypt(self, encrypted_data):
        """Decrypt data with AES"""
        if not self.aes_key or not self.aes_iv:
            raise ValueError("AES key not set")

        encrypted_bytes = base64.b64decode(encrypted_data)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        decrypted = unpad(decrypted_padded, AES.block_size)

        return decrypted.decode('utf-8')

    def encrypt_message(self, message):
        """Encrypt a message (dict or string) with AES"""
        if isinstance(message, dict):
            message = json.dumps(message)

        return self.aes_encrypt(message)

    def decrypt_message(self, encrypted_message):
        """Decrypt a message and return as string"""
        return self.aes_decrypt(encrypted_message)

    def create_key_exchange_message(self):
        """Create a message containing encrypted AES key for key exchange"""
        if not self.aes_key or not self.aes_iv:
            self.generate_aes_key()

        # Combine key and IV
        key_data = {
            'aes_key': base64.b64encode(self.aes_key).decode('utf-8'),
            'aes_iv': base64.b64encode(self.aes_iv).decode('utf-8')
        }

        # Encrypt with RSA
        key_json = json.dumps(key_data)
        encrypted_key = self.rsa_encrypt(key_json)

        return {
            'type': 'key_exchange',
            'encrypted_key': encrypted_key
        }

    def process_key_exchange_message(self, message):
        """Process incoming key exchange message and extract AES key"""
        encrypted_key = message.get('encrypted_key')
        if not encrypted_key:
            raise ValueError("No encrypted key in message")

        # Decrypt with RSA
        decrypted_json = self.rsa_decrypt(encrypted_key)
        key_data = json.loads(decrypted_json)

        # Extract and set AES key
        aes_key = base64.b64decode(key_data['aes_key'])
        aes_iv = base64.b64decode(key_data['aes_iv'])
        self.set_aes_key(aes_key, aes_iv)

        return True

    @staticmethod
    def generate_session_id():
        """Generate a unique session ID"""
        return base64.b64encode(get_random_bytes(16)).decode('utf-8')

    @staticmethod
    def hash_password(password):
        """Hash a password using SHA-256"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()


class SecureMessageHandler:
    """Handles secure message transmission with encryption"""

    def __init__(self, crypto_handler):
        self.crypto = crypto_handler
        self.message_counter = 0

    def prepare_message(self, message_dict):
        """Prepare a message for secure transmission"""
        # Add message ID for tracking
        message_dict['msg_id'] = self.message_counter
        self.message_counter += 1

        # Convert to JSON and encrypt
        message_json = json.dumps(message_dict)
        encrypted_content = self.crypto.aes_encrypt(message_json)

        # Create envelope
        envelope = {
            'type': 'encrypted_message',
            'content': encrypted_content,
            'timestamp': os.urandom(8).hex()  # Random value to prevent replay
        }

        return json.dumps(envelope) + '\n'

    def process_message(self, raw_message):
        """Process an incoming encrypted message"""
        try:
            # Parse envelope
            envelope = json.loads(raw_message.strip())

            if envelope.get('type') != 'encrypted_message':
                # Not an encrypted message, return as-is
                return json.loads(raw_message.strip())

            # Decrypt content
            encrypted_content = envelope.get('content')
            if not encrypted_content:
                raise ValueError("No encrypted content in message")

            decrypted_json = self.crypto.aes_decrypt(encrypted_content)
            return json.loads(decrypted_json)

        except Exception as e:
            print(f"Error processing secure message: {e}")
            return None


def test_encryption():
    """Test the encryption functionality"""
    print("Testing encryption module...")

    # Create server and client handlers
    server_crypto = CryptoHandler()
    client_crypto = CryptoHandler()

    # Server generates RSA keypair
    print("1. Server generating RSA keypair...")
    public_key_pem = server_crypto.generate_rsa_keypair()
    print(f"Public key generated: {public_key_pem[:50]}...")

    # Client loads server's public key
    print("\n2. Client loading server's public key...")
    client_crypto.load_rsa_public_key(public_key_pem)

    # Client generates AES key and creates key exchange
    print("\n3. Client generating AES key and creating key exchange...")
    key_exchange_msg = client_crypto.create_key_exchange_message()
    print(f"Key exchange message: {key_exchange_msg}")

    # Server processes key exchange
    print("\n4. Server processing key exchange...")
    server_crypto.process_key_exchange_message(key_exchange_msg)
    print("Server extracted AES key successfully")

    # Test message encryption
    print("\n5. Testing message encryption...")
    test_message = {
        'type': 'packet',
        'protocol': 'TCP',
        'source_ip': '192.168.1.1',
        'data': 'This is sensitive packet data'
    }

    # Client encrypts message
    client_handler = SecureMessageHandler(client_crypto)
    encrypted_msg = client_handler.prepare_message(test_message)
    print(f"Encrypted message: {encrypted_msg[:100]}...")

    # Server decrypts message
    server_handler = SecureMessageHandler(server_crypto)
    decrypted_msg = server_handler.process_message(encrypted_msg.strip())
    print(f"Decrypted message: {decrypted_msg}")

    # Verify
    if decrypted_msg == test_message:
        print("\n✓ Encryption test PASSED!")
    else:
        print("\n✗ Encryption test FAILED!")


if __name__ == "__main__":
    test_encryption()