from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_key():
    # Generate a random 256-bit (32-byte) key
    return get_random_bytes(32)

def aes_encrypt(plaintext, key):
    # Create an AES cipher object with the provided key and AES.MODE_ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad the plaintext to match the block size (128 bits or 16 bytes for AES)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext


def aes_decrypt(ciphertext, key):
    # Create an AES cipher object with the provided key and AES.MODE_ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt(ciphertext)
    # Unpad the decrypted data
    plaintext = unpad(decrypted_data, AES.block_size)
    return plaintext.decode('utf-8')


# Example usage:
plaintext_message = "Hello, AES Encryption!"
# Generate a random key
encryption_key = generate_key()
# Encrypt the message
encrypted_message = aes_encrypt(plaintext_message, encryption_key)
print(f"Encrypted Message: {encrypted_message}")

# Decrypt the message
decrypted_message = aes_decrypt(encrypted_message, encryption_key)
print(f"Decrypted Message: {decrypted_message}")