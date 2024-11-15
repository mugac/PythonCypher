from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate a random 256-bit AES key (32 bytes)
key = os.urandom(32)

# Convert the key to a hexadecimal string and format it with "0x" prefix
formatted_key = "0x" + key.hex()
print("Generated AES Key:", formatted_key)

# Example plaintext data to encrypt
plaintext = b'This is a secret message!'

# Generate a random 128-bit IV (16 bytes) for AES encryption
iv = os.urandom(16)

# Encrypt the plaintext using AES in CBC mode
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Ensure the plaintext is a multiple of block size (16 bytes for AES)
# Padding plaintext to make it a multiple of the block size (AES block size is 16 bytes)
padding_length = 16 - len(plaintext) % 16
padded_plaintext = plaintext + bytes([padding_length]) * padding_length

# Perform the encryption
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

# Output the encrypted data and IV
print("Ciphertext:", ciphertext.hex())
print("IV:", iv.hex())

# Decrypt the ciphertext
decryptor = cipher.decryptor()
decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

# Remove the padding
padding_length = decrypted_data[-1]
decrypted_data = decrypted_data[:-padding_length]

print("Decrypted data:", decrypted_data.decode())
