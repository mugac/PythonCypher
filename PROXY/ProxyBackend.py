import socket
import struct
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Server configuration
HOST = '10.128.40.94'  # Server address
PORT = 55712           # Server's port

# Function to generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    return private_key, public_key

# Function to serialize the private key
def serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

# Function to encrypt a message using the server's public key
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Function to send a multipart message
def send_message(client_socket, message):
    message_bytes = message.encode()
    length = len(message_bytes)
    client_socket.sendall(struct.pack('!I', length))
    client_socket.sendall(message_bytes)

# Function to receive a multipart message
def receive_message(client_socket):
    length_data = client_socket.recv(4)
    message_length = struct.unpack('!I', length_data)[0]

    message_data = b''
    while len(message_data) < message_length:
        chunk = client_socket.recv(min(1024, message_length - len(message_data)))
        if not chunk:
            raise ValueError("Failed to receive the complete message.")
        message_data += chunk
    
    return message_data.decode()

# Create and connect the client socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))  # Connect to the server
    print(f"Connected to server at {HOST}:{PORT}")

    # Generate RSA keys for the client
    client_private_key, client_public_key = generate_rsa_keys()

    # Step 1: Receive server's public key
    server_public_key_pem = receive_message(client_socket).encode()
    server_public_key = serialization.load_pem_public_key(server_public_key_pem)

    # Step 2: Send encrypted secret key to the server
    secret_key = "SharedSecret123"  # The secret key to exchange
    encrypted_secret_key = encrypt_message(server_public_key, secret_key)
    send_message(client_socket, encrypted_secret_key.decode())

    print(f"Sent secret key to the server: {secret_key}")

    while True:
        # Input from the user to send to the server
        message = input("You: ")

        # Send the message
        send_message(client_socket, message)

        # Receive acknowledgment or response from the server
        response = receive_message(client_socket)
        print(f"Server: {response}")

        if message.lower() == 'exit':
            print("Closing connection.")
            break
