import socket
import struct
import threading
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

    # Return both private and public keys
    return private_key, public_key

# Function to serialize the public key to send it to the client
def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

# Function to decrypt messages using the private key
def decrypt_message(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

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

# Function to handle communication with the client
def handle_client(client_socket, server_private_key):
    try:
        # Step 1: Send public key to the client
        private_key, public_key = generate_rsa_keys()
        public_key_pem = serialize_public_key(public_key)
        send_message(client_socket, public_key_pem.decode())

        # Step 2: Receive the encrypted secret key from the client
        encrypted_secret_key = receive_message(client_socket).encode()
        secret_key = decrypt_message(server_private_key, encrypted_secret_key)

        # Now the server and client share a secret key securely
        print(f"Received secret key from client: {secret_key.decode()}")

        while True:
            # Receive the message from the client
            message = receive_message(client_socket)
            print(f"Received: {message}")

            # Respond to the client
            response = "Message received!"  # Just an example response
            send_message(client_socket, response)
            
            # Exit condition for the server: if the message is "exit"
            if message.lower() == 'exit':
                print("Closing connection.")
                break

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()  # Close the connection when done

# Create and bind the server socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))  # Bind to address and port
    server_socket.listen()            # Start listening for connections
    print(f"Server listening on {HOST}:{PORT}...")

    # Generate RSA keys for the server
    server_private_key, server_public_key = generate_rsa_keys()

    while True:
        # Accept incoming client connections
        client_socket, addr = server_socket.accept()
        print(f"Connected to {addr}")
        
        # Handle the client in a separate thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket, server_private_key))
        client_thread.start()
