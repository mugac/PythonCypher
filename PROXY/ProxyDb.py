import socket
import struct
import threading

# Server configuration
HOST = '10.128.40.94'  # Server address
PORT = 55712           # Server's port

# Helper function to send a multipart message
def send_message(client_socket, message):
    # Encode the message to bytes
    message_bytes = message.encode()

    # Send the length of the message first (this helps with reassembly on the receiving side)
    length = len(message_bytes)
    client_socket.sendall(struct.pack('!I', length))  # '!I' is for network byte order (4 bytes for length)

    # Now send the actual message in chunks if it's large
    client_socket.sendall(message_bytes)
    print(f"Sent: {message}")

# Helper function to receive a multipart message
def receive_message(client_socket):
    # First, receive the length of the incoming message
    length_data = client_socket.recv(4)
    if len(length_data) < 4:
        raise ValueError("Failed to receive the message length.")
    
    # Unpack the length (this tells us how much data to expect)
    message_length = struct.unpack('!I', length_data)[0]

    # Now receive the actual message data in chunks (if necessary)
    message_data = b''
    while len(message_data) < message_length:
        chunk = client_socket.recv(min(1024, message_length - len(message_data)))
        if not chunk:
            raise ValueError("Failed to receive the complete message.")
        message_data += chunk
    
    return message_data.decode()

# Function to handle communication with the client
def handle_client(client_socket):
    try:
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

    while True:
        # Accept incoming client connections
        client_socket, addr = server_socket.accept()
        print(f"Connected to {addr}")
        # Handle the client in a separate thread so the server can listen and send at the same time
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()