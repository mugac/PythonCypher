import socket
import struct
import json

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

# Create a socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    try:
        client_socket.connect((HOST, PORT))  # Connect to the server
        print(f"Connected to server at {HOST}:{PORT}")
        
        while True:
            # Input from the user to send to the server
            message = input("You: ")

            # Send the message (multipart)
            send_message(client_socket, message)

            # Receive acknowledgment or response from the server (multipart)
            response = receive_message(client_socket)
            deserializedResponse = json.loads(response)
            print(f"Server: {deserializedResponse}")
            
            print(deserializedResponse.get('p'))
            p, q, N, d, h = deserializedResponse.get('p'), deserializedResponse.get('q'), deserializedResponse.get('N'), deserializedResponse.get('d'), deserializedResponse.get('h')  
            
            with open('key.pub', 'w') as file:
                file.write(f"# p ::: {p}\n")
                file.write(f"# q ::: {q}\n")
                file.write(f"# N ::: {N}\n")
                file.write(f"# d ::: {d}\n")
                file.write(f"# h ::: {h}\n")



            # Exit condition: If user types 'exit', break the loop
            if message.lower() == 'exit':
                print("Closing connection.")
                break

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
