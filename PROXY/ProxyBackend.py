import socket
import struct
import json
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
# import pq_ntru
sys.path.append(os.path.abspath("./NTRU"))
# sys.path.append(os.path.abspath("./AES"))

from ntru import generate_keys,encrypt,decrypt

# Server configuration
#HOST = '10.128.40.94'  # Server address
HOST = '127.0.0.1'  # Server address
PORT = 55712           # Server's port



def getkeys(filename):
 #   filename = 'key.pub'
    key_data = {'p': [], 'q': [], 'N': [], 'd': [], 'h': []}
    # Open and read the file line by line
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()  # Remove leading and trailing whitespace
            
            if line.startswith('#'):
                # Remove the '#' comment symbol and split the line into key and value
                line = line[2:].strip()  # Remove the '# ' at the start
                
                # Check for the specific keys and process them
                if 'p' in line:
                    # Extract and convert to list of integers
                    key_data['p'] = [int(x) for x in line.split(':::')[1].strip().split()]
                elif 'q' in line:
                    # Extract and convert to list of integers
                    key_data['q'] = [int(x) for x in line.split(':::')[1].strip().split()]
                elif 'N' in line:
                    # Extract and convert to list of integers
                    key_data['N'] = [int(x) for x in line.split(':::')[1].strip().split()]
                elif 'd' in line:
                    # Extract and convert to list of integers
                    key_data['d'] = [int(x) for x in line.split(':::')[1].strip().split()]
                elif 'h' in line:
                    # Extract and convert to list of integers
                    key_data['h'] = [int(x) for x in line.split(':::')[1].strip().split()]
    json_data = json.dumps(key_data, separators=(',', ':'))
    return json_data


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

    #        generate new pair of keys
    #        generate_keys("key", mode="moderate", skip_check=True, debug=True)
          #  generate_keys("key", mode="moderate", skip_check=True, debug=True)
            time.sleep(2)
            pub_key = getkeys("key.pub")
            # Send the message (multipart)
            send_message(client_socket, message)

            # Receive acknowledgment or response from the server (multipart)
            response = receive_message(client_socket)
            deserializedResponse = json.loads(response)
            with open('key2.pub', 'w') as file:
                for key in deserializedResponse:
                    
                    file.write(f"# {key} ::: {' '.join(str(x) for x in deserializedResponse[key])}\n")
            send_message(client_socket, response)
            res = receive_message(client_socket)
            if res != "200":
                print("Connection not established")
                break
            print("key exchanged")

            # Generate aes key
            # Generate a random 256-bit AES key (32 bytes)
            key = os.urandom(32)

            # Convert the key to a hexadecimal string and format it with "0x" prefix
            formatted_key = "0x" + key.hex()
            print("Generated AES Key:", formatted_key)

            #encrypt using ntru and send
            encrypted_aes_key = encrypt("key2",formatted_key)

            send_message(client_socket,encrypted_aes_key)

            # os.remove("./key2.pub")
          


            # Exit condition: If user types 'exit', break the loop
            if message.lower() == 'exit':
                print("Closing connection.")
                break

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
