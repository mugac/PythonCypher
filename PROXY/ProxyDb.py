import socket
import struct
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import os
import sys
import aes
# import pq_ntru
sys.path.append(os.path.abspath("./NTRU"))
# sys.path.append(os.path.abspath("./AES"))

from ntru import generate_keys,encrypt,decrypt






# Server configuration
#HOST = '10.128.40.94'  # Server address
HOST = '127.0.0.1'  # Server address
PORT = 55712           # Server's port



def getkeys():
    filename = 'key.pub'
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
                    print(f"p: {key_data['p']}")
                elif 'q' in line:
                    # Extract and convert to list of integers
                    key_data['q'] = [int(x) for x in line.split(':::')[1].strip().split()]
                    print(f"q: {key_data['q']}")
                elif 'N' in line:
                    # Extract and convert to list of integers
                    key_data['N'] = [int(x) for x in line.split(':::')[1].strip().split()]
                    print(f"N: {key_data['N']}")
                elif 'd' in line:
                    # Extract and convert to list of integers
                    key_data['d'] = [int(x) for x in line.split(':::')[1].strip().split()]
                    print(f"d: {key_data['d']}")
                elif 'h' in line:
                    # Extract and convert to list of integers
                    key_data['h'] = [int(x) for x in line.split(':::')[1].strip().split()]
                    print(f"h: {key_data['h']}")
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

# Function to handle communication with the client
def handle_client(client_socket):
    try:
        while True:
            # Receive the message from the client
            message = receive_message(client_socket)
            print(f"Received: {message}")

                        # Step 1: Read the file and parse the data
            filename = 'key.pub'
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
                            print(f"p: {key_data['p']}")
                        elif 'q' in line:
                            # Extract and convert to list of integers
                            key_data['q'] = [int(x) for x in line.split(':::')[1].strip().split()]
                            print(f"q: {key_data['q']}")
                        elif 'N' in line:
                            # Extract and convert to list of integers
                            key_data['N'] = [int(x) for x in line.split(':::')[1].strip().split()]
                            print(f"N: {key_data['N']}")
                        elif 'd' in line:
                            # Extract and convert to list of integers
                            key_data['d'] = [int(x) for x in line.split(':::')[1].strip().split()]
                            print(f"d: {key_data['d']}")
                        elif 'h' in line:
                            # Extract and convert to list of integers
                            key_data['h'] = [int(x) for x in line.split(':::')[1].strip().split()]
                            print(f"h: {key_data['h']}")
            json_data = json.dumps(key_data, separators=(',', ':'))


            

            # Printing the serialized data in one line
#print(json_data)    
            send_message(client_socket, json_data)
            res = receive_message(client_socket)
            if res == json_data:
                send_message(client_socket, "200")
            # Exit condition for the server: if the message is "exit"

            #validovat
            aes_key =  bytes.fromhex((decrypt("key",receive_message(client_socket)))[2:])
            # print(receive_message(client_socket))
            iv = bytes.fromhex(receive_message(client_socket))
            print(aes_key)
            os.remove("./key.priv")
            os.remove("./key.pub")
   

            while True:
                #encrypt messages using aes
                # Encrypt the plaintext using AES in CBC mode
               
               # message to be sent
                message = "poggers"


                # FUNCTION

                # Convert message to bytes
                message_bytes = message.encode('utf-8')

                # Padding plaintext to make it a multiple of the block size (AES block size is 16 bytes)
                padding_length = 16 - len(message_bytes) % 16
                padded_plaintext = message_bytes + bytes([padding_length]) * padding_length

                # Create the cipher object
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                # Perform the encryption
                ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

                  #  END OF FUNCTION

                # Output the encrypted text
                #send_message(client_socket,"0x" + ciphertext.hex())
                send_message(client_socket,ciphertext.hex())

                # LISTEN HERE FOR DB

            
            

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