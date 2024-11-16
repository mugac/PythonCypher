import socket
import struct
import json
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import threading
# import pq_ntru
sys.path.append(os.path.abspath("./NTRU"))
# sys.path.append(os.path.abspath("./AES"))

from ntru import generate_keys,encrypt,decrypt

# Server configuration
#HOST = '10.128.40.94'  # Server address
HOST = '127.0.0.1'  # Server address
PORT = 55712           # Server's port

class ClientThread(threading.Thread):
    def __init__(self, clientSocket, targetHost, targetPort,aes_key,iv):
        threading.Thread.__init__(self)
        self.__clientSocket = clientSocket
        self.__targetHost = targetHost
        self.__targetPort = targetPort
        self.__aeskey = aes_key
        self.__iv = iv


    def run(self):
        print("Client Thread started")
        self.__clientSocket.setblocking(0)

        targetHostSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        targetHostSocket.connect((self.__targetHost, self.__targetPort))
        targetHostSocket.setblocking(0)

        clientData = b''
        targetHostData = b''
        terminate = False
        while not terminate and not terminateAll:
            inputs = [self.__clientSocket, targetHostSocket]
            outputs = []

            if len(clientData) > 0:
                outputs.append(self.__clientSocket)

            if len(targetHostData) > 0:
                outputs.append(targetHostSocket)

            try:
                inputsReady, outputsReady, errorsReady = select.select(inputs, outputs, [], 1.0)
            except Exception as e:
                print(f"Exception during select: {e}")
                break

            for inp in inputsReady:
                if inp == self.__clientSocket:
                    try:
                        data = self.__clientSocket.recv(4096)
                    except Exception as e:
                        print(f"Exception while receiving from client: {e}")

                    if data:
                        if len(data) > 0:
                            targetHostData += data
                        else:
                            terminate = True
                elif inp == targetHostSocket:
                    try:
                        data = targetHostSocket.recv(4096)
                    except Exception as e:
                        print(f"Exception while receiving from target host: {e}")

                    if data:
                        if len(data) > 0:
                            clientData += data
                        else:
                            terminate = True

            for out in outputsReady:
                if out == self.__clientSocket and len(clientData) > 0:
                    try:
                        # AES decryption of data received from target host
                        key = b'YourSharedAESKey123'  # This should be the shared AES key (hardcoded for now)
                        decrypted_data =  self.aes_encrypt(cipheredtext)
                        self.__clientSocket.send(decrypted_data)
                        clientData = b''  # Clear data after sending
                       
                    except Exception as e:
                        print(f"Exception while sending to client: {e}")
                elif out == targetHostSocket and len(targetHostData) > 0:
                    try:
                        # AES encryption of data from the client
                        iv = os.urandom(16)  # Generate new IV for each message
                        key = b'YourSharedAESKey123'  # Shared AES key (this should be securely exchanged)
                        ciphertext = aes_encrypt(aes_key, iv, targetHostData)
                        targetHostSocket.send(iv + ciphertext)  # Send IV + ciphertext
                        targetHostData = b''  # Clear data after sending
                    except Exception as e:
                        print(f"Exception while sending to target host: {e}")

        self.__clientSocket.close()
        targetHostSocket.close()
        print("ClientThread terminating")

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
            generate_keys("key", mode="moderate", skip_check=True, debug=True)
            # time.sleep(2)
            pub_key = getkeys("key.pub")
            # Send the message (multipart)
            send_message(client_socket, message)

            # Receive acknowledgment or response from the server (multipart)
            response = receive_message(client_socket)
            deserializedResponse = json.loads(response)
            with open('key2.pub', 'w') as file:
                #for key in deserializedResponse:
                    file.write(f"# p ::: {' '.join(str(x) for x in deserializedResponse["p"])}\n")
                    file.write(f"# q ::: {' '.join(str(x) for x in deserializedResponse["q"])}\n")
                    file.write(f"# N ::: {' '.join(str(x) for x in deserializedResponse["N"])}\n")
                    file.write(f"# d ::: {' '.join(str(x) for x in deserializedResponse["d"])}\n")
                    file.write(f"# h ::: {' '.join(str(x) for x in deserializedResponse["h"])} ")
            send_message(client_socket, response)
            res = receive_message(client_socket)
            if res != "200":
                print("Connection not established")
                break
            print("key exchanged")

            # Generate aes key
            # Generate a random 256-bit AES key (32 bytes)
            aes_key = os.urandom(32)

            # Convert the key to a hexadecimal string and format it with "0x" prefix
            formatted_key = "0x" + aes_key.hex()
            print("Generated AES Key:", formatted_key)

            #iv
            iv = os.urandom(16)

            #encrypt using ntru and send
            encrypted_aes_key = encrypt("key2",formatted_key)

            send_message(client_socket,encrypted_aes_key)
            send_message(client_socket,iv.hex())

            os.remove("./key2.pub")


            #repeater
            localHost = '10.128.40.94'
            localPort = 59123
            targetHost = '10.128.40.94'
            targetPort = 55213


            exited = False
            while True:
                # Decrypt the ciphertext
                
                cipheredtext = bytes.fromhex(receive_message(client_socket))

                # FUNCTION
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(cipheredtext) + decryptor.finalize()
                # Remove the padding
                padding_length = decrypted_data[-1]
                decrypted_data = decrypted_data[:-padding_length]
                #  END OF FUNCTION

                print("Decrypted data:", decrypted_data.decode())
                # decrypt messages using aes
                if cipheredtext == "exit":
                    exited = True
                    break
                
                #repeater
                 # Replace with the actual AES key and IV from the handshake
                aes_key = b'your_16_byte_aes_key'  # 16 bytes for AES-128, adjust as needed
                iv = b'your_16_byte_iv'  # 16 bytes IV for CBC mode
                
                serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                serverSocket.bind((localHost, localPort))
                serverSocket.listen(5)
                print("Waiting for client...")
                while True:
                    try:
                        clientSocket, address = serverSocket.accept()
                    except KeyboardInterrupt:
                        print("\nTerminating...")
                        terminateAll = True
                        break
                    # Handle the client in a separate thread
                    ClientThread(clientSocket, targetHost, targetPort, aes_key, iv).start()
                    
                serverSocket.close()




                #LISTEN HERE FOR SQL STATEMENTS
          


            # Exit condition: If user types 'exit', break the loop
            if exited == True:
                print("Closing connection.")
                break

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
