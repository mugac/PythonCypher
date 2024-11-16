import socket
import threading
import select
import sys
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
sys.path.append(os.path.abspath("./NTRU"))
from ntru import generate_keys, encrypt, decrypt

terminateAll = False

# Helper function to send a multipart message
def send_message(socket, message):
    message_bytes = message.encode()
    length = len(message_bytes)
    socket.sendall(struct.pack('!I', length))  # Send the length first (4 bytes)
    socket.sendall(message_bytes)

# Helper function to receive a multipart message
def receive_message(socket):
    length_data = socket.recv(4)
    if len(length_data) < 4:
        raise ValueError("Failed to receive the message length.")
    message_length = struct.unpack('!I', length_data)[0]
    message_data = b''
    while len(message_data) < message_length:
        chunk = socket.recv(min(1024, message_length - len(message_data)))
        if not chunk:
            raise ValueError("Failed to receive the complete message.")
        message_data += chunk
    return message_data.decode()

# AES Decryption
def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove padding
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    return decrypted_data

# AES Encryption
def aes_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = plaintext + bytes([16 - len(plaintext) % 16]) * (16 - len(plaintext) % 16)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

class ClientThread(threading.Thread):
    def __init__(self, clientSocket, targetHost, targetPort):
        threading.Thread.__init__(self)
        self.__clientSocket = clientSocket
        self.__targetHost = targetHost
        self.__targetPort = targetPort

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
                        iv = clientData[:16]  # Extract IV (first 16 bytes)
                        ciphertext = clientData[16:]  # Rest is the ciphertext
                        key = b'YourSharedAESKey123'  # This should be the shared AES key (hardcoded for now)
                        decrypted_data = aes_decrypt(key, iv, ciphertext)
                        self.__clientSocket.send(decrypted_data)
                        clientData = b''  # Clear data after sending
                    except Exception as e:
                        print(f"Exception while sending to client: {e}")
                elif out == targetHostSocket and len(targetHostData) > 0:
                    try:
                        # AES encryption of data from the client
                        iv = os.urandom(16)  # Generate new IV for each message
                        key = b'YourSharedAESKey123'  # Shared AES key (this should be securely exchanged)
                        ciphertext = aes_encrypt(key, iv, targetHostData)
                        targetHostSocket.send(iv + ciphertext)  # Send IV + ciphertext
                        targetHostData = b''  # Clear data after sending
                    except Exception as e:
                        print(f"Exception while sending to target host: {e}")

        self.__clientSocket.close()
        targetHostSocket.close()
        print("ClientThread terminating")

if __name__ == '__main__':
    # if len(sys.argv) != 5:
    #     print('Usage:\n\tpython SimpleTCPRedirector <host> <port> <remote host> <remote port>')
    #     print('Example:\n\tpython SimpleTCPRedirector localhost 8080 www.google.com 80')
    #     sys.exit(0)

    localHost = '10.128.40.94'
    localPort = 55712
    targetHost = '10.128.40.94'
    targetPort = 59123

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
        ClientThread(clientSocket, targetHost, targetPort).start()

    serverSocket.close()
