import socket
import threading
import select
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

terminateAll = False

class ClientThread(threading.Thread):
    def __init__(self, clientSocket, targetHost, targetPort, aes_key, iv):
        threading.Thread.__init__(self)
        self.__clientSocket = clientSocket
        self.__targetHost = targetHost
        self.__targetPort = targetPort
        self.__aes_key = aes_key
        self.__iv = iv
        
    def encrypt_data(self, data):
        # Encrypt the data using AES in CBC mode
        cipher = Cipher(algorithms.AES(self.__aes_key), modes.CBC(self.__iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding plaintext to make it a multiple of the block size (AES block size is 16 bytes)
        padding_length = 16 - len(data) % 16
        padded_data = data + bytes([padding_length]) * padding_length
        
        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    def decrypt_data(self, data):
        # Decrypt the data using AES in CBC mode
        cipher = Cipher(algorithms.AES(self.__aes_key), modes.CBC(self.__iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        
        # Remove padding
        padding_length = decrypted_data[-1]
        return decrypted_data[:-padding_length]

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
                            # Decrypt client data before forwarding to the target host
                            decrypted_data = self.decrypt_data(data)
                            targetHostData += decrypted_data
                        else:
                            terminate = True
                elif inp == targetHostSocket:
                    try:
                        data = targetHostSocket.recv(4096)
                    except Exception as e:
                        print(f"Exception while receiving from target host: {e}")
                        
                    if data:
                        if len(data) > 0:
                            # Decrypt target host data before forwarding to the client
                            decrypted_data = self.decrypt_data(data)
                            clientData += decrypted_data
                        else:
                            terminate = True
                        
            for out in outputsReady:
                if out == self.__clientSocket and len(clientData) > 0:
                    try:
                        # Encrypt client data before sending it back to the client
                        encrypted_data = self.encrypt_data(clientData)
                        bytesWritten = self.__clientSocket.send(encrypted_data)
                        if bytesWritten > 0:
                            clientData = clientData[bytesWritten:]
                    except Exception as e:
                        print(f"Exception while sending to client: {e}")
                elif out == targetHostSocket and len(targetHostData) > 0:
                    try:
                        # Encrypt target host data before sending it to the target host
                        encrypted_data = self.encrypt_data(targetHostData)
                        bytesWritten = targetHostSocket.send(encrypted_data)
                        if bytesWritten > 0:
                            targetHostData = targetHostData[bytesWritten:]
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
    localPort = 59123
    targetHost = '10.128.40.94'
    targetPort = 55213
    
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
