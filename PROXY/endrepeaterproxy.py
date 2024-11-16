import socket
import threading
import select
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


terminateAll = False

class ClientThread(threading.Thread):
    def __init__(self, clientSocket, targetHost, targetPort):
        threading.Thread.__init__(self)
        self.__clientSocket = clientSocket
        self.__targetHost = targetHost
        self.__targetPort = targetPort
        self.__aes_key= b"\xbe}\xdc\xab\xbe\x1d\x82\xb9C\xba\xfd\xe0>n\xc7K\xb6\xe1\x96\x17~\xeeu'\xb4k%Z\xdeQD\x9a"
        self.__iv = b'y\x8b\xd3\x005\xb3\xd4s\xa2\xca\xe9\x8dHHB\xd1'
        
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
                            try:
                                # Ensure that the data length is a multiple of the block size
                                if len(data) % 16 != 0:
                                    raise ValueError(f"Ciphertext length is not a multiple of block size (16 bytes). {data}")

                                cipher = Cipher(algorithms.AES(self.__aes_key), modes.CBC(self.__iv), backend=default_backend())
                                decryptor = cipher.decryptor()
                                decrypted_data = decryptor.update(data) + decryptor.finalize()

                                # Check for padding
                                padding_length = decrypted_data[-1]
                                decrypted_data = decrypted_data[:-padding_length]  # Remove the padding

                                clientData += decrypted_data

                            except Exception as e:
                                print(f"Failed decryption: {e}")
                        else:
                            terminate = True
                        
            for out in outputsReady:
                if out == self.__clientSocket and len(clientData) > 0:
                    try:
                        #encrypt data here
                                                # Convert message to bytes
                 #       message_bytes = message.encode('utf-8')

                        # Padding plaintext to make it a multiple of the block size (AES block size is 16 bytes)
                 

                        # Step 1: Decode the UTF-8 bytes into text (string)
                        decoded_text = clientData.decode('utf-8')

                        # Step 2: Re-encode the decoded text back into UTF-8 bytes
                        reencoded_bytes = decoded_text.encode('utf-8')



                        padding_length = 16 - len(reencoded_bytes) % 16
                        padded_plaintext = reencoded_bytes + bytes([padding_length]) * padding_length
                        print(f"Padded {padded_plaintext}")

                        # Create the cipher object
                        cipher = Cipher(algorithms.AES( self.__aes_key), modes.CBC(self.__iv), backend=default_backend())
                        encryptor = cipher.encryptor()
                        

                        # Perform the encryption
                        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
                        print(f"Padded {ciphertext}")
                        bytesWritten = self.__clientSocket.send(ciphertext)
                        if bytesWritten > 0:
                            clientData = clientData[bytesWritten:]
                    except Exception as e:
                        print(f"Exception while sending to client: {e}")
                elif out == targetHostSocket and len(targetHostData) > 0:
                    try:
                                         # Step 1: Decode the UTF-8 bytes into text (string)
                        decoded_text = clientData.decode('utf-8')

                        # Step 2: Re-encode the decoded text back into UTF-8 bytes
                        reencoded_bytes = decoded_text.encode('utf-8')



                        padding_length = 16 - len(reencoded_bytes) % 16
                        padded_plaintext = reencoded_bytes + bytes([padding_length]) * padding_length
                        print(f"Padded {padded_plaintext}")

                        # Create the cipher object
                        cipher = Cipher(algorithms.AES( self.__aes_key), modes.CBC(self.__iv), backend=default_backend())
                        encryptor = cipher.encryptor()
                        

                        # Perform the encryption
                        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
                        print(f"Padded {ciphertext}")
                        bytesWritten = self.__clientSocket.send(ciphertext)
                        bytesWritten = targetHostSocket.send(ciphertext)
                        if bytesWritten > 0:
                            targetHostData = targetHostData[bytesWritten:]
                    except Exception as e:
                        print(f"Exception while sending to target host: {e}")
        
        self.__clientSocket.close()
        targetHostSocket.close()
        print("ClientThread terminating")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print('Usage:\n\tpython SimpleTCPRedirector <host> <port> <remote host> <remote port>')
        print('Example:\n\tpython SimpleTCPRedirector localhost 8080 www.google.com 80')
        sys.exit(0)        
        
    localHost = sys.argv[1]
    localPort = int(sys.argv[2])
    targetHost = sys.argv[3]
    targetPort = int(sys.argv[4])
        
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
