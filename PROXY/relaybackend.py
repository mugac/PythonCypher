import socket

def relay1():
    relay1_listen_port = 12345  # Port to receive messages from the sender
    relay2_host = '127.0.0.1'  # Relay 2 address
    relay2_port = 23456  # Relay 2 listening port for Relay 1

    # Set up persistent connection to Relay 2
    relay2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay2_socket.connect((relay2_host, relay2_port))
    print("Relay 1 connected to Relay 2")

    try:
        # Set up the relay server to listen for messages from the sender
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as relay1_socket:
            relay1_socket.bind(('127.0.0.1', relay1_listen_port))
            relay1_socket.listen(5)
            print("Relay 1 listening for messages from sender...")

            while True:
                # Accept a new connection from the sender
                connection, sender_address = relay1_socket.accept()
                with connection:
                    print(f"Connected by sender at {sender_address}")
                    # Receive message from sender
                    message = connection.recv(1024).decode()
                    print("Message received from sender:", message)

                    # Forward message to Relay 2
                    relay2_socket.sendall(message.encode())
                    print("Message forwarded to Relay 2.")
    finally:
        relay2_socket.close()  # Ensure the connection is closed when done

if __name__ == "__main__":
    relay1()
