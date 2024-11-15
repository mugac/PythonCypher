import socket
import threading
import time

def connect_with_retry(host, port, retries=5, delay=2):
    """Attempt to connect with retries."""
    for attempt in range(retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            print(f"Connected to {host}:{port} on attempt {attempt + 1}")
            return sock
        except socket.error:
            print(f"Connection to {host}:{port} failed, retrying in {delay} seconds...")
            time.sleep(delay)
    raise ConnectionError(f"Could not connect to {host}:{port} after {retries} attempts")

def receive_from_relay1_and_forward_to_receiver(connection, final_receiver_socket):
    """Handles receiving messages from Relay 1 and forwarding to Final Receiver."""
    while True:
        message = connection.recv(1024).decode()
        if message:
            print(f"Relay 2 received message: {message}")
            final_receiver_socket.sendall(message.encode())
        else:
            break

def relay2_thread():
    relay2_listen_port = 23456  # Port to receive messages from Relay 1
    final_receiver_host = '127.0.0.1'  # Final receiver address
    final_receiver_port = 54321  # Final receiver listening port for Relay 2

    # Persistent connection to Final Receiver with retries
    final_receiver_socket = connect_with_retry(final_receiver_host, final_receiver_port)
    print("Relay 2 connected to Final Receiver")

    try:
        # Set up the relay to listen for messages from Relay 1
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as relay2_socket:
            relay2_socket.bind(('127.0.0.1', relay2_listen_port))
            relay2_socket.listen(5)
            print("Relay 2 listening for messages from Relay 1...")

            while True:
                connection, relay1_address = relay2_socket.accept()
                print(f"Relay 2 connected by Relay 1 at {relay1_address}")
                # Handle receiving and forwarding using a thread
                threading.Thread(target=receive_from_relay1_and_forward_to_receiver, args=(connection, final_receiver_socket)).start()
    finally:
        final_receiver_socket.close()

if __name__ == "__main__":
    # Start the relay 2 thread
    threading.Thread(target=relay2_thread).start()
