import socket
import threading

def send_message_to_relay(message):
    relay1_host = '127.0.0.1'  # Relay 1 address
    relay1_port = 12345  # Relay 1 listening port (fixed)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((relay1_host, relay1_port))
        client_socket.sendall(message.encode())
        print(f"Message sent to Relay 1: {message}")

def sender_thread():
    messages = ["Hello from Sender", "Another message to Relay 1", "Goodbye from Sender"]
    for message in messages:
        send_message_to_relay(message)

if __name__ == "__main__":
    # Start the sender thread
    threading.Thread(target=sender_thread).start()
