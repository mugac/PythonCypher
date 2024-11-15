import socket
import threading

def receive_from_relay2():
    host = '10.128.40.94'
    port = 54321  # Final receiver listening port (fixed)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print("Final receiver waiting for messages from Relay 2...")

        connection, address = server_socket.accept()
        with connection:
            print(f"Connected by Relay 2 at {address}")
            while True:
                message = connection.recv(1024).decode()
                if not message:
                    break  # Exit if the connection is closed
                print(f"Message received from Relay 2: {message}")

def final_receiver_thread():
    # Start listening for messages
    receive_from_relay2()

if __name__ == "__main__":
    # Start the final receiver thread
    threading.Thread(target=final_receiver_thread).start()
