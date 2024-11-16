import socket

# Server setup
HOST = '10.128.40.94'  # Localhost
PORT = 55231        # Port to listen on

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))  # Bind to the host and port
    server_socket.listen()            # Start listening for connections
    print(f"Server listening on {HOST}:{PORT}...")
    
    conn, addr = server_socket.accept()  # Accept a connection
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)  # Receive up to 1024 bytes
            if not data:
                break
            print(f"Received: {data.decode()}")
            conn.sendall(data)  # Echo back the received data



