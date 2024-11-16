import socket

# Server setup
HOST = '10.128.40.94'  # Localhost
PORT = 12345            # Port to listen on
TARGET_HOST = '127.0.0.1'  # Target server address
TARGET_PORT = 55712     # Port to forward data to

# Create a server socket to listen for incoming connections
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))  # Bind to the host and port
    server_socket.listen()            # Start listening for connections
    print(f"Server listening on {HOST}:{PORT}...")

    conn, addr = server_socket.accept()  # Accept a connection
    with conn:
        print(f"Connected by {addr}")
        
        # Create a socket to send data to the target server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_socket:
            target_socket.connect((TARGET_HOST, TARGET_PORT))  # Connect to the target server
            
            while True:
                data = conn.recv(1024)  # Receive up to 1024 bytes from the client
                if not data:
                    break
                
                print(f"Received: {data.decode()}")
                
                # Forward the data to the target server
                target_socket.sendall(data)
                print(f"Sent to target server at {TARGET_HOST}:{TARGET_PORT}")
                
                # Optionally, you can handle a response from the target server here
                # If the target server responds and you want to send the response back to the client:
                # response = target_socket.recv(1024)  # Receive response from target server
            
