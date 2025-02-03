import socket

HOST = '0.0.0.0' # Listen on all available interfaces
PORT = 65432  # Choose a non-standard port

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT)) # Bind the socket to the host and port
    s.listen()  # Start listening for connections
    print(f"Listening on {HOST}:{PORT}")

    conn, addr = s.accept() # Accepts new connection requests
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)  # receive up to 1024 bytes of data
            if not data:
                break # If no data break the connection
            print(f"Received: {data.decode()}")
            conn.sendall(data)  # Send the received data back
        print(f"Closing connection from {addr}")