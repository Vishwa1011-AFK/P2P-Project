import socket

HOST = '127.0.0.1'  # Replace with server IP
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))  # Connect to the server
    while True:
        message = input("Enter a message (or 'exit'): ")
        if message.lower() == "exit":
            break
        s.sendall(message.encode())  # Send the message
        data = s.recv(1024)   # receive the response from the server
        print(f"Received: {data.decode()}")