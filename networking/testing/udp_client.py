import socket
HOST = '127.0.0.1'  # Replace with server IP
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    while True:
        message = input("Enter a message (or 'exit'): ")
        if message.lower() == "exit":
            break
        s.sendto(message.encode(), (HOST, PORT))
        data, addr = s.recvfrom(1024)
        print(f"Received: {data.decode()} from {addr}")