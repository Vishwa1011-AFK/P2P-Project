import socket

HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
  s.bind((HOST, PORT))
  print(f"Listening on {HOST}:{PORT}")
  while True:
     data, addr = s.recvfrom(1024)
     print(f"Received: {data.decode()} from {addr}")
     s.sendto(data, addr) # echo back to the sender