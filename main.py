import threading
import time
import asyncio
import sys
from networking.discovery import receive_broadcasts, send_broadcasts
from networking.connection import connect_to_peer, send_message, receive_message

peer_list = []
connections = {}

async def handle_peer_connections():
    """
    Establishes connections with discovered peers and starts monitoring them
    """
    while True:
        await asyncio.sleep(5)
        for peer_ip in peer_list:
            if peer_ip not in connections or not connections[peer_ip]:
                print(f"Trying to connect to {peer_ip}")
                connection = await connect_to_peer(peer_ip)
                if connection:
                    connections[peer_ip] = connection
                    # Start a receive handler for this connection
                    asyncio.create_task(handle_messages(peer_ip, connection))

async def handle_messages(peer_ip, connection):
    """
    Handles incoming messages from a specific peer
    """
    try:
        while True:
            message = await receive_message(connection)
            if message:
                print(f"\nMessage from {peer_ip}: {message}")
                print("Enter your message: ", end='', flush=True)
    except Exception as e:
        print(f"Lost connection to {peer_ip}: {e}")
        if peer_ip in connections:
            del connections[peer_ip]

async def chat_input():
  """
  Handles user input for chat messages asynchronously.
  """
  loop = asyncio.get_event_loop() # Get the event loop to use with sys.stdin
  while True:
      print("Enter your message: ", end='', flush=True)  # Prompt before input
      message = await loop.run_in_executor(None, sys.stdin.readline) # Read user input from sys.stdin asynchronusly
      message = message.strip() # remove the new line character
      if message.lower() == 'exit':
          break

      # Send the message to all connected peers
      for peer_ip, connection in connections.items():
          if connection:
              sent = await send_message(connection, message)
              if not sent:
                  print(f"Failed to send message to {peer_ip}")

if __name__ == "__main__":
    # Start broadcast threads
    broadcast_thread = threading.Thread(target=send_broadcasts, daemon=True)
    broadcast_thread.start()
    
    discovery_thread = threading.Thread(target=receive_broadcasts, args=(peer_list,), daemon=True)
    discovery_thread.start()

    # Start async event loop for handling connections and chat
    async def main():
        await asyncio.gather(
            handle_peer_connections(),
            chat_input()
        )

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...")