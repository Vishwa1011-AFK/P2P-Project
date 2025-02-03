import asyncio
import websockets

async def client():
    uri = "ws://192.168.69.14:8765"  # Replace with your server URI
    async with websockets.connect(uri) as websocket:
        print("Connected to server")
        while True:
            message = input("Enter a message (or 'exit'): ")
            if message.lower() == "exit":
                break
            await websocket.send(message)  # send message to the server
            response = await websocket.recv()  # receive response from the server
            print(f"Received: {response}")

if __name__ == "__main__":
    asyncio.run(client())