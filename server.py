import asyncio
import websockets

async def handle_connection(websocket):
    print("Client connected")
    try:
        async for message in websocket:
            print(f"Received: {message}")
            await websocket.send(f"You said: {message}")  # echo back the message
    except websockets.exceptions.ConnectionClosedError:
        print("Client Disconnected")

async def main():
    async with websockets.serve(handle_connection, "0.0.0.0", 8765): # create a server on port 8765
        print("WebSocket server started")
        await asyncio.Future()  # Keep the server running

if __name__ == "__main__":
    asyncio.run(main())