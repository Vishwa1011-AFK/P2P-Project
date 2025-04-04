import asyncio
import logging
import sys
import websockets
from networking.discovery import PeerDiscovery
from networking.messaging.core import receive_peer_messages, handle_incoming_connection, connections
from networking.messaging.commands import user_input, display_messages, initialize_user_config
from networking.messaging.core import maintain_peer_list
from networking.file_transfer import update_transfer_progress
from networking.shared_state import peer_usernames, peer_public_keys, shutdown_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", stream=sys.stdout)

async def handle_peer_connection(websocket, path=None):
    peer_ip = websocket.remote_address[0]
    logging.info(f"New connection from {peer_ip}")
    try:
        if await handle_incoming_connection(websocket, peer_ip):
            await receive_peer_messages(websocket, peer_ip)
    except Exception as e:
        logging.error(f"Error handling connection from {peer_ip}: {e}")
    finally:
        if peer_ip in connections:
            del connections[peer_ip]

async def main():
    await initialize_user_config()
    discovery = PeerDiscovery()
    tasks = [
        asyncio.create_task(discovery.send_broadcasts()),
        asyncio.create_task(discovery.receive_broadcasts()),
        asyncio.create_task(discovery.cleanup_stale_peers()),
        asyncio.create_task(update_transfer_progress()),
        asyncio.create_task(maintain_peer_list(discovery)),
        asyncio.create_task(user_input(discovery)),
        asyncio.create_task(display_messages()),
    ]
    server = await websockets.serve(handle_peer_connection, "0.0.0.0", 8765, ping_interval=None, max_size=10 * 1024 * 1024)
    logging.info("WebSocket server started")
    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        shutdown_event.set()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        server.close()
        await server.wait_closed()
        for ws in list(connections.values()):
            if ws.open:
                await ws.close()
        connections.clear()
        peer_public_keys.clear()
        peer_usernames.clear()
        discovery.stop()
        logging.info("Application fully shut down.")

if __name__ == "__main__":
    asyncio.run(main())