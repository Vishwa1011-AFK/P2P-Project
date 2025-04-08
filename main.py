import asyncio
import logging
import sys
import websockets
from websockets.connection import State
from networking.discovery import PeerDiscovery
from networking.messaging.core import receive_peer_messages, handle_incoming_connection, connections
from networking.messaging.commands import user_input, display_messages, initialize_user_config
from networking.messaging.core import maintain_peer_list
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
        asyncio.create_task(maintain_peer_list(discovery)),
        asyncio.create_task(user_input(discovery)),
        asyncio.create_task(display_messages()),
    ]
    server = await websockets.serve(
        handle_peer_connection, "0.0.0.0", 8765, ping_interval=None, max_size=10 * 1024 * 1024
    )
    logging.info("WebSocket server started")
    try:
        # Run until shutdown_event is set
        await shutdown_event.wait()
    finally:
        logging.info("Shutdown initiated...")
        # Cancel all tasks
        for task in tasks:
            if not task.done():
                task.cancel()
        # Close server
        server.close()
        await server.wait_closed()
        # Close all WebSocket connections
        close_tasks = [
            ws.close(code=1001, reason="Server shutting down")
            for ws in connections.values()
            if ws.state == State.OPEN
        ]
        if close_tasks:
            await asyncio.gather(*close_tasks, return_exceptions=True)
        # Wait for tasks to finish with a timeout
        try:
            await asyncio.wait(tasks, timeout=2)
        except asyncio.TimeoutError:
            logging.info("Some tasks did not complete in time, proceeding with shutdown.")
        # Clean up resources
        connections.clear()
        peer_public_keys.clear()
        peer_usernames.clear()
        discovery.stop()
        # Shut down the default executor
        loop = asyncio.get_event_loop()
        await loop.shutdown_default_executor()
        logging.info("Application fully shut down.")

if __name__ == "__main__":
    asyncio.run(main())