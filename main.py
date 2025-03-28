import asyncio
import logging
import sys
import websockets
from networking.discovery import PeerDiscovery
from networking.messaging import (
    user_input,
    display_messages,
    receive_peer_messages,
    handle_incoming_connection,
    connections,
    maintain_peer_list,
    initialize_user_config,
)
from networking.file_transfer import update_transfer_progress
from networking.shared_state import peer_usernames, peer_public_keys, shutdown_event

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout
)

async def handle_peer_connection(websocket, path=None):
    """Handle incoming WebSocket connections."""
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
    """Main application loop."""
    await initialize_user_config()

    discovery = PeerDiscovery()
    # Define all tasks
    broadcast_task = asyncio.create_task(discovery.send_broadcasts())
    discovery_task = asyncio.create_task(discovery.receive_broadcasts())
    cleanup_task = asyncio.create_task(discovery.cleanup_stale_peers())
    progress_task = asyncio.create_task(update_transfer_progress())
    maintain_task = asyncio.create_task(maintain_peer_list(discovery))
    input_task = asyncio.create_task(user_input(discovery)) # Pass discovery instance
    display_task = asyncio.create_task(display_messages())

    # Start WebSocket server
    server = await websockets.serve(
        handle_peer_connection,
        "0.0.0.0",
        8765,
        ping_interval=None,
        max_size=10 * 1024 * 1024,  # Set max_size to 10MB (CHANGE APPLIED HERE)
    )
    logging.info("WebSocket server started")

    tasks = [
        broadcast_task,
        discovery_task,
        cleanup_task,
        progress_task,
        maintain_task,
        input_task,
        display_task,
    ]

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Shutting down...")
        shutdown_event.set()
    except asyncio.CancelledError:
        logging.info("Shutdown triggered via /exit. Closing down...")
    finally:
        logging.info("Initiating shutdown process...")

        # Cancel all tasks
        for task in tasks:
            if not task.done():
                task.cancel()
                logging.info(f"Canceled task: {task.get_name()}")

        # Wait for tasks to finish with a timeout
        await asyncio.wait(tasks, timeout=2.0)

        # Close WebSocket server
        logging.info("Closing WebSocket server...")
        server.close()
        await server.wait_closed()
        logging.info("WebSocket server closed.")

        # Close all peer connections
        for peer_ip, websocket in list(connections.items()):
            try:
                if websocket.open:
                    await websocket.close()
                    logging.info(f"Closed connection to {peer_ip}")
            except Exception as e:
                logging.error(f"Error closing connection to {peer_ip}: {e}")
        connections.clear()
        peer_public_keys.clear()
        peer_usernames.clear()

        # Stop discovery
        logging.info("Stopping discovery...")
        discovery.stop()

        # Clean up file transfers
        from networking.file_transfer import active_transfers
        for transfer_id, transfer in list(active_transfers.items()):
            if transfer.file_handle:
                await transfer.file_handle.close()
                logging.info(f"Closed file handle for transfer {transfer_id}")
            del active_transfers[transfer_id]

        logging.info("Application fully shut down.")
        loop = asyncio.get_event_loop()
        loop.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down via interrupt...")
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)