import asyncio
import logging
import sys
import websockets
import ssl
import os.path
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
from networking.shared_state import (
    active_transfers, message_queue, connections, user_data, peer_public_keys,
    peer_usernames, peer_device_ids, shutdown_event, connections_lock
)
from networking.messaging import get_config_directory 


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout
)

async def handle_peer_connection(websocket, path=None):
    peer_ip = websocket.remote_address[0]
    logging.info(f"New connection from {peer_ip}")
    
    websocket.ping_interval = 30.0  
    websocket.ping_timeout = 10.0  
    
    try:
        if await handle_incoming_connection(websocket, peer_ip):
            await receive_peer_messages(websocket, peer_ip)
    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"Connection from {peer_ip} closed normally")
    except websockets.exceptions.ConnectionClosedError as e:
        logging.warning(f"Connection from {peer_ip} closed with error: {e}")
    except Exception as e:
        logging.error(f"Error handling connection from {peer_ip}: {e}")
    finally:
        async with connections_lock:
            if peer_ip in connections:
                del connections[peer_ip]

async def main():
    """Main application loop."""
    await initialize_user_config()

    discovery = PeerDiscovery()
    broadcast_task = asyncio.create_task(discovery.send_broadcasts())
    discovery_task = asyncio.create_task(discovery.receive_broadcasts())
    cleanup_task = asyncio.create_task(discovery.cleanup_stale_peers())
    progress_task = asyncio.create_task(update_transfer_progress())
    maintain_task = asyncio.create_task(maintain_peer_list(discovery))
    input_task = asyncio.create_task(user_input(discovery))
    display_task = asyncio.create_task(display_messages())
    
    config_dir = get_config_directory()
    cert_path = os.path.join(config_dir, "cert.pem")
    key_path = os.path.join(config_dir, "key.pem")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
    logging.warning("SSL certificates not found! Creating self-signed certificates...")
    os.makedirs(config_dir, exist_ok=True)
    os.system(f"openssl req -newkey rsa:2048 -nodes -keyout {key_path} -x509 -days 365 -out {cert_path} -subj '/CN=localhost'")
    logging.info(f"Self-signed certificates created in {config_dir}")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(cert_path, key_path)

    server = await websockets.serve(
        handle_peer_connection,
        "0.0.0.0",
        8765,
        ping_interval=None,
        max_size=10 * 1024 * 1024,
        ssl=ssl_context  
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

        async with connections_lock:
            for peer_ip, websocket in list(connections.items()):
                try:
                    if websocket.open:
                        await websocket.close(code=1001, reason="Application shutting down")
                        logging.info(f"Sent clean shutdown notification to {peer_ip}")
                except Exception as e:
                    logging.error(f"Error during clean closure to {peer_ip}: {e}")
        
        for task in tasks:
            if not task.done():
                task.cancel()
                logging.info(f"Canceled task: {task.get_name()}")

        await asyncio.wait(tasks, timeout=5.0)

        logging.info("Closing WebSocket server...")
        server.close()
        await server.wait_closed()
        logging.info("WebSocket server closed.")

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

        logging.info("Stopping discovery...")
        discovery.stop()

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