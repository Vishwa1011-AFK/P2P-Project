# main.py
import asyncio
import logging
import sys
import websockets
from websockets.connection import State
from websockets.exceptions import ConnectionClosedOK
from networking.discovery import PeerDiscovery
from networking.messaging.core import handle_incoming_connection, maintain_peer_list
from networking.messaging.commands import user_input, display_messages, initialize_user_config
from networking.shared_state import (
    connections,
    peer_public_keys,
    peer_usernames,
    peer_device_ids,
    username_to_ip,
    discovered_peers_by_username,
    active_transfers,
    pending_approvals,
    groups, # Assuming you might want to clear these too
    pending_invites,
    pending_join_requests,
    completed_transfers, # Added for completeness
    shutdown_event
)
from networking.messaging.utils import get_own_ip # For logging server address

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", stream=sys.stdout)


async def handle_peer_connection(websocket, path=None):
    peer_ip = websocket.remote_address[0]
    logging.info(f"New connection attempt from {peer_ip}")
    connection_fully_handled = False
    try:
        # handle_incoming_connection now attempts the handshake.
        # Returns True if auto-approved (starts receive_peer_messages internally)
        # Returns False if manual approval needed OR if initial checks failed (e.g., banned, bad HELLO).
        connection_fully_handled = await handle_incoming_connection(websocket, peer_ip)

        if connection_fully_handled:
            logging.debug(f"handle_incoming_connection successful (auto-approved) for {peer_ip}. Task started.")
            # Wait indefinitely here ONLY IF receive_peer_messages is NOT started internally
            # Since handle_incoming_connection starts it on success, we don't need to do anything else here.
            # The connection lifecycle is now managed by the receive_peer_messages task.
            # We need to ensure this handler doesn't exit prematurely, allowing the receive task to run.
            # However, websockets.serve typically keeps the handler alive as long as the connection is open.
            # If the receive_peer_messages task exits (e.g., disconnect), this handler should also exit.
            # Let's rely on the websocket connection state. We can wait for close.
            await websocket.wait_closed()
            logging.debug(f"Websocket connection closed for {peer_ip} after handling.")

        else:
            # Manual approval pending OR initial connection failed/closed by handler.
            # If pending, the websocket is kept open but managed by pending_approvals logic.
            # If failed, handle_incoming_connection already closed it.
            if peer_ip in pending_approvals:
                 logging.info(f"Connection from {peer_ip} is pending manual approval.")
                 # Keep handler alive while pending? Or let websockets.serve manage it?
                 # Let's assume the websocket library keeps the connection managed.
                 # We might need to await closure here too if approval is denied externally.
                 await websocket.wait_closed() # Wait for potential denial/closure
                 logging.debug(f"Websocket for pending connection {peer_ip} closed.")

            else:
                 # Connection failed initial checks and should be closed.
                 logging.debug(f"handle_incoming_connection returned False for {peer_ip}, likely failed initial checks/closed.")


    except ConnectionClosedOK:
         logging.info(f"Connection {peer_ip} closed normally.")
    except websockets.exceptions.ConnectionClosedError as e:
         logging.warning(f"Connection {peer_ip} closed with error. Code: {e.code}, Reason: {e.reason}")
    except Exception as e:
        logging.error(f"Unexpected error in top-level handle_peer_connection for {peer_ip}: {e}")
        if websocket and websocket.state == State.OPEN:
            await websocket.close(code=1011, reason="Server error during connection handling")
    finally:
        # Final cleanup check, although most should happen in receive_peer_messages or handle_incoming
        if peer_ip in connections and connections.get(peer_ip) == websocket:
            logging.debug(f"Final state check: Removing connection object for {peer_ip} in handle_peer_connection finally.")
            del connections[peer_ip]
        # Add other state cleanup only if strictly necessary and not handled elsewhere
        logging.debug(f"Exiting handle_peer_connection for {peer_ip}")


async def main():
    try:
        await initialize_user_config()
    except Exception as e:
         logging.critical(f"Failed to initialize user config: {e}. Cannot continue.")
         return # Exit if config fails

    discovery = PeerDiscovery()
    tasks = [
        asyncio.create_task(discovery.send_broadcasts(), name="SendBroadcasts"),
        asyncio.create_task(discovery.receive_broadcasts(), name="ReceiveBroadcasts"),
        asyncio.create_task(discovery.cleanup_stale_peers(), name="CleanupPeers"),
        asyncio.create_task(maintain_peer_list(discovery), name="MaintainPeerList"),
        asyncio.create_task(user_input(discovery), name="UserInput"),
        asyncio.create_task(display_messages(), name="DisplayMessages"),
    ]
    server = None
    try:
        server = await websockets.serve(
            handle_peer_connection,
            "0.0.0.0",
            8765,
            ping_interval=20, # Send pings every 20s
            ping_timeout=20,  # Wait 20s for pong response
            max_size=10 * 1024 * 1024 # Limit message size to 10MB
        )
        my_ip = await get_own_ip()
        logging.info(f"WebSocket server started on {my_ip}:8765")

        await shutdown_event.wait() # Wait until /exit command or signal sets the event

    except OSError as e:
         logging.critical(f"Failed to start WebSocket server: {e}")
         shutdown_event.set() # Trigger shutdown if server fails to start
    except Exception as e:
        logging.critical(f"An unexpected error occurred in main: {e}")
        shutdown_event.set() # Trigger shutdown on unexpected errors
    finally:
        logging.info("Shutdown initiated...")

        # 1. Stop Discovery
        if 'discovery' in locals() and discovery:
            discovery.stop()

        # 2. Close WebSocket Server
        if server:
            server.close()
            await server.wait_closed()
            logging.info("WebSocket server stopped.")

        # 3. Close Active Peer Connections gracefully
        logging.info("Closing active peer connections...")
        close_tasks = []
        for peer_ip, ws in list(connections.items()):
             # Check ws object directly for state
             if ws and not ws.closed:
                  logging.debug(f"Closing connection to {peer_ip}")
                  close_tasks.append(asyncio.create_task(ws.close(code=1001, reason="Server shutting down")))
        if close_tasks:
            await asyncio.gather(*close_tasks, return_exceptions=True) # Wait for closes to complete
        logging.info("Connections closed.")

        # 4. Cancel all background tasks
        logging.info("Cancelling background tasks...")
        # Gather current tasks again, as some might have finished
        active_tasks = [t for t in tasks if not t.done()]
        for task in active_tasks:
            task.cancel()

        # Wait for tasks to finish cancelling
        if active_tasks:
            results = await asyncio.gather(*active_tasks, return_exceptions=True)
            for i, result in enumerate(results):
                 if isinstance(result, asyncio.CancelledError):
                      logging.debug(f"Task {active_tasks[i].get_name()} cancelled successfully.")
                 elif isinstance(result, Exception):
                      logging.error(f"Error during cancellation/shutdown of task {active_tasks[i].get_name()}: {result}")
        logging.info("Background tasks cancellation complete.")

        # 5. Clear Shared State (ensure imports are correct at top)
        logging.info("Clearing shared application state...")
        connections.clear()
        peer_public_keys.clear()
        peer_usernames.clear()
        peer_device_ids.clear()
        username_to_ip.clear()
        discovered_peers_by_username.clear()
        active_transfers.clear()
        pending_approvals.clear()
        groups.clear()
        pending_invites.clear()
        pending_join_requests.clear()
        completed_transfers.clear() # Clear history as well
        logging.info("Shared state cleared.")

        # 6. Shutdown Default Executor (optional, for cleaner exit)
        try:
             loop = asyncio.get_running_loop()
             if hasattr(loop, 'shutdown_default_executor'):
                  executor = getattr(loop, '_default_executor', None) # Access potentially private attr
                  if executor and hasattr(executor, 'shutdown'):
                       logging.info("Shutting down default executor...")
                       # Run in executor or separate thread recommended, but can block briefly here
                       await loop.run_in_executor(None, executor.shutdown, True) # wait=True
                       logging.info("Default executor shut down.")
                  elif executor:
                       logging.debug("Default executor does not have a shutdown method.")
        except Exception as exec_e:
             logging.warning(f"Error shutting down default executor: {exec_e}")

        logging.info("Application fully shut down.")

if __name__ == "__main__":
    # Add signal handling for graceful shutdown on SIGINT/SIGTERM? (More advanced)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # This is often handled by asyncio.run cancelling the main task,
        # triggering the 'finally' block in main(). No explicit event set needed here.
        logging.info("Shutdown initiated by user (Ctrl+C)...")
    except Exception as e:
         # Catch unforeseen errors during startup/runtime
         logging.critical(f"Unhandled exception occurred: {e}", exc_info=True)
         # Attempt to ensure shutdown event is set if possible
         if not shutdown_event.is_set():
             shutdown_event.set() # Help trigger cleanup if main loop isn't running