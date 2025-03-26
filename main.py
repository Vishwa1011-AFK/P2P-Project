import asyncio
import logging
import sys # Ensure sys is imported
import os  # Ensure os is imported
import websockets
from networking.discovery import PeerDiscovery
from networking.messaging import (
    user_input, # TUI runner task
    receive_peer_messages,
    handle_incoming_connection,
    connections,
    maintain_peer_list,
    initialize_user_config,
    # message_queue is handled internally by messaging now for display
)
from networking.file_transfer import update_transfer_progress
from networking.shared_state import peer_usernames, peer_public_keys, shutdown_event, active_transfers

# Configure logging
logging.basicConfig(
    level=logging.INFO, # Adjust level (e.g., logging.DEBUG for more detail)
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", # Include logger name
    # filename="p2p_app.log", # Optionally log to a file
    # filemode="a",
    stream=sys.stdout # Keep logging to stdout for terminal view
)
# Silence noisy libraries if needed
# logging.getLogger("websockets").setLevel(logging.WARNING)

# Get a logger instance for this module
logger = logging.getLogger(__name__)


async def handle_peer_connection(websocket, path=None):
    """Handle incoming WebSocket connections."""
    peer_ip = websocket.remote_address[0]
    logger.info(f"Incoming connection attempt from {peer_ip}")
    try:
        # handle_incoming_connection now performs the full handshake
        success = await handle_incoming_connection(websocket, peer_ip)
        if success:
            # If handshake successful, start receiving messages
            await receive_peer_messages(websocket, peer_ip)
        else:
             logger.warning(f"Handshake failed with {peer_ip}. Closing connection.")
             # Ensure connection is closed if handshake fails but doesn't raise exception
             if websocket.open:
                 await websocket.close(code=1008, reason="Handshake failed")

    except websockets.exceptions.ConnectionClosed:
         # Use debug level as this is common and expected during shutdown or normal disconnects
         logger.debug(f"Connection closed by {peer_ip} (during/after handshake).")
    except Exception as e:
        logger.exception(f"Error handling connection from {peer_ip}: {e}")
        # Ensure connection is closed on error
        if websocket.open:
            await websocket.close(code=1011, reason="Server error")
    finally:
        # Cleanup is now handled more robustly within receive_peer_messages and handle_incoming_connection
        logger.debug(f"Finished handling connection from {peer_ip}")


async def main():
    """Main application entry point."""
    # Collect startup messages instead of queuing them immediately
    startup_messages = []

    # Initialize config FIRST
    # Note: initialize_user_config itself might queue messages for username prompt/load status
    # We handle the main application start messages here.
    await initialize_user_config()
    logger.info("User configuration initialized.")
    startup_messages.append("--- Starting P2P Application ---")

    discovery = PeerDiscovery()

    # --- Start Core Tasks (excluding input_task for now) ---
    broadcast_task = asyncio.create_task(discovery.send_broadcasts(), name="BroadcastSender")
    discovery_task = asyncio.create_task(discovery.receive_broadcasts(), name="BroadcastReceiver")
    cleanup_task = asyncio.create_task(discovery.cleanup_stale_peers(), name="PeerCleanup")
    progress_task = asyncio.create_task(update_transfer_progress(), name="TransferProgress")
    maintain_task = asyncio.create_task(maintain_peer_list(discovery), name="PeerMaintainer")

    # --- Start WebSocket Server ---
    server = None
    main_task_exception = None # Variable to store critical exceptions
    input_task = None # Initialize input_task to None

    try:
        server = await websockets.serve(
            handle_peer_connection,
            "0.0.0.0", # Listen on all interfaces
            8765,
            ping_interval=20, # Send pings every 20s
            ping_timeout=20, # Disconnect if pong not received within 20s
            close_timeout=10, # Time to wait for close handshake
            max_size=None, # Allow large file transfers
        )
        server_addr = server.sockets[0].getsockname()
        logger.info(f"WebSocket server started on {server_addr}")
        startup_messages.append(f"--- Listening for peers on {server_addr[0]}:{server_addr[1]} ---")
        startup_messages.append("--- Type /help for commands ---")

        # --- Start Input Task *after* server is up and messages are ready ---
        input_task = asyncio.create_task(
            user_input(discovery, initial_messages=startup_messages), # Pass messages
            name="UserInputTUI"
        )

        # List of all tasks to manage (now includes input_task)
        tasks = [
            broadcast_task,
            discovery_task,
            cleanup_task,
            progress_task,
            maintain_task,
            input_task,
        ]

        # --- Wait for shutdown signal ---
        logger.info("Main loop running. Waiting for commands or shutdown signal.")
        await shutdown_event.wait()
        logger.info("Shutdown event received, proceeding to clean up.")


    except OSError as e:
         # Specific handling for address in use
         if "Address already in use" in str(e):
              logger.critical(f"Failed to start WebSocket server: Port 8765 is already in use.")
              # Try queueing message if messaging is set up, otherwise print
              try:
                   from networking.messaging import message_queue
                   await message_queue.put("[CRITICAL] Cannot start server on port 8765. Is another instance running?")
              except ImportError:
                    print("[CRITICAL] Cannot start server on port 8765. Is another instance running?", file=sys.stderr)
         else:
              logger.critical(f"Failed to start WebSocket server due to OS error: {e}")
              try:
                   from networking.messaging import message_queue
                   await message_queue.put(f"[CRITICAL] Cannot start server: {e}")
              except ImportError:
                   print(f"[CRITICAL] Cannot start server: {e}", file=sys.stderr)

         main_task_exception = e
         shutdown_event.set() # Trigger shutdown if server fails
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
        shutdown_event.set()
    except asyncio.CancelledError:
        logger.info("Main task cancelled. Shutting down...") # Should not happen unless externally cancelled
        shutdown_event.set()
    except Exception as e:
         logger.exception(f"Unexpected error in main loop: {e}")
         main_task_exception = e
         shutdown_event.set()
    finally:
        logger.info("Initiating shutdown process...")
        if not shutdown_event.is_set():
             logger.warning("Shutdown initiated without shutdown_event being set. Setting now.")
             shutdown_event.set() # Ensure event is set

        # --- Graceful Shutdown ---
        logger.info("Cancelling all running tasks...")
        # Construct the list of tasks to cancel *within* the finally block
        # This ensures input_task is included if it was successfully created
        all_tasks_to_cancel = [
            task for task in [
                broadcast_task, discovery_task, cleanup_task,
                progress_task, maintain_task, input_task # input_task might be None if server failed early
            ] if task is not None # Filter out None tasks
        ]

        for task in all_tasks_to_cancel:
             # Check if task is not done before cancelling
             if not task.done():
                 task.cancel()
                 logger.debug(f"Cancelled task: {task.get_name()}")

        # Wait for tasks to finish cancellation (with timeout)
        logger.info("Waiting for tasks to finish...")
        results = []
        if all_tasks_to_cancel: # Only gather if there are tasks to cancel
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*all_tasks_to_cancel, return_exceptions=True),
                    timeout=5.0 # Adjust timeout as needed (e.g., 5-10 seconds)
                )
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for tasks to cancel. Some tasks may not have finished cleanly.")
                # Check tasks status again after timeout
                for i, task in enumerate(all_tasks_to_cancel):
                    if task and not task.done():
                        task_name = task.get_name() if hasattr(task, 'get_name') else f"Task_{i}"
                        logger.error(f"Task {task_name} did not cancel in time.")
            except Exception as gather_ex:
                 logger.error(f"Error during task gathering on shutdown: {gather_ex}")
        else:
             logger.info("No tasks were running to wait for.")


        if results: # Check if results were obtained (not timed out)
            for i, result in enumerate(results):
                # Need to handle potential index errors if gather timed out partially
                if i < len(all_tasks_to_cancel):
                    task_ref = all_tasks_to_cancel[i]
                    task_name = task_ref.get_name() if task_ref else f"Task_{i}"

                    if isinstance(result, asyncio.CancelledError):
                        logger.debug(f"Task {task_name} finished cancellation.")
                    elif isinstance(result, Exception):
                        # Log exceptions raised *during cancellation* or if task failed before cancellation
                        if result is not main_task_exception:
                             if isinstance(result, Exception) and str(result) == "EXIT_APP_SIGNAL":
                                  logger.debug(f"Task {task_name} exited via signal.")
                             else:
                                  # Log exceptions from tasks other than the one causing shutdown
                                  logger.error(f"Task {task_name} raised exception during processing/shutdown: {result!r}")

        # Close WebSocket server
        if server:
            logger.info("Closing WebSocket server...")
            server.close()
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=2.0)
                logger.info("WebSocket server closed.")
            except asyncio.TimeoutError:
                 logger.warning("Timed out waiting for WebSocket server to close.")
            except Exception as server_close_ex:
                 logger.error(f"Error closing WebSocket server: {server_close_ex}")


        # Close all remaining peer connections (should be handled by receive loops, but as fallback)
        logger.info("Closing any remaining peer connections...")
        for peer_ip, websocket in list(connections.items()):
            try:
                if websocket.open:
                    # Use code 1001 (Going Away) for graceful shutdown
                    await websocket.close(code=1001, reason="Server shutting down")
                    logger.debug(f"Closed connection to {peer_ip}")
            except Exception as e:
                logger.error(f"Error closing connection to {peer_ip} during shutdown: {e}")
        connections.clear()
        peer_public_keys.clear()
        peer_usernames.clear()

        # Stop discovery explicitly (stops broadcast socket)
        logger.info("Stopping discovery...")
        if 'discovery' in locals() and hasattr(discovery, 'stop'):
             discovery.stop() # Call the stop method on the discovery instance

        # Close any remaining file handles in active transfers
        logger.info("Cleaning up file transfers...")
        for transfer_id, transfer in list(active_transfers.items()):
            if transfer.file_handle and not transfer.file_handle.closed:
                try:
                    await transfer.file_handle.close()
                    logger.debug(f"Closed file handle for transfer {transfer_id} during shutdown")
                except Exception as e:
                     logger.error(f"Error closing file handle for transfer {transfer_id} during shutdown: {e}")
        active_transfers.clear()

        logger.info("Application shutdown complete.")
        # The asyncio event loop stops automatically when run with asyncio.run()

if __name__ == "__main__":
    # Ensure downloads directory exists before any async code runs
    if not os.path.exists("downloads"):
         try:
              os.makedirs("downloads")
              print("Created 'downloads' directory.")
         except OSError as e:
              print(f"Error creating 'downloads' directory: {e}", file=sys.stderr)
              sys.exit(1)

    try:
        # Note: asyncio.run() handles loop creation and closing
        asyncio.run(main())
    except KeyboardInterrupt:
        # This handles interrupt if it happens *before* the main async loop starts
        print("\nShutdown requested before main loop started.")
    except Exception as e:
        print(f"\nUnexpected critical error during application execution: {e}", file=sys.stderr)
        # Optionally print traceback for debugging
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
         print("Application has exited.")