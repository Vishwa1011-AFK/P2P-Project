# main.py
import asyncio
import logging
import sys
import os
import websockets  # Import the main library
from typing import Optional

# --- Core Application Imports ---
from networking.config_manager import ConfigManager
from networking.peer_manager import PeerManager
from networking.transfer_manager import TransferManager
from networking.ui_manager import UIManager
from networking.discovery import PeerDiscovery
from networking.connection import handle_incoming_connection, DEFAULT_PORT
from networking.shared_state import shutdown_event

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)-25s: %(message)s",
    stream=sys.stdout,
)
logging.getLogger("websockets").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# --- Global Manager Instances ---
config_manager: Optional[ConfigManager] = None
peer_manager: Optional[PeerManager] = None
transfer_manager: Optional[TransferManager] = None
ui_manager: Optional[UIManager] = None
discovery: Optional[PeerDiscovery] = None
# *** CORRECTED TYPE HINT for server ***
server: Optional[websockets.Server] = None


# *** CORRECTED TYPE HINT for websocket ***
async def peer_connection_handler(websocket: websockets.WebSocketServerProtocol, path: Optional[str] = None):
    """
    Coroutine called by websockets.serve() for each new incoming connection.
    Delegates handshake and subsequent message handling.
    """
    global config_manager, peer_manager, ui_manager, transfer_manager

    peer_ip = "Unknown"
    try:
        peer_addr = websocket.remote_address
        if peer_addr:
            peer_ip = peer_addr[0]
        logger.info(f"Incoming connection attempt from {peer_ip}")

        if not all([config_manager, peer_manager, ui_manager, transfer_manager]):
             logger.critical("Managers not initialized! Cannot handle connection.")
             if websocket.open:
                 await websocket.close(code=1011, reason="Server setup error")
             return

        handshake_successful = await handle_incoming_connection(
            websocket, peer_ip, config_manager, peer_manager, ui_manager, transfer_manager
        )

        if handshake_successful:
            logger.info(f"Handshake with {peer_ip} successful. Connection active.")
            # Receive loop task handles keeping connection alive
            pass
        else:
             logger.warning(f"Handshake failed with {peer_ip}. Connection will be closed.")
             if websocket.open:
                 await websocket.close(code=1002, reason="Handshake failed")

    except websockets.exceptions.ConnectionClosed:
         logger.debug(f"Connection from {peer_ip} closed during initial handling.")
    except Exception as e:
        logger.exception(f"Error in peer_connection_handler for {peer_ip}: {e}")
        if websocket and websocket.open:
            try:
                await websocket.close(code=1011, reason="Server error handling connection")
            except Exception: pass
    finally:
        logger.debug(f"Finished peer_connection_handler for connection from {peer_ip}")


async def main():
    """Main application entry point: Initializes managers, starts tasks, handles shutdown."""
    global config_manager, peer_manager, transfer_manager, ui_manager, discovery, server

    logger.info("--- Starting P2P Application ---")
    tasks = []
    main_task_exception = None

    # --- Ensure 'downloads' directory exists ---
    try:
        downloads_dir = "downloads"
        if not os.path.exists(downloads_dir):
             os.makedirs(downloads_dir)
             logger.info(f"Created '{downloads_dir}' directory.")
        elif not os.path.isdir(downloads_dir):
             logger.critical(f"'{downloads_dir}' exists but is not a directory! Exiting.")
             print(f"[CRITICAL] '{downloads_dir}' exists but is not a directory!", file=sys.stderr)
             sys.exit(1)
    except OSError as e:
          logger.critical(f"Error ensuring '{downloads_dir}' directory exists: {e}. Exiting.", exc_info=True)
          print(f"[CRITICAL] Error creating '{downloads_dir}' directory: {e}", file=sys.stderr)
          sys.exit(1)

    # --- Main Application Logic ---
    try:
        # --- Initialize Managers ---
        logger.debug("Initializing managers...")
        temp_ui_queue_for_config = asyncio.Queue()
        config_manager = ConfigManager(temp_ui_queue_for_config)
        init_success = await config_manager.initialize()
        if not init_success:
             logger.critical("Failed to initialize user configuration. Exiting.")
             while not temp_ui_queue_for_config.empty():
                  try: print(temp_ui_queue_for_config.get_nowait())
                  except asyncio.QueueEmpty: break
             return

        ui_manager = UIManager(config_manager, None, None, None)
        config_manager.set_ui_queue(ui_manager.message_queue)

        logger.debug("Draining temporary config message queue...")
        while not temp_ui_queue_for_config.empty():
             try:
                  message = temp_ui_queue_for_config.get_nowait()
                  await ui_manager.add_message(message)
                  temp_ui_queue_for_config.task_done()
             except asyncio.QueueEmpty: break
             except Exception as drain_err:
                  logger.error(f"Error draining temp config queue: {drain_err}")
        logger.debug("Finished draining temporary queue.")

        peer_manager = PeerManager(config_manager, ui_manager)
        transfer_manager = TransferManager(peer_manager, ui_manager)
        peer_manager.transfer_manager = transfer_manager
        ui_manager.set_peer_manager(peer_manager)
        ui_manager.set_transfer_manager(transfer_manager)
        # Use a different port for discovery than for websocket connections
        discovery_port = DEFAULT_PORT + 1
        discovery = PeerDiscovery(broadcast_port=discovery_port)
        ui_manager.discovery = discovery
        logger.debug("Managers initialized successfully.")

        # --- Start Core Background Tasks ---
        logger.debug("Starting background tasks...")
        tasks.append(asyncio.create_task(discovery.send_broadcasts(config_manager), name="BroadcastSender"))
        tasks.append(asyncio.create_task(discovery.receive_broadcasts(), name="BroadcastReceiver"))
        tasks.append(asyncio.create_task(discovery.cleanup_stale_peers(), name="PeerCleanup"))
        tasks.append(asyncio.create_task(peer_manager.run_maintenance(discovery), name="PeerMaintainer"))
        tasks.append(asyncio.create_task(transfer_manager.run_progress_updates(), name="TransferProgress"))
        logger.debug(f"{len(tasks)} core background tasks started.")

        # --- Start WebSocket Server ---
        logger.debug(f"Starting WebSocket server on port {DEFAULT_PORT}...")
        server = await websockets.serve(
            peer_connection_handler,
            "0.0.0.0", DEFAULT_PORT,
            ping_interval=20, ping_timeout=20, close_timeout=10, max_size=None,
        )
        server_addr = server.sockets[0].getsockname() if server.sockets else ("Unknown", "N/A")
        server_display_addr = f"{server_addr[0]}:{server_addr[1]}"
        logger.info(f"WebSocket server started, listening on {server_display_addr}")
        await ui_manager.add_message(f"--- Listening for peers on {server_display_addr} ---")
        await ui_manager.add_message(f"--- Discovery running on UDP port {discovery_port} ---") # Inform user about discovery port
        await ui_manager.add_message("--- Type /help for commands ---")

        # --- Start TUI Task ---
        logger.debug("Starting TUI task...")
        tui_task = asyncio.create_task(ui_manager.run_tui(), name="UIManagerTUI")
        tasks.append(tui_task)

        # --- Wait for shutdown signal ---
        logger.info("Application startup complete. Waiting for shutdown signal...")
        await shutdown_event.wait()
        logger.info("Shutdown signal received, proceeding to cleanup.")

    # --- Exception Handling for Startup/Main Loop ---
    except OSError as e:
         if "Address already in use" in str(e) or (hasattr(e, 'errno') and e.errno == 98):
              err_msg = f"[CRITICAL] Port {DEFAULT_PORT} already in use. Is another instance running?"
              logger.critical(f"Failed to start WebSocket server: {err_msg}")
         else:
              err_msg = f"[CRITICAL] Cannot start server due to OS error: {e}"
              logger.critical(err_msg, exc_info=True)
         if ui_manager: await ui_manager.add_message(err_msg)
         else: print(err_msg, file=sys.stderr)
         main_task_exception = e
         shutdown_event.set()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received during startup/main loop. Initiating shutdown...")
        shutdown_event.set()
    except asyncio.CancelledError:
        logger.info("Main task cancelled unexpectedly. Initiating shutdown...")
        shutdown_event.set()
    except Exception as e:
         err_msg = f"Unexpected error in main execution: {e}"
         logger.critical(err_msg, exc_info=True)
         if ui_manager: await ui_manager.add_message(f"[CRITICAL ERROR] {err_msg}. Shutting down.")
         else: print(f"[CRITICAL ERROR] {err_msg}. Shutting down.", file=sys.stderr)
         main_task_exception = e
         shutdown_event.set()

    # --- Graceful Shutdown Sequence ---
    finally:
        logger.info("--- Initiating Application Shutdown ---")
        if not shutdown_event.is_set():
             logger.warning("Shutdown sequence entered but shutdown_event was not set. Setting now.")
             shutdown_event.set()

        # 1. Stop Server & Signal Tasks
        logger.debug("Closing server and signalling tasks...")
        if server: server.close()
        if ui_manager: ui_manager.stop()
        if discovery: discovery.stop()

        # 2. Cancel & Wait for Tasks
        logger.info(f"Cancelling background tasks...")
        # Use current tasks list, filter out None or already done tasks
        tasks_to_cancel = [t for t in tasks if t and not t.done()]
        logger.info(f"Attempting to cancel {len(tasks_to_cancel)} running tasks.")
        for task in tasks_to_cancel: task.cancel()

        if tasks_to_cancel:
            logger.info(f"Waiting up to 5 seconds for {len(tasks_to_cancel)} tasks to finish...")
            done, pending = await asyncio.wait(tasks_to_cancel, timeout=5.0, return_when=asyncio.ALL_COMPLETED)
            if pending:
                 logger.warning(f"{len(pending)} tasks did not finish cancellation in time:")
                 for task in pending: logger.warning(f"  - Task pending: {task.get_name()}")
            for task in done:
                 try: task.result()
                 except asyncio.CancelledError: logger.debug(f"Task {task.get_name()} completed cancellation.")
                 except Exception as task_ex:
                      if task_ex is not main_task_exception:
                           logger.error(f"Task {task.get_name()} raised exception: {task_ex!r}", exc_info=False)
        else:
            logger.info("No running background tasks needed cancellation.")

        # 3. Wait for Server Close
        if server:
            logger.info("Waiting for WebSocket server to close completely...")
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=3.0)
                logger.info("WebSocket server closed.")
            except asyncio.TimeoutError: logger.warning("Timed out waiting for WebSocket server to close.")
            except Exception as ex: logger.error(f"Error waiting for server close: {ex}")

        # 4. Final Peer Cleanup (Safety Net)
        if peer_manager:
             connected_peers = peer_manager.get_all_connected_peers()
             if connected_peers:
                  logger.info(f"Closing {len(connected_peers)} remaining peer connections...")
                  disconnect_tasks = [peer_manager.remove_peer(ip, "Server shutting down") for _, ip in connected_peers]
                  try:
                      await asyncio.wait_for(asyncio.gather(*disconnect_tasks, return_exceptions=True), timeout=5.0)
                  except asyncio.TimeoutError: logger.warning("Timed out final peer cleanup.")
                  except Exception as ex: logger.error(f"Error during final peer cleanup: {ex}")
             # Clear manager state after attempting closure
             if hasattr(peer_manager, '_connections'): peer_manager._connections.clear()
             if hasattr(peer_manager, '_peer_public_keys'): peer_manager._peer_public_keys.clear()
             if hasattr(peer_manager, '_peer_usernames'): peer_manager._peer_usernames.clear()


        logger.info("--- Application Shutdown Complete ---")

# --- Application Entry Point ---
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nKeyboardInterrupt caught outside main loop. Exiting.")
        print("\nApplication interrupted.")
    except Exception as e:
        logger.critical(f"Critical error during application lifecycle: {e}", exc_info=True)
        print(f"\n[CRITICAL ERROR] Application failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
         print("Application has exited.")