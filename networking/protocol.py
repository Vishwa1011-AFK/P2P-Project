import asyncio
import json
import logging
import websockets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Assumes managers (Config, Peer, UI, Transfer) are passed as arguments

logger = logging.getLogger(__name__)

# --- Message Sending (Post-Handshake) ---

async def send_message(target_username, message_content, config_manager, peer_manager):
    """
    Send an encrypted text message to one or all connected peers.
    Args:
        target_username: Username of the recipient, or None to broadcast to all.
        message_content: The string message to send.
        config_manager: Instance of ConfigManager.
        peer_manager: Instance of PeerManager.
    Returns:
        True if message was sent successfully to at least one peer, False otherwise.
    """
    if not message_content:
        logger.warning("Attempted to send empty message content.")
        return False

    peers_to_send = {} # {peer_ip: websocket}

    # Determine target websocket(s) using PeerManager
    if target_username:
        # Sending to a specific peer
        peer_ip = peer_manager.get_peer_ip(target_username)
        websocket = peer_manager.get_websocket(peer_ip=peer_ip)
        # Validate connection state
        if not (peer_ip and websocket and websocket.open):
            error_msg = f"Error: Peer '{target_username}' not connected or connection invalid."
            await peer_manager.ui_manager.add_message(error_msg) # Use PeerManager's UI access
            logger.warning(f"Send message failed: {error_msg}")
            # Optional: Trigger cleanup if state seems inconsistent?
            # if peer_ip and not (websocket and websocket.open):
            #     asyncio.create_task(peer_manager.remove_peer(peer_ip, "Invalid connection state during send"))
            return False
        peers_to_send[peer_ip] = websocket
        logger.debug(f"Prepared to send private message to {target_username} ({peer_ip})")
    else:
        # Sending broadcast to all connected peers
        all_connected = peer_manager.get_all_connected_peers() # List of (uname, ip)
        if not all_connected:
             await peer_manager.ui_manager.add_message("No peers connected to send broadcast message.")
             logger.info("Broadcast message requested but no peers connected.")
             return False

        # Filter for valid, open connections
        valid_peers_found = False
        for uname, ip in all_connected:
            ws = peer_manager.get_websocket(peer_ip=ip)
            if ws and ws.open:
                peers_to_send[ip] = ws
                valid_peers_found = True
            else:
                 logger.warning(f"Found invalid/closed connection for {uname} ({ip}) during broadcast prep.")
                 # Consider removing peer here? Handled by maintenance task too.
                 # asyncio.create_task(peer_manager.remove_peer(ip, "Websocket invalid during broadcast prep"))

        if not valid_peers_found:
            await peer_manager.ui_manager.add_message("No valid connections found to send broadcast message.")
            logger.warning("Broadcast message requested but no valid connections available.")
            return False
        logger.debug(f"Prepared to send broadcast message to {len(peers_to_send)} peers.")


    # --- Encrypt and Send ---
    sent_count = 0
    failed_peer_ips = []
    message_bytes = message_content.encode('utf-8')

    for peer_ip, websocket in peers_to_send.items():
        peer_public_key = peer_manager.get_public_key(peer_ip)
        if not peer_public_key:
            logger.error(f"CRITICAL: Missing public key for connected peer {peer_ip}. Cannot encrypt message.")
            failed_peer_ips.append(peer_ip)
            # This indicates a state inconsistency. PeerManager should ensure key exists when adding peer.
            # Consider removing peer if key is missing?
            # asyncio.create_task(peer_manager.remove_peer(peer_ip, "Public key missing"))
            continue

        try:
            # Encrypt message using peer's public key
            encrypted_message_bytes = peer_public_key.encrypt(
                message_bytes,
                padding.OAEP( # Use OAEP padding - recommended for RSA encryption
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Convert encrypted bytes to hex string for JSON serialization
            encrypted_hex = encrypted_message_bytes.hex()

            # Prepare JSON payload
            payload = {"type": "MESSAGE", "message": encrypted_hex}
            message_to_send = json.dumps(payload)

            # Send the message
            await websocket.send(message_to_send)
            # logger.debug(f"Sent encrypted message to {peer_ip}")
            sent_count += 1

        except websockets.exceptions.ConnectionClosed as e:
             logger.warning(f"Failed to send message to {peer_ip}: Connection closed ({e.code}). Removing peer.")
             failed_peer_ips.append(peer_ip)
             # Connection is dead, trigger removal via PeerManager (don't await)
             asyncio.create_task(peer_manager.remove_peer(peer_ip, f"Connection closed during send: {e.code}"))
        except Exception as e:
            # Includes potential encryption errors or other websocket send errors
            recipient_name = peer_manager.get_peer_username(peer_ip) or peer_ip
            logger.exception(f"Failed to encrypt or send message to {recipient_name}: {e}")
            failed_peer_ips.append(peer_ip)
            # Consider removing peer depending on error type/severity? Optional.
            # If encryption fails, it's likely a key issue - maybe remove peer.
            # If send fails transiently, maybe retry or rely on maintenance task.

    # --- Report Failures ---
    if failed_peer_ips:
         # Inform user about failures, be specific if only one target
         num_failed = len(failed_peer_ips)
         if target_username and num_failed == 1:
             await peer_manager.ui_manager.add_message(f"Failed to send message to {target_username}.")
         elif target_username: # Should not happen if only one target specified
              logger.error(f"Logic Error? Failed {num_failed} peers when sending to single target {target_username}")
         else: # Broadcast failure
              await peer_manager.ui_manager.add_message(f"Failed to send message to {num_failed} peer(s). Check logs.")

    return sent_count > 0


# --- Message Receiving Loop & Handling ---

async def handle_received_message(data, peer_ip, config_manager, peer_manager, ui_manager, transfer_manager):
    """
    Process a received JSON message based on its 'type' field.
    Delegates handling to appropriate managers or functions.
    Args:
        data: The decoded JSON data (dictionary).
        peer_ip: IP address of the sender.
        config_manager: Instance of ConfigManager.
        peer_manager: Instance of PeerManager.
        ui_manager: Instance of UIManager.
        transfer_manager: Instance of TransferManager.
    """
    message_type = data.get("type")
    if not message_type:
        logger.warning(f"Received message with no 'type' field from {peer_ip}: {data}")
        return

    peer_username = peer_manager.get_peer_username(peer_ip) or f"Peer_{peer_ip}"
    # logger.debug(f"Handling message type '{message_type}' from {peer_username} ({peer_ip})")

    # --- Handle Different Message Types ---
    try:
        if message_type == "MESSAGE":
            # Encrypted text message
            encrypted_hex = data.get("message")
            if not encrypted_hex:
                 logger.warning(f"Received MESSAGE type with no 'message' field from {peer_ip}")
                 return
            try:
                private_key = config_manager.get_private_key()
                if not private_key:
                     logger.error("Cannot decrypt message: Private key not loaded.")
                     await ui_manager.add_message("[ERROR] Cannot decrypt messages - missing private key.")
                     return # Cannot proceed

                decrypted_bytes = private_key.decrypt(
                    bytes.fromhex(encrypted_hex),
                    padding.OAEP( # Ensure padding matches sender
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_message = decrypted_bytes.decode('utf-8')
                # Queue the decrypted message for display by UIManager
                await ui_manager.add_message(f"{peer_username}: {decrypted_message}")
            except (ValueError, TypeError) as e: # Includes bytes.fromhex errors, potential decryption issues
                 logger.error(f"Decryption/Decoding error for message from {peer_ip}: {e}")
                 await ui_manager.add_message(f"[System] Error decrypting message from {peer_username}.")
            except Exception as e:
                 # Catch other potential decryption errors (less common with correct padding)
                 logger.exception(f"Unexpected error handling received MESSAGE from {peer_ip}: {e}")
                 await ui_manager.add_message(f"[System] Failed to process message from {peer_username}.")


        elif message_type == "USERNAME_UPDATE":
            # Peer is announcing a username change
            old_username = data.get("old_username")
            new_username = data.get("new_username")
            if old_username and new_username:
                 # Delegate state update to PeerManager
                 peer_manager.handle_username_update(peer_ip, old_username, new_username)
            else:
                 logger.warning(f"Received invalid USERNAME_UPDATE from {peer_ip}: {data}")


        # --- File Transfer Related Messages (Delegate to TransferManager) ---
        elif message_type == "folder_transfer_init":
            folder_name = data.get("folder_name")
            file_count = data.get("file_count")
            if folder_name and isinstance(file_count, int):
                await transfer_manager.handle_folder_init(peer_ip, folder_name, file_count)
            else:
                 logger.warning(f"Received invalid folder_transfer_init from {peer_ip}: {data}")

        elif message_type == "file_transfer_init":
            # Receiver gets this request
            await transfer_manager.handle_file_init_request(
                peer_ip=peer_ip,
                transfer_id=data.get("transfer_id"),
                relative_path=data.get("relative_path"),
                file_size=data.get("filesize"),
                file_hash=data.get("file_hash")
            )

        elif message_type == "file_transfer_ack":
            # Original sender gets this approval/denial response
            transfer_manager.handle_file_ack(
                peer_ip=peer_ip,
                transfer_id=data.get("transfer_id"),
                approved=data.get("approved") # handle_file_ack checks boolean
            )

        elif message_type == "file_chunk":
            # Receiver gets file data chunks
            await transfer_manager.handle_file_chunk(
                peer_ip=peer_ip,
                transfer_id=data.get("transfer_id"),
                chunk_hex=data.get("chunk")
            )

        # --- Add handlers for other message types here ---
        # elif message_type == "SOME_OTHER_TYPE":
        #    await handle_some_other_type(data, peer_ip, ...)

        else:
            # Log unhandled message types
            logger.debug(f"Received unhandled message type '{message_type}' from {peer_ip}")

    except KeyError as e:
         logger.warning(f"Missing expected key {e} in message type '{message_type}' from {peer_ip}: {data}")
    except Exception as e:
         # Catch-all for errors during message handling for a specific type
         logger.exception(f"Error handling message type '{message_type}' from {peer_ip}: {e}")
         # Consider sending an error back to peer? Or just log locally.


async def receive_peer_messages(websocket, peer_ip, config_manager, peer_manager, ui_manager, transfer_manager):
    """
    Coroutine that runs for the duration of a single peer connection,
    receiving messages and dispatching them for handling.
    Args:
        websocket: The active websocket connection for this peer.
        peer_ip: IP address of the connected peer.
        config_manager: Instance of ConfigManager.
        peer_manager: Instance of PeerManager.
        ui_manager: Instance of UIManager.
        transfer_manager: Instance of TransferManager.
    """
    peer_username = "Unknown" # Placeholder, gets updated shortly
    reason = "Unknown reason" # Reason for loop exit

    try:
        # Short delay seems unnecessary if started right after handshake success
        # await asyncio.sleep(0.1)
        peer_username = peer_manager.get_peer_username(peer_ip) or f"Peer_{peer_ip}"
        logger.info(f"Message receive loop started for {peer_username} ({peer_ip})")

        # Loop indefinitely, receiving messages until connection closes or error
        async for message in websocket:
            # Check shutdown flag before processing each message
            from .shared_state import shutdown_event # Check latest state each iteration
            if shutdown_event.is_set():
                reason = "Shutdown signal received"
                logger.debug(f"Shutdown detected in receive loop for {peer_ip}.")
                break # Exit loop on shutdown

            # Process the received message
            try:
                # Assume messages are JSON strings
                if isinstance(message, str):
                    data = json.loads(message)
                    if not isinstance(data, dict):
                         logger.warning(f"Received non-dict JSON from {peer_ip}: {message[:100]}...")
                         continue # Skip non-dict data
                elif isinstance(message, bytes):
                     # Handle binary messages? Current protocol assumes JSON strings.
                     logger.warning(f"Received unexpected binary message from {peer_ip}: {message[:100]}...")
                     continue # Skip binary data
                else:
                     logger.warning(f"Received message of unexpected type {type(message)} from {peer_ip}")
                     continue

                # Delegate processing to the handler function
                await handle_received_message(
                    data, peer_ip, config_manager, peer_manager, ui_manager, transfer_manager
                )

            except json.JSONDecodeError:
                 logger.warning(f"Received invalid JSON from {peer_username} ({peer_ip}): {message[:100]}...")
                 # Decide action: ignore, disconnect? Ignore for robustness.
            except asyncio.CancelledError:
                 logger.info(f"Message handling cancelled for peer {peer_ip}")
                 reason = "Task cancelled"
                 # Re-raise cancellation to ensure loop stops correctly
                 raise
            except Exception as e:
                 # Catch errors during the processing of a single message
                 logger.exception(f"Error processing message from {peer_username} ({peer_ip}): {e}")
                 # Decide if certain errors should cause disconnection? For now, just log.

        # --- Loop exited normally (usually means connection closed) ---
        # Reason might still be "Unknown reason" if loop exited without explicit break/exception
        if reason == "Unknown reason":
            # Infer reason based on websocket state if possible
             if websocket.closed:
                  reason = f"Connection closed by peer ({websocket.close_code})"
             else:
                  reason = "Receive loop ended unexpectedly"


    # --- Handle connection closing exceptions ---
    except websockets.exceptions.ConnectionClosedOK:
        reason = "Connection closed normally by peer"
        logger.info(f"{reason} ({peer_username} - {peer_ip})")
    except websockets.exceptions.ConnectionClosedError as e:
        reason = f"Connection closed with error: {e.code} {e.reason}"
        logger.warning(f"{reason} ({peer_username} - {peer_ip})")
    except asyncio.CancelledError:
         # This catches cancellation of the receive_peer_messages task itself
         reason = "Receive loop task cancelled"
         logger.info(f"{reason} for {peer_username} ({peer_ip})")
         # Don't remove peer here, cancellation is usually part of shutdown sequence
         return # Exit cleanly
    except Exception as e:
         # Catch unexpected errors in the receive loop itself (e.g., websocket read error)
         reason = f"Receive loop error: {e}"
         logger.exception(f"Unexpected error in receive loop for {peer_username} ({peer_ip}): {e}")
    finally:
        # --- Cleanup ---
        logger.info(f"Exiting receive loop for {peer_username} ({peer_ip}). Reason: {reason}")
        # Ensure cleanup happens via PeerManager *unless* shutdown is in progress
        from .shared_state import shutdown_event
        if not shutdown_event.is_set():
             logger.debug(f"Triggering peer removal for {peer_ip} from receive loop finally.")
             # Use PeerManager to handle disconnection and all related cleanup
             await peer_manager.remove_peer(peer_ip, reason)
        else:
             # If shutting down, PeerManager's final cleanup or main loop's cleanup will handle it
             logger.debug(f"Shutdown in progress, skipping explicit peer removal for {peer_ip} in receive loop finally.")