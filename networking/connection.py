import asyncio
import json
import logging
import websockets
from cryptography.hazmat.primitives import serialization

# Assuming protocol.py contains receive_peer_messages
from .protocol import receive_peer_messages

logger = logging.getLogger(__name__)

# Default port constant
DEFAULT_PORT = 8765


async def connect_to_peer(peer_ip, target_username, config_manager, peer_manager, ui_manager):
    """
    Establish an OUTGOING WebSocket connection and perform handshake.
    Args:
        peer_ip: IP address of the peer to connect to.
        target_username: Expected username of the peer (for UI/verification).
        config_manager: Instance of ConfigManager.
        peer_manager: Instance of PeerManager.
        ui_manager: Instance of UIManager.
    Returns:
        Websocket object on success, None on failure.
    """
    uri = f"ws://{peer_ip}:{DEFAULT_PORT}"
    websocket = None
    peer_display_name = f"{target_username} ({peer_ip})" # For logging/messages

    try:
        await ui_manager.add_message(f"Attempting to connect to {peer_display_name}...")
        # Establish WebSocket connection with timeout
        websocket = await asyncio.wait_for(
            websockets.connect(
                uri,
                ping_interval=20,       # Send pings every 20s
                ping_timeout=20,        # Wait 20s for pong response
                close_timeout=10,       # Time for close handshake
                max_size=None           # Allow large messages (for file transfer)
            ),
            timeout=15.0 # Connection establishment timeout
        )
        logger.info(f"WebSocket connected to {peer_ip}. Starting handshake.")

        # --- Handshake Step 1: Send INIT ---
        own_ip = config_manager.get_ip()
        init_msg = f"INIT {own_ip}"
        await websocket.send(init_msg)
        logger.debug(f"Sent to {peer_ip}: {init_msg}")

        # --- Handshake Step 2: Receive INIT_ACK ---
        response = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        logger.debug(f"Received from {peer_ip}: {response}")
        if not isinstance(response, str) or not response.startswith("INIT_ACK"):
            raise ConnectionRefusedError("Peer did not send valid INIT_ACK.")

        # --- Handshake Step 3: Send CONNECTION_REQUEST ---
        public_key_pem = config_manager.get_public_key_pem()
        if not public_key_pem:
             raise ConnectionAbortedError("Local public key not available.") # Should not happen if config loaded

        conn_request_payload = {
            "type": "CONNECTION_REQUEST",
            "requesting_username": config_manager.get_username(),
            "target_username": target_username, # Let receiver verify if they are the intended target
            "key": public_key_pem
        }
        conn_request_msg = json.dumps(conn_request_payload)
        await websocket.send(conn_request_msg)
        logger.debug(f"Sent CONNECTION_REQUEST to {peer_ip}")
        await ui_manager.add_message(f"Connection request sent to {target_username}. Waiting for approval...")

        # --- Handshake Step 4: Receive CONNECTION_RESPONSE ---
        approval_response_msg = await asyncio.wait_for(websocket.recv(), timeout=70.0) # Longer timeout for user approval on other side
        logger.debug(f"Received from {peer_ip}: {approval_response_msg}")
        try:
            approval_data = json.loads(approval_response_msg)
        except json.JSONDecodeError:
            raise ConnectionAbortedError("Received invalid JSON for CONNECTION_RESPONSE.")

        if not isinstance(approval_data, dict) or \
           approval_data.get("type") != "CONNECTION_RESPONSE" or \
           not approval_data.get("approved"):
            # Peer denied the connection
            await ui_manager.add_message(f"Connection to {target_username} was denied by the peer.")
            logger.info(f"Connection to {peer_ip} denied by peer.")
            # Close connection cleanly after denial
            await websocket.close(code=1000, reason="Connection denied")
            return None # Indicate failure

        # --- Connection Approved - Handshake Step 5: Send IDENTITY ---
        # Send own identity details
        identity_payload = {
            "type": "IDENTITY",
            "username": config_manager.get_username(),
            "device_id": config_manager.get_device_id(),
            "key": public_key_pem # Send own key again for verification/completeness
        }
        identity_msg = json.dumps(identity_payload)
        await websocket.send(identity_msg)
        logger.debug(f"Sent IDENTITY to {peer_ip}")

        # --- Handshake Step 6: Receive Peer's IDENTITY ---
        peer_identity_msg = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        logger.debug(f"Received from {peer_ip}: {peer_identity_msg}")
        try:
            peer_identity_data = json.loads(peer_identity_msg)
        except json.JSONDecodeError:
             raise ConnectionAbortedError("Received invalid JSON for peer IDENTITY.")

        if not isinstance(peer_identity_data, dict) or peer_identity_data.get("type") != "IDENTITY":
            raise ConnectionAbortedError("Peer sent invalid IDENTITY response type.")

        peer_actual_username = peer_identity_data.get("username")
        peer_key_pem = peer_identity_data.get("key")
        # Optional: Validate device ID if needed: peer_device_id = peer_identity_data.get("device_id")

        if not peer_actual_username or not peer_key_pem:
             raise ConnectionAbortedError("Peer IDENTITY message missing username or key.")

        # Optional: Verify if the username matches the target_username we tried to connect to
        if peer_actual_username != target_username:
             logger.warning(f"Connected to {peer_ip} but identity username '{peer_actual_username}' differs from target '{target_username}'. Proceeding anyway.")
             # Or could choose to disconnect here if strict matching is required
             # await websocket.close(code=1008, reason="Username mismatch")
             # return None

        # Load peer's public key
        try:
            peer_public_key = serialization.load_pem_public_key(peer_key_pem.encode('utf-8'))
        except Exception as key_error:
             raise ConnectionAbortedError(f"Invalid public key received from peer '{peer_actual_username}': {key_error}")

        # --- Handshake Successful ---
        logger.info(f"Handshake successful with {peer_actual_username} ({peer_ip}).")

        # Add peer using PeerManager (PeerManager handles UI message)
        await peer_manager.add_peer(peer_ip, peer_actual_username, peer_public_key, websocket)

        # Start the message receiving loop for this connection
        # Pass all necessary managers to the receive loop task
        asyncio.create_task(
            receive_peer_messages(
                websocket, peer_ip, config_manager, peer_manager, ui_manager, peer_manager.transfer_manager
            ),
            name=f"Receive-{peer_actual_username}"
        )
        logger.debug(f"Receive loop task started for {peer_actual_username} ({peer_ip}).")

        return websocket # Return websocket object on success

    # --- Error Handling & Cleanup for connect_to_peer ---
    except websockets.exceptions.InvalidURI:
         msg = f"Connection failed: Invalid address {uri}"
         logger.error(msg)
         await ui_manager.add_message(msg)
    except ConnectionRefusedError as e:
        msg = f"Connection to {peer_display_name} refused: {e}"
        logger.warning(msg)
        await ui_manager.add_message(msg)
    except ConnectionAbortedError as e:
         msg = f"Connection to {peer_display_name} aborted during handshake: {e}"
         logger.warning(msg)
         await ui_manager.add_message(msg)
    except asyncio.TimeoutError:
        msg = f"Connection or handshake with {peer_display_name} timed out."
        logger.warning(msg)
        await ui_manager.add_message(msg)
    except websockets.exceptions.ConnectionClosed as e:
        # This might happen if peer closes immediately after connect or during handshake
        msg = f"Connection to {peer_display_name} closed unexpectedly during handshake: {e.code} {e.reason}"
        logger.warning(msg)
        await ui_manager.add_message(msg)
    except OSError as e:
         # Catch OS-level errors like "Network is unreachable"
         msg = f"Network error connecting to {peer_display_name}: {e}"
         logger.error(msg)
         await ui_manager.add_message(msg)
    except Exception as e:
        # Catch-all for unexpected errors during connection/handshake
        msg = f"Unexpected error connecting to {peer_display_name}: {e}"
        logger.exception(msg) # Log full traceback
        await ui_manager.add_message(f"[ERROR] {msg}")

    # --- Cleanup on Failure ---
    # Ensure websocket is closed if it was opened but handshake failed
    if websocket and websocket.open:
        logger.debug(f"Closing failed connection attempt to {peer_ip}")
        try:
            await websocket.close(code=1002, reason="Handshake failed") # Protocol error
        except Exception as close_err:
             logger.error(f"Error closing websocket after failed connection to {peer_ip}: {close_err}")

    # Remove potentially partially added peer state ONLY if error occurred after adding
    # It's generally safer to let PeerManager handle consistency via its add/remove methods
    # and maintenance task. If add_peer was never called, nothing needs removal here.

    return None # Indicate connection failure


async def handle_incoming_connection(websocket, peer_ip, config_manager, peer_manager, ui_manager, transfer_manager):
    """
    Handle the handshake for an INCOMING peer connection request.
    Args:
        websocket: The incoming websocket connection.
        peer_ip: IP address of the connecting peer.
        config_manager: Instance of ConfigManager.
        peer_manager: Instance of PeerManager.
        ui_manager: Instance of UIManager.
        transfer_manager: Instance of TransferManager.
    Returns:
        True if handshake is successful, False otherwise.
        If successful, also starts the receive_peer_messages task.
    """
    logger.info(f"Handling incoming handshake from {peer_ip}")
    try:
        # --- Basic Checks ---
        if peer_ip == config_manager.get_ip():
             logger.warning(f"Rejected connection attempt from self ({peer_ip})")
             return False # Don't connect to self
        if peer_manager.is_connected(peer_ip=peer_ip):
            logger.warning(f"Rejected duplicate connection attempt from already connected peer {peer_ip}")
            # Send rejection? Close immediately? Closing is safer.
            # await websocket.close(code=1008, reason="Already connected") # Policy violation
            return False # Let outer handler close

        # --- Handshake Step 1: Receive INIT ---
        message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        logger.debug(f"Received from {peer_ip}: {message}")
        if not isinstance(message, str) or not message.startswith("INIT "):
             logger.warning(f"Invalid initial message from {peer_ip}: {message}")
             return False
        # sender_ip_in_msg = message.split(" ", 1)[1] # We already have peer_ip from socket

        # --- Handshake Step 2: Send INIT_ACK ---
        init_ack_msg = "INIT_ACK"
        await websocket.send(init_ack_msg)
        logger.debug(f"Sent to {peer_ip}: {init_ack_msg}")

        # --- Handshake Step 3: Receive CONNECTION_REQUEST ---
        request_msg = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        logger.debug(f"Received from {peer_ip}: {request_msg}")
        try:
            request_data = json.loads(request_msg)
            if not isinstance(request_data, dict): raise ValueError("Payload not a dict")
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Invalid JSON or format in CONNECTION_REQUEST from {peer_ip}: {e}")
            return False

        if request_data.get("type") != "CONNECTION_REQUEST":
            logger.warning(f"Expected CONNECTION_REQUEST from {peer_ip}, got type: {request_data.get('type')}")
            return False

        requesting_username = request_data.get("username") # Use 'username' if sent, fallback 'requesting_username' if needed
        if not requesting_username: requesting_username = request_data.get("requesting_username") # Backwards compatibility check
        target_username = request_data.get("target_username") # Check if connection is for us
        peer_key_pem = request_data.get("key")

        # Validate request content
        if not all([requesting_username, target_username, peer_key_pem]):
             logger.warning(f"Incomplete CONNECTION_REQUEST from {peer_ip}: Missing fields.")
             return False
        if target_username != config_manager.get_username():
            logger.warning(f"Connection request from {peer_ip} is for wrong user '{target_username}' (this is '{config_manager.get_username()}'). Denying.")
            # Send explicit denial response before closing
            try:
                 await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False}))
            except Exception: pass # Ignore errors sending denial if connection is already failing
            return False

        # --- Handshake Step 4: Request UI Approval & Send CONNECTION_RESPONSE ---
        logger.info(f"Requesting UI approval for connection from {requesting_username} ({peer_ip})")
        approved = False # Default to not approved
        try:
             # Ask UIManager to display prompt and wait for user response (handles future internally now)
             # This now blocks until user responds or timeout occurs within UIManager
             # UIManager raises TimeoutError if needed
             approved = await ui_manager.request_connection_approval(peer_ip, requesting_username)
             logger.info(f"UI approval result for {peer_ip}: {approved}")
        except asyncio.TimeoutError:
             # Timeout handled within UIManager (logs message), just need to ensure 'approved' is False
             approved = False
        except asyncio.CancelledError:
             logger.info(f"Approval request cancelled for {peer_ip}, denying connection.")
             approved = False
             # If handshake cancelled, re-raise to stop processing
             # raise # Or just return False? Returning False seems cleaner.
             return False
        except Exception as e:
             logger.exception(f"Error during UI connection approval for {peer_ip}: {e}")
             approved = False # Deny on unexpected errors

        # Send CONNECTION_RESPONSE based on approval result
        try:
            response_payload = {"type": "CONNECTION_RESPONSE", "approved": approved}
            await websocket.send(json.dumps(response_payload))
            logger.debug(f"Sent CONNECTION_RESPONSE to {peer_ip}: Approved={approved}")
        except Exception as e:
             logger.error(f"Failed to send CONNECTION_RESPONSE (Approved={approved}) to {peer_ip}: {e}")
             # If we can't send response, connection likely dead. Abort handshake.
             return False

        if not approved:
            logger.info(f"Connection denied by user/timeout for {requesting_username} ({peer_ip}).")
            return False # Let outer handler close the connection

        # --- Connection Approved - Step 5: Receive IDENTITY ---
        logger.info(f"Connection from {requesting_username} ({peer_ip}) approved by user.")
        # Load peer public key received in the *initial request*
        try:
             peer_public_key = serialization.load_pem_public_key(peer_key_pem.encode('utf-8'))
        except Exception as key_error:
             logger.error(f"Invalid public key received from {peer_ip} in request: {key_error}")
             # Send error response? Or just close? Close is simpler.
             return False # Cannot proceed without valid key

        # Receive the peer's confirming IDENTITY message
        identity_msg = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        logger.debug(f"Received from {peer_ip}: {identity_msg}")
        try:
            identity_data = json.loads(identity_msg)
            if not isinstance(identity_data, dict): raise ValueError("Payload not dict")
        except (json.JSONDecodeError, ValueError):
             logger.warning(f"Invalid JSON or format in IDENTITY received from {peer_ip}.")
             return False

        # Validate IDENTITY content
        if identity_data.get("type") != "IDENTITY" or \
           identity_data.get("username") != requesting_username:
             logger.warning(f"Invalid or mismatched IDENTITY received from {peer_ip}. Expected '{requesting_username}', got '{identity_data.get('username')}'.")
             # Could be MITM attempt or protocol error. Deny/close.
             return False
        # Optional: Verify device ID if needed: identity_data.get("device_id")

        # --- Handshake Step 6: Send own IDENTITY ---
        own_identity_payload = {
            "type": "IDENTITY",
            "username": config_manager.get_username(),
            "device_id": config_manager.get_device_id(),
            "key": config_manager.get_public_key_pem() # Send own key
        }
        try:
             await websocket.send(json.dumps(own_identity_payload))
             logger.debug(f"Sent IDENTITY to {peer_ip}")
        except Exception as e:
             logger.error(f"Failed to send own IDENTITY to {peer_ip}: {e}")
             # Connection likely unusable if we can't send. Abort.
             return False

        # --- Handshake Successful ---
        logger.info(f"Incoming handshake complete with {requesting_username} ({peer_ip}).")

        # Add peer using PeerManager (PeerManager handles UI message)
        await peer_manager.add_peer(peer_ip, requesting_username, peer_public_key, websocket)

        # Start the message receiving loop for this connection
        asyncio.create_task(
            receive_peer_messages(
                websocket, peer_ip, config_manager, peer_manager, ui_manager, transfer_manager
            ),
            name=f"Receive-{requesting_username}"
        )
        logger.debug(f"Receive loop task started for incoming connection {requesting_username} ({peer_ip}).")

        return True # Indicates successful handshake, receive loop is running

    # --- Error Handling for handle_incoming_connection ---
    except asyncio.TimeoutError:
        logger.warning(f"Handshake timeout with incoming connection {peer_ip}.")
    except websockets.exceptions.ConnectionClosed as e:
        logger.info(f"Connection closed by {peer_ip} during handshake: {e.code} {e.reason}")
    except ConnectionRefusedError as e: # Custom error used in connect_to_peer, maybe use here?
         logger.warning(f"Handshake aborted for {peer_ip}: {e}")
    except ConnectionAbortedError as e: # Custom error used in connect_to_peer
         logger.warning(f"Handshake aborted for {peer_ip}: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error during incoming handshake with {peer_ip}: {e}")

    # If any error occurs or validation fails, function returns False.
    # The main server loop (`peer_connection_handler` in main.py) is responsible
    # for ensuring the websocket is closed if this function returns False.
    # No need for explicit websocket.close() here, simplifies logic.
    logger.debug(f"Incoming handshake failed for {peer_ip}.")
    return False