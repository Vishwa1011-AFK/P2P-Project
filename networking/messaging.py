import asyncio
import logging
import websockets
import os
# import platform # No longer needed for get_mac_address
import json
import hashlib
import aiofiles
# import netifaces # Not directly used here, used in discovery.py
import uuid
from aioconsole import ainput
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey # For type hinting if used
from networking.utils import get_own_ip
from networking.shared_state import (
    active_transfers, message_queue, connections, user_data, peer_public_keys, peer_usernames, shutdown_event
)
from networking.file_transfer import send_file, FileTransfer, TransferState
from websockets.connection import State
from appdirs import user_config_dir

# Global state
# peer_list = {}  # {ip: (username, last_seen)} # REMOVED - Redundant
connection_denials = {}  # {target_username: {requesting_username: denial_count}}
pending_approvals = {}  # {peer_ip: asyncio.Future}

def get_config_directory():
    """Determine the appropriate config directory based on the OS."""
    appname = "P2PChat"  # Your application name (use a consistent name)
    appauthor = False  # Set False to prevent the author name from being added

    return user_config_dir(appname, appauthor)


async def initialize_user_config():
    """Load or create user configuration, using a user-specific config directory."""
    config_dir = get_config_directory()
    os.makedirs(config_dir, exist_ok=True)  # Ensure directory exists

    config_file_path = os.path.join(config_dir, "user_config.json")

    if os.path.exists(config_file_path):
        try:
            with open(config_file_path, "r") as f:
                loaded_data = json.load(f)
            user_data.update(loaded_data)
            # Ensure keys are loaded correctly
            user_data["public_key"] = serialization.load_pem_public_key(user_data["public_key"].encode())
            user_data["private_key"] = serialization.load_pem_private_key(user_data["private_key"].encode(), password=None)
            print(f"Welcome back, {user_data['original_username']}!")
        except Exception as e:
            print(f"Error loading config, creating new one: {e}")
            await create_new_user_config(config_file_path) # Pass the full path to create
    else:
        await create_new_user_config(config_file_path)  # Pass the full path to create
        print(f"Welcome, {user_data['original_username']}")


async def create_new_user_config(config_file_path, username=None):
    """Create a new user configuration file in the specified path."""
    if username is None:
        original_username = await ainput("Enter your username: ")
    else:
        original_username = username

    internal_username = f"{original_username}_{uuid.uuid4()}"  # Generate unique internal username
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    device_id = str(uuid.uuid4())  # Generate unique device ID

    user_data.clear()  # Clear any existing user data
    user_data.update({
        "original_username": original_username,
        "internal_username": internal_username,
        "public_key": public_key,
        "private_key": private_key,
        "device_id": device_id
    })

    # Prepare data for JSON serialization
    data_to_save = {
        "original_username": original_username,
        "internal_username": internal_username,
        "public_key": public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
        "private_key": private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
        "device_id": device_id
    }

    try:
        with open(config_file_path, "w") as f:
            json.dump(data_to_save, f, indent=4) # Add indent for readability
    except IOError as e:
        logging.error(f"Failed to save config file {config_file_path}: {e}")
        print(f"Error: Could not save configuration file.")


async def connect_to_peer(peer_ip, requesting_username, target_username, port=8765):
    """Establish a WebSocket connection to a peer."""
    if peer_ip in connections:
        print(f"Already connected to {target_username} ({peer_ip})") # Info message
        return connections[peer_ip] # Return existing connection

    uri = f"ws://{peer_ip}:{port}"
    websocket = None # Initialize websocket to None
    try:
        websocket = await websockets.connect(uri, ping_interval=None, max_size=10*1024*1024) # Use same max_size as server
        own_ip = await get_own_ip()
        await websocket.send(f"INIT {own_ip}")
        response = await websocket.recv()
        if response.startswith("INIT_ACK"):
            public_key_pem = user_data["public_key"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            await websocket.send(json.dumps({
                "type": "CONNECTION_REQUEST",
                "requesting_username": requesting_username,
                "target_username": target_username,
                "key": public_key_pem
            }))
            approval_response = await websocket.recv()
            approval_data = json.loads(approval_response)
            if approval_data["type"] == "CONNECTION_RESPONSE" and approval_data["approved"]:
                await websocket.send(json.dumps({
                    "type": "IDENTITY",
                    "username": requesting_username,
                    "device_id": user_data["device_id"],
                    "key": public_key_pem
                }))
                identity_message = await websocket.recv()
                identity_data = json.loads(identity_message)
                if identity_data["type"] == "IDENTITY":
                    peer_username = identity_data["username"]
                    peer_public_keys[peer_ip] = serialization.load_pem_public_key(identity_data["key"].encode())
                    peer_usernames[peer_username] = peer_ip
                    connections[peer_ip] = websocket
                    logging.info(f"{requesting_username} connected to {peer_username} ({peer_ip})")
                    return websocket
                else:
                    await websocket.close()
                    print(f"Connection to {target_username} failed: Invalid identity response.")
                    return None
            else:
                await websocket.close()
                denial_message = approval_data.get("reason", "Connection was denied by the peer.")
                print(f"Connection to {target_username} failed: {denial_message}")
                return None
        else:
            await websocket.close()
            print(f"Connection to {target_username} failed: No INIT_ACK received.")
            return None
    except websockets.exceptions.InvalidURI:
         print(f"Connection to {target_username} failed: Invalid URI '{uri}'")
         return None
    except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK):
        print(f"Connection to {target_username} closed unexpectedly during handshake.")
        if websocket and websocket.state != State.CLOSED: await websocket.close()
        return None
    except ConnectionRefusedError:
        print(f"Connection to {target_username} ({peer_ip}) refused.")
        if websocket and websocket.state != State.CLOSED: await websocket.close()
        return None
    except OSError as e: # Catch socket errors like "No route to host"
         print(f"Connection to {target_username} failed: Network error ({e})")
         if websocket and websocket.state != State.CLOSED: await websocket.close()
         return None
    except Exception as e:
        logging.exception(f"Failed to connect to {peer_ip}: {e}")
        print(f"Connection to {target_username} failed: {str(e)}")
        if websocket and websocket.state != State.CLOSED:
            await websocket.close()
        return None


async def disconnect_from_peer(peer_username):
    """Disconnect from a specified peer."""
    if peer_username in peer_usernames:
        peer_ip = peer_usernames[peer_username]
        if peer_ip in connections:
            websocket = connections[peer_ip]
            try:
                # Clean up state *before* closing to avoid race conditions
                del connections[peer_ip]
                if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
                del peer_usernames[peer_username] # Remove this specific username mapping

                await websocket.close()
                print(f"Disconnected from {peer_username} ({peer_ip})")
            except Exception as e:
                logging.error(f"Error disconnecting from {peer_username} ({peer_ip}): {e}")
                print(f"Failed to cleanly disconnect from {peer_username}: {e}")
                # Ensure state is cleaned up even if close fails
                if peer_ip in connections: del connections[peer_ip]
                if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
                if peer_username in peer_usernames: del peer_usernames[peer_username]

        else:
            print(f"Already disconnected from {peer_username}")
             # Clean up potentially stale state if websocket is missing
            if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
            del peer_usernames[peer_username]
    else:
        print(f"No such peer: {peer_username}")


async def handle_incoming_connection(websocket, peer_ip):
    """Handle an incoming peer connection request."""
    try:
        message = await websocket.recv()
        if shutdown_event.is_set():
            await websocket.close(code=1001, reason="Server shutting down")
            return False
        if message.startswith("INIT "):
            _, sender_ip = message.split(" ", 1) # sender_ip not strictly needed if we use peer_ip
            # own_ip = await get_own_ip() # Not needed for comparison here
            if peer_ip in connections:
                 logging.warning(f"Duplicate connection attempt from {peer_ip}. Closing new one.")
                 await websocket.close(code=1008, reason="Already connected")
                 return False

            await websocket.send("INIT_ACK")
            request_message = await websocket.recv()
            request_data = json.loads(request_message)

            if request_data["type"] == "CONNECTION_REQUEST":
                requesting_username = request_data["requesting_username"]
                target_username = request_data["target_username"]
                peer_key_pem = request_data["key"]

                if target_username != user_data["original_username"]:
                    logging.warning(f"Connection request from {requesting_username} for wrong target '{target_username}'. Denying.")
                    await websocket.send(json.dumps({
                        "type": "CONNECTION_RESPONSE",
                        "approved": False,
                        "reason": "Incorrect target username"
                    }))
                    await websocket.close()
                    return False

                # Check denial count (optional, simple spam prevention)
                denial_count = connection_denials.get(target_username, {}).get(requesting_username, 0)
                if denial_count >= 3:
                    logging.warning(f"Connection request from blocked user {requesting_username}. Denying.")
                    await websocket.send(json.dumps({
                        "type": "CONNECTION_RESPONSE",
                        "approved": False,
                        "reason": "Connection blocked due to too many previous denials."
                    }))
                    await websocket.close()
                    return False


                # Ask user for approval
                approval_future = asyncio.Future()
                pending_approvals[peer_ip] = approval_future
                await message_queue.put({
                    "type": "approval_request",
                    "peer_ip": peer_ip,
                    "requesting_username": requesting_username
                })

                approved = False # Default to not approved
                try:
                    # Wait for user response (yes/no via user_input)
                    approved = await asyncio.wait_for(approval_future, timeout=30.0)
                except asyncio.TimeoutError:
                    logging.info(f"Approval for {requesting_username} ({peer_ip}) timed out.")
                    await message_queue.put(f"\nApproval request for {requesting_username} timed out.") # Inform user
                finally:
                    # Always remove from pending approvals
                    if peer_ip in pending_approvals: del pending_approvals[peer_ip]

                # Handle denial counting
                if not approved:
                    if target_username not in connection_denials:
                        connection_denials[target_username] = {}
                    current_denials = connection_denials[target_username]
                    current_denials[requesting_username] = current_denials.get(requesting_username, 0) + 1
                    await message_queue.put(f"Denied connection from {requesting_username} ({current_denials[requesting_username]}/3)")
                    if current_denials[requesting_username] >= 3:
                        await message_queue.put(f"{requesting_username} has been blocked for this session.")

                # Send response to peer
                await websocket.send(json.dumps({
                    "type": "CONNECTION_RESPONSE",
                    "approved": approved
                }))

                if not approved:
                    await websocket.close()
                    return False

                # If approved, send own identity
                public_key_pem = user_data["public_key"].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                await websocket.send(json.dumps({
                    "type": "IDENTITY",
                    "username": user_data["original_username"],
                    "device_id": user_data["device_id"],
                    "key": public_key_pem
                }))

                # Receive peer's identity
                identity_message = await websocket.recv()
                identity_data = json.loads(identity_message)
                if identity_data["type"] == "IDENTITY":
                    # Verify received username matches requesting_username? Optional check.
                    # peer_username = identity_data["username"] # Already have requesting_username
                    peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_key_pem.encode()) # Use key from initial request
                    peer_usernames[requesting_username] = peer_ip # Map username to IP
                    connections[peer_ip] = websocket
                    logging.info(f"{user_data['original_username']} accepted connection from {requesting_username} ({peer_ip})")
                    await message_queue.put(f"Connected to {requesting_username}") # Inform user
                    return True
                else:
                    logging.error(f"Invalid identity message from {peer_ip} after approval. Closing.")
                    await websocket.close()
                    return False
            else:
                logging.warning(f"Unexpected message type from {peer_ip}: {request_data.get('type')}. Closing.")
                await websocket.close(code=1002, reason="Unexpected message type")
                return False
        else:
            logging.warning(f"Invalid initial message from {peer_ip}: '{message[:30]}...'. Closing.")
            await websocket.close(code=1002, reason="Invalid initial message")
            return False
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON received from {peer_ip}. Closing connection.")
        if websocket and websocket.state == State.OPEN:
            await websocket.close(code=1007, reason="Invalid JSON")
        return False
    except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK):
        logging.info(f"Connection closed by {peer_ip} during handshake.")
        # Ensure cleanup if closed unexpectedly
        if peer_ip in pending_approvals: del pending_approvals[peer_ip]
        return False
    except Exception as e:
        logging.exception(f"Error in connection handshake with {peer_ip}: {e}")
        if websocket and websocket.state == State.OPEN:
            await websocket.close(code=1011, reason="Internal server error")
         # Ensure cleanup if exception occurs
        if peer_ip in pending_approvals: del pending_approvals[peer_ip]
        return False


async def maintain_peer_list(discovery_instance):
    """Maintain the list of connected peers and check connections."""
    # global peer_list # REMOVED - No longer needed
    while not shutdown_event.is_set():
        try:
            # Check WebSocket connections
            for peer_ip, ws in list(connections.items()):
                if shutdown_event.is_set(): break
                try:
                    # Send ping and wait for pong
                    await asyncio.wait_for(ws.ping(), timeout=10.0)
                except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                    logging.warning(f"Connection lost with peer {peer_ip}. Cleaning up.")
                    # Find username associated with this IP
                    lost_username = None
                    for uname, uip in list(peer_usernames.items()):
                        if uip == peer_ip:
                            lost_username = uname
                            break

                    # Clean up state
                    if peer_ip in connections: del connections[peer_ip]
                    if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
                    if lost_username and lost_username in peer_usernames:
                         del peer_usernames[lost_username]
                         await message_queue.put(f"Disconnected from {lost_username} (connection lost)")

                    # Close websocket forcefully if needed (though it's likely already closed)
                    if ws.state != State.CLOSED:
                        await ws.close()

            # Copying discovery list is removed as it's not used globally here
            # peer_list = discovery_instance.peer_list.copy() # REMOVED

            await asyncio.sleep(15) # Check connections every 15 seconds
        except asyncio.CancelledError:
            logging.info("maintain_peer_list task cancelled.")
            break
        except Exception as e:
            logging.exception(f"Error in maintain_peer_list: {e}")
            await asyncio.sleep(15) # Wait before retrying after error
    logging.info("maintain_peer_list exited.")


async def send_message_to_peers(message, target_username=None):
    """Send a message to one or all connected peers."""
    if not isinstance(message, str) or not message:
        logging.warning("Attempted to send empty or non-string message.")
        return False

    targets = []
    if target_username:
        if target_username in peer_usernames:
            peer_ip = peer_usernames[target_username]
            if peer_ip in connections and connections[peer_ip].state == State.OPEN:
                targets.append((peer_ip, connections[peer_ip], peer_public_keys.get(peer_ip), target_username))
            else:
                await message_queue.put(f"Error: Not connected to {target_username}.")
                return False
        else:
            await message_queue.put(f"Error: No peer found with username {target_username}.")
            return False
    else: # Send to all
        for username, peer_ip in list(peer_usernames.items()):
             if peer_ip in connections and connections[peer_ip].state == State.OPEN:
                 targets.append((peer_ip, connections[peer_ip], peer_public_keys.get(peer_ip), username))

    if not targets:
        if not target_username:
             await message_queue.put("No peers connected to send message to.")
        # If target_username was specified, error was already printed
        return False

    sent_to_at_least_one = False
    for peer_ip, websocket, peer_key, username in targets:
        if not peer_key:
            logging.warning(f"Missing public key for {username} ({peer_ip}). Cannot encrypt message.")
            continue
        try:
            encrypted_message = peer_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).hex()
            payload = json.dumps({"type": "MESSAGE", "message": encrypted_message})
            await websocket.send(payload)
            sent_to_at_least_one = True
        except Exception as e:
            logging.error(f"Failed to send message to {username} ({peer_ip}): {e}")
            # Consider marking peer as disconnected if send fails repeatedly
            await message_queue.put(f"Error sending message to {username}: {e}")

    return sent_to_at_least_one


async def receive_peer_messages(websocket, peer_ip):
    """Receive messages from a connected peer."""
    peer_username = "unknown" # Placeholder until identity known or connection closes
    try:
        # Find username associated with this IP upon successful connection
        for uname, uip in peer_usernames.items():
            if uip == peer_ip:
                peer_username = uname
                break
        if peer_username == "unknown":
             logging.warning(f"Could not find username for established connection {peer_ip}")
             # This shouldn't happen if handshake logic is correct

        async for message in websocket:
            if shutdown_event.is_set():
                break
            try:
                data = json.loads(message)
                message_type = data.get("type")

                if message_type == "file_transfer_init":
                    # ... (existing file transfer init logic) ...
                    transfer_id = data["transfer_id"]
                    file_name = data["filename"]
                    file_size = data["filesize"]
                    expected_hash = data.get("file_hash")
                    # SECURITY/UX: Sanitize filename and check for conflicts
                    safe_filename_base = os.path.basename(file_name)
                    download_dir = "downloads"
                    os.makedirs(download_dir, exist_ok=True)
                    file_path = os.path.join(download_dir, safe_filename_base)

                    # Basic conflict avoidance: append (n) if file exists
                    counter = 1
                    base, ext = os.path.splitext(safe_filename_base)
                    while os.path.exists(file_path):
                        file_path = os.path.join(download_dir, f"{base}({counter}){ext}")
                        counter += 1

                    transfer = FileTransfer(file_path, peer_ip, direction="receive")
                    transfer.transfer_id = transfer_id
                    transfer.total_size = file_size
                    transfer.expected_hash = expected_hash
                    transfer.hash_algo = hashlib.sha256() if expected_hash else None
                    transfer.state = TransferState.IN_PROGRESS
                    transfer.file_handle = await aiofiles.open(file_path, "wb")
                    active_transfers[transfer_id] = transfer
                    await message_queue.put(f"Receiving '{os.path.basename(file_path)}' from {peer_username} (ID: {transfer_id[:8]}...)")


                elif message_type == "file_chunk":
                    # ... (existing file chunk receiving logic) ...
                    transfer_id = data["transfer_id"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.direction == "receive":
                        async with transfer.condition:
                            while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                                await transfer.condition.wait()
                            if shutdown_event.is_set():
                                if transfer.file_handle: await transfer.file_handle.close()
                                # Consider removing partially downloaded file on shutdown?
                                if transfer_id in active_transfers: del active_transfers[transfer_id]
                                break # Exit condition wait loop

                        if transfer.state != TransferState.IN_PROGRESS: # Check if cancelled/failed during pause
                            continue

                        try:
                            # Assuming encryption added here in future: decrypt chunk first
                            # chunk = decrypt_chunk(data["chunk"], data["nonce"], transfer.aes_key)
                            chunk = bytes.fromhex(data["chunk"]) # Placeholder

                            await transfer.file_handle.write(chunk)
                            transfer.transferred_size += len(chunk)
                            if transfer.hash_algo:
                                transfer.hash_algo.update(chunk)

                            # Check completion
                            if transfer.transferred_size >= transfer.total_size:
                                await transfer.file_handle.close()
                                transfer.file_handle = None
                                final_message = ""
                                if transfer.expected_hash:
                                    calculated_hash = transfer.hash_algo.hexdigest()
                                    if calculated_hash == transfer.expected_hash:
                                        transfer.state = TransferState.COMPLETED
                                        final_message = f"'{os.path.basename(transfer.file_path)}' received successfully from {peer_username}."
                                    else:
                                        transfer.state = TransferState.FAILED
                                        final_message = f"File integrity check FAILED for '{os.path.basename(transfer.file_path)}' from {peer_username}. File deleted."
                                        logging.error(f"Hash mismatch for {transfer_id}. Expected {transfer.expected_hash}, got {calculated_hash}")
                                        try:
                                            os.remove(transfer.file_path)
                                        except OSError as rm_err:
                                             logging.error(f"Could not remove failed transfer file {transfer.file_path}: {rm_err}")
                                else:
                                    # No hash provided, assume complete
                                    transfer.state = TransferState.COMPLETED
                                    final_message = f"'{os.path.basename(transfer.file_path)}' received from {peer_username} (no integrity check)."

                                await message_queue.put(final_message)
                                # Cleanup handled by update_transfer_progress task

                        except Exception as chunk_err:
                             logging.exception(f"Error processing chunk for transfer {transfer_id}: {chunk_err}")
                             await message_queue.put(f"Error receiving file chunk from {peer_username}. Transfer failed.")
                             transfer.state = TransferState.FAILED
                             if transfer.file_handle: await transfer.file_handle.close()
                             # Cleanup handled by update_transfer_progress task


                elif message_type == "MESSAGE":
                    try:
                        decrypted_message = user_data["private_key"].decrypt(
                            bytes.fromhex(data["message"]),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        ).decode()
                        await message_queue.put(f"{peer_username}: {decrypted_message}")
                    except Exception as decrypt_err:
                        logging.error(f"Failed to decrypt message from {peer_username} ({peer_ip}): {decrypt_err}")
                        await message_queue.put(f"[Failed to decrypt message from {peer_username}]")

                # Handle other message types if needed

            except json.JSONDecodeError:
                logging.warning(f"Received invalid JSON from {peer_username} ({peer_ip}): {message[:100]}")
                await message_queue.put(f"[{peer_username} sent invalid data]")
            except Exception as proc_err:
                logging.exception(f"Error processing message from {peer_username} ({peer_ip}): {proc_err}")
                await message_queue.put(f"[Error processing message from {peer_username}]")

    except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK) as closed_err:
        logging.info(f"Connection with {peer_username} ({peer_ip}) closed: {closed_err}")
    except Exception as e:
        logging.exception(f"Unexpected error receiving from {peer_username} ({peer_ip}): {e}")
    finally:
        logging.info(f"Cleaning up connection state for {peer_ip}")
        # Ensure comprehensive cleanup in finally block
        if peer_ip in connections:
            del connections[peer_ip]
        if peer_ip in peer_public_keys:
            del peer_public_keys[peer_ip]
        # Find and remove the correct username mapping
        current_username = None
        for uname, uip in list(peer_usernames.items()):
             if uip == peer_ip:
                 current_username = uname
                 break
        if current_username and current_username in peer_usernames:
             del peer_usernames[current_username]
             # Only notify user if the connection wasn't explicitly closed by /disconnect
             if not shutdown_event.is_set(): # Avoid spamming during shutdown
                 await message_queue.put(f"Disconnected from {current_username}")
        # Clean up any pending transfers associated with this peer? Maybe not, allow resume later?
        # For now, transfers might just fail if peer disconnects.


async def user_input(discovery): # Takes discovery instance as argument
    """Handle user input with centralized control."""
    await asyncio.sleep(1) # Allow other tasks to initialize
    my_username = user_data.get('original_username', 'User') # Cache for prompt

    while not shutdown_event.is_set():
        try:
            # Use aioconsole for async input
            message = await ainput(f"{my_username} > ")
            message = message.strip() # Remove leading/trailing whitespace

            if not message: # Skip empty input
                 continue

            if message == "/exit":
                print("Shutting down application...")
                shutdown_event.set()
                # Raising CancelledError here might stop the main loop prematurely.
                # Let the shutdown_event propagate and main() handle cleanup.
                break # Exit the user_input loop

            elif message == "/help":
                print("\nAvailable commands:")
                print("  /connect <username>     - Connect to a discovered peer by username")
                print("  /disconnect <username>  - Disconnect from a connected peer")
                print("  /msg <username> <text>  - Send private message to a connected peer")
                print("  /send <username> <path> - Send file to a connected peer")
                print("  /pause <transfer_id>    - Pause an active file transfer (by ID prefix)")
                print("  /resume <transfer_id>   - Resume a paused file transfer (by ID prefix)")
                print("  /transfers              - List active file transfers")
                print("  /list                   - Show discovered and connected peers")
                print("  /changename <new_name>  - Change your username (persists)")
                print("  /exit                   - Exit the application")
                print("  /help                   - Show this help message")
                print("  <message>               - Send message to all connected peers")
                continue

            elif message == "/list":
                print("\nAvailable peers:")
                own_ip = await get_own_ip()
                # Use discovery.peer_list directly (CHANGE APPLIED HERE)
                if not discovery.peer_list and not connections:
                     print("  No peers discovered or connected.")
                else:
                    known_ips = set(connections.keys()) | set(discovery.peer_list.keys())
                    for ip in known_ips:
                         disc_info = discovery.peer_list.get(ip)
                         username = "Unknown"
                         status = ""

                         # Get username preferably from established connection, else from discovery
                         conn_username = None
                         for u, c_ip in peer_usernames.items():
                             if c_ip == ip:
                                 conn_username = u
                                 break

                         if conn_username:
                             username = conn_username
                         elif disc_info:
                             username = disc_info[0]

                         # Determine status
                         if ip == own_ip:
                             status = "Self"
                             username = user_data['original_username'] # Ensure self-username is correct
                         elif ip in connections:
                             status = "Connected"
                         elif disc_info:
                              status = "Discovered"
                         else:
                             status = "Disconnected (stale?)" # Should ideally not happen if cleanup is fast

                         print(f"- {username} ({ip}, {status})")
                continue

            elif message.startswith("/connect "):
                target_username = message[len("/connect "):].strip()
                if not target_username:
                     print("Usage: /connect <username>")
                     continue
                if target_username == user_data['original_username']:
                     print("You cannot connect to yourself.")
                     continue

                requesting_username = user_data["original_username"]
                peer_ip = None
                # Find peer IP from discovery list (CHANGE APPLIED HERE - use discovery directly)
                for ip, (username, _) in discovery.peer_list.items():
                    if username == target_username:
                        peer_ip = ip
                        break

                if peer_ip:
                    if peer_ip in connections:
                        print(f"Already connected to {target_username}")
                    else:
                        print(f"Attempting to connect to {target_username} ({peer_ip})...")
                        # Start connection task in background
                        asyncio.create_task(connect_and_handle(peer_ip, requesting_username, target_username))
                else:
                    print(f"Peer '{target_username}' not found in discovered list. They might be offline or running under a different name.")
                continue

            elif message.startswith("/disconnect "):
                target_username = message[len("/disconnect "):].strip()
                if not target_username:
                     print("Usage: /disconnect <username>")
                     continue
                await disconnect_from_peer(target_username)
                continue

            elif message.startswith("/msg "):
                parts = message[len("/msg "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /msg <username> <message>")
                    continue
                target_username, msg_content = parts
                if await send_message_to_peers(msg_content, target_username):
                     await message_queue.put(f"You → {target_username}: {msg_content}")
                # send_message_to_peers handles errors and prints messages
                continue

            elif message.startswith("/send "):
                parts = message[len("/send "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /send <username> <file_path>")
                    continue
                target_username, file_path = parts
                if not os.path.exists(file_path):
                     print(f"Error: File not found at '{file_path}'")
                     continue
                if not os.path.isfile(file_path):
                     print(f"Error: '{file_path}' is not a valid file.")
                     continue

                if target_username in peer_usernames:
                    peer_ip = peer_usernames[target_username]
                    if peer_ip in connections:
                        print(f"Starting to send '{os.path.basename(file_path)}' to {target_username}...")
                        # Run send_file in background
                        asyncio.create_task(send_file(file_path, {peer_ip: connections[peer_ip]}))
                    else:
                        print(f"Error: Not connected to {target_username}.")
                else:
                    print(f"Error: No peer found with username {target_username}.")
                continue

            elif message.startswith(("/pause ", "/resume ")):
                 command, potential_id = message.split(" ", 1)
                 transfer_id_prefix = potential_id.strip()
                 if not transfer_id_prefix:
                     print(f"Usage: {command} <transfer_id_prefix>")
                     continue

                 matched_transfer = None
                 match_count = 0
                 for tid, transfer in active_transfers.items():
                     if tid.startswith(transfer_id_prefix):
                         matched_transfer = transfer
                         match_count += 1

                 if match_count == 0:
                      print(f"No active transfer found with ID starting with '{transfer_id_prefix}'")
                 elif match_count > 1:
                      print(f"Multiple transfers match '{transfer_id_prefix}'. Please provide a longer, unique ID prefix.")
                 else:
                      action = command.strip('/') # "pause" or "resume"
                      if action == "pause":
                           if matched_transfer.state == TransferState.IN_PROGRESS:
                               await matched_transfer.pause()
                               print(f"Paused transfer {matched_transfer.transfer_id}")
                           elif matched_transfer.state == TransferState.PAUSED:
                                print(f"Transfer {matched_transfer.transfer_id} is already paused.")
                           else:
                                print(f"Cannot pause transfer {matched_transfer.transfer_id} (state: {matched_transfer.state.value})")
                      elif action == "resume":
                            if matched_transfer.state == TransferState.PAUSED:
                                await matched_transfer.resume()
                                print(f"Resumed transfer {matched_transfer.transfer_id}")
                            elif matched_transfer.state == TransferState.IN_PROGRESS:
                                print(f"Transfer {matched_transfer.transfer_id} is already in progress.")
                            else:
                                print(f"Cannot resume transfer {matched_transfer.transfer_id} (state: {matched_transfer.state.value})")
                 continue


            elif message == "/transfers":
                if not active_transfers:
                    print("\nNo active transfers.")
                else:
                    print("\nActive transfers:")
                    for transfer_id, transfer in list(active_transfers.items()):
                        direction = "Sending" if transfer.direction == "send" else "Receiving"
                        progress = 0.0
                        if transfer.total_size > 0:
                             progress = (transfer.transferred_size / transfer.total_size * 100)
                        print(f"- {transfer_id}: {direction} '{os.path.basename(transfer.file_path)}' to/from {transfer.peer_ip} ({progress:.1f}%, {transfer.state.value})")
                continue

            elif message.startswith("/changename "):
                new_username = message[len("/changename "):].strip()
                if not new_username:
                    print("Usage: /changename <new_username>")
                    continue
                if new_username == user_data['original_username']:
                    print("New username is the same as the current one.")
                    continue

                # --- CHANGENAME FIX START ---
                print(f"Attempting to change username to '{new_username}'...")
                config_dir = get_config_directory()
                config_file_path = os.path.join(config_dir, "user_config.json")

                # Update username in memory first
                old_username = user_data['original_username']
                user_data['original_username'] = new_username
                my_username = new_username # Update prompt variable

                # Prepare data to save (including existing keys/id)
                data_to_save = {}
                for key, value in user_data.items():
                    if key == "public_key" and isinstance(value, RSAPublicKey):
                         data_to_save[key] = value.public_bytes(
                              encoding=serialization.Encoding.PEM,
                              format=serialization.PublicFormat.SubjectPublicKeyInfo
                         ).decode()
                    elif key == "private_key" and isinstance(value, RSAPrivateKey):
                         data_to_save[key] = value.private_bytes(
                              encoding=serialization.Encoding.PEM,
                              format=serialization.PrivateFormat.PKCS8,
                              encryption_algorithm=serialization.NoEncryption()
                         ).decode()
                    else:
                         # Handles original_username, internal_username, device_id
                         data_to_save[key] = value

                # Save the updated config file
                try:
                    with open(config_file_path, "w") as f:
                        json.dump(data_to_save, f, indent=4)
                    print(f"Username changed to '{new_username}' and saved.")
                    # Send immediate broadcast about the name change
                    await discovery.send_immediate_broadcast()
                except IOError as e:
                    logging.error(f"Failed to save updated config file {config_file_path}: {e}")
                    print(f"Error: Could not save configuration. Reverting username change.")
                    # Revert change in memory if save failed
                    user_data['original_username'] = old_username
                    my_username = old_username
                except Exception as e:
                    logging.exception(f"Unexpected error saving config during username change: {e}")
                    print(f"Unexpected error saving config. Reverting username change.")
                    # Revert change in memory if save failed
                    user_data['original_username'] = old_username
                    my_username = old_username

                # --- CHANGENAME FIX END ---
                continue


            # Handle approval requests (yes/no)
            elif message.lower() in ("yes", "y", "no", "n") and pending_approvals:
                 # Find the oldest pending approval (usually only one active)
                 peer_ip_to_approve = next(iter(pending_approvals))
                 future = pending_approvals.pop(peer_ip_to_approve) # Remove it immediately
                 if not future.done():
                      is_approved = message.lower() in ("yes", "y")
                      future.set_result(is_approved)
                      print(f"Approval response {'sent' if is_approved else 'denied'} for {peer_ip_to_approve}.")
                 else:
                     # This case might happen if timeout occurred just before user typed yes/no
                     print("Approval already timed out or processed.")
                     # Put it back if it wasn't ours to handle? Unlikely needed.
                 continue

            # Default: Send message to all connected peers
            else:
                if connections:
                    if await send_message_to_peers(message):
                         await message_queue.put(f"You (to all): {message}")
                    # send_message_to_peers handles errors
                else:
                    print("No peers connected to send messages to. Use /connect <username> or wait for connections.")
                continue # Added continue for clarity

        except asyncio.CancelledError:
            # This can happen if shutdown_event is set while awaiting input
            logging.info("User input task cancelled.")
            break
        except Exception as e:
            logging.exception(f"Error in user_input loop: {e}")
            print(f"\nAn error occurred in the input handler: {e}")
            await asyncio.sleep(1) # Avoid tight loop on unexpected error

    logging.info("user_input task finished.")


async def display_messages():
    """Display messages from the message queue without re-printing the prompt."""
    while not shutdown_event.is_set():
        try:
            item = await message_queue.get()
            if isinstance(item, dict) and item.get("type") == "approval_request":
                peer_ip = item["peer_ip"]
                requesting_username = item["requesting_username"]
                # Print on a new line to avoid interfering with potential user input
                print(f"\n\n>> Connection request from {requesting_username} ({peer_ip}). Approve? (yes/no) <<")
                # Rely on user_input to reprint prompt after user hits Enter or types next command
            elif isinstance(item, str):
                # Print message on a new line
                print(f"\n{item}")
            else:
                 logging.warning(f"Unknown item type in message queue: {type(item)}")

            message_queue.task_done()
            # Let aioconsole handle the prompt redisplay after user interaction
            # print(f"{user_data.get('original_username', 'User')} > ", end='', flush=True) # Avoid manual reprint

        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.exception(f"Error displaying message: {e}")
            await asyncio.sleep(1) # Avoid tight loop on error
    logging.info("display_messages task finished.")


async def connect_and_handle(peer_ip, requesting_username, target_username):
     """Helper task to connect and then start receiving messages."""
     websocket = await connect_to_peer(peer_ip, requesting_username, target_username)
     if websocket:
         # Connection successful, start listening for messages from this peer
         # The receive_peer_messages task will handle cleanup if connection drops
         await receive_peer_messages(websocket, peer_ip)
     # If connection fails, connect_to_peer prints the error, task simply finishes.