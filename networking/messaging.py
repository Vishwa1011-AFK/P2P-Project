import asyncio
import logging
import websockets
import os
import json
import hashlib
import aiofiles
import netifaces
import uuid
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from networking.utils import get_own_ip
from networking.shared_state import (
    active_transfers, message_queue, connections, user_data,
    peer_public_keys, peer_usernames, shutdown_event,
    pending_file_receive_approvals, # Use this for receiver waiting for user input
    pending_file_send_acks # Use this for sender waiting for ack message
)
from networking.file_transfer import send_file, send_folder, FileTransfer, TransferState
from websockets.connection import State as WebSocketState # Rename to avoid confusion
from appdirs import user_config_dir

# --- TUI Setup ---
from prompt_toolkit import Application, print_formatted_text
from prompt_toolkit.layout import Layout, HSplit, Window
from prompt_toolkit.widgets import TextArea
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.completion import WordCompleter, Completer, Completion
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.application.current import get_app
from prompt_toolkit.formatted_text import FormattedText

# Global state for TUI and Approvals
peer_list = {}  # {ip: (username, last_seen)} - Maintained by maintain_peer_list
connection_denials = {}  # {target_username: {requesting_username: denial_count}}
pending_connection_approvals = {}  # {peer_ip: asyncio.Future} - For incoming connection requests

# State variables to track the *currently displayed* approval request
# These link the displayed prompt to the "yes/no" input
current_connection_approval_ip = None
current_file_approval_id = None


# --- Dynamic Completer ---
class DynamicCompleter(Completer):
    base_commands = ["/connect", "/disconnect", "/msg", "/send", "/sendfolder", "/pause", "/resume", "/transfers", "/list", "/changename", "/exit", "/help", "yes", "no"]
    path_commands = ["/send", "/sendfolder"]

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        parts = text.split()

        if not text or ' ' not in text:
            # Complete base commands or first part of message
            for cmd in self.base_commands:
                if cmd.startswith(text):
                    yield Completion(cmd, start_position=-len(text))
        elif len(parts) >= 1:
            command = parts[0]
            if command in ["/connect", "/disconnect", "/msg", "/send", "/sendfolder"]:
                 if len(parts) == 1 and text.endswith(" "): # Need username next
                      # Suggest discovered/connected peers
                      current_peers = list(peer_usernames.keys())
                      # Also suggest discovered peers not yet connected
                      for ip, (uname, _) in peer_list.items():
                          if uname not in current_peers and ip != user_data.get('ip'):
                              current_peers.append(uname)

                      for peer_name in current_peers:
                           yield Completion(peer_name, start_position=0) # Start from space
                 elif len(parts) == 2 and command in self.path_commands and not text.endswith(" "):
                     # Suggest local paths (basic implementation)
                     # This part can be complex for good path completion
                     # For simplicity, we won't implement full path completion here
                     # You could use libraries like 'glob' or 'os.listdir' if needed
                     pass # Placeholder for path completion logic
            elif command in ["/pause", "/resume"]:
                if len(parts) == 1 and text.endswith(" "): # Need transfer ID
                    for tid in active_transfers.keys():
                        yield Completion(tid, start_position=0)


def get_current_prompt():
    """Get the prompt string dynamically."""
    return f"{user_data.get('original_username', 'User')} > "

# Define the TUI layout
output_area = TextArea(
    # text will be updated dynamically
    read_only=True,
    scrollbar=True,
    line_numbers=False,
    focusable=False # Don't want cursor in output
)
input_area = TextArea(
    height=1,
    prompt=get_current_prompt, # Use callable for dynamic prompt
    multiline=False,
    wrap_lines=False,
    history=InMemoryHistory(),
    completer=DynamicCompleter(),
    accept_handler=lambda buff: get_app().exit(result=buff.text) # Exit app loop with input text
)

layout = Layout(
    HSplit([
        output_area,
        Window(height=1, char='-', style='class:separator'), # Separator line
        input_area
    ])
)

bindings = KeyBindings()
# Default Enter binding is handled by accept_handler
# Add Ctrl+C binding for graceful exit
@bindings.add("c-c")
@bindings.add("c-d")
def _(event):
    """ Control-C or Control-D to exit. """
    event.app.exit(result="EXIT_APP_SIGNAL") # Use a special signal

tui_app = Application(layout=layout, key_bindings=bindings, full_screen=False, mouse_support=True)

# --- Config and Core Logic ---

def get_config_directory():
    """Determine the appropriate config directory based on the OS."""
    appname = "P2PChat"
    appauthor = False # Keep it simple
    return user_config_dir(appname, appauthor)

async def display_startup_message(message):
    """Helper to display messages before TUI runs using message queue."""
    # Use put_nowait as the queue reading loop might not be running yet
    # Or, more robustly, ensure the display task starts before these messages
    await message_queue.put(message)

async def initialize_user_config():
    """Load or create user configuration."""
    config_dir = get_config_directory()
    os.makedirs(config_dir, exist_ok=True)
    config_file_path = os.path.join(config_dir, "user_config.json")

    own_ip = await get_own_ip()
    user_data['ip'] = own_ip # Store own IP

    if os.path.exists(config_file_path):
        try:
            with open(config_file_path, "r") as f:
                loaded_data = json.load(f)
            user_data.update(loaded_data)
            user_data["public_key"] = serialization.load_pem_public_key(user_data["public_key"].encode())
            user_data["private_key"] = serialization.load_pem_private_key(user_data["private_key"].encode(), password=None)
            await display_startup_message(f"Config loaded. Welcome back, {user_data['original_username']}!")
        except Exception as e:
            await display_startup_message(f"Error loading config: {e}. Creating a new one.")
            # Use aioconsole ONLY if config doesn't exist or is invalid
            from aioconsole import ainput # Local import only when needed
            initial_username = await ainput("Enter your desired username: ")
            await create_new_user_config(config_file_path, initial_username)
    else:
        from aioconsole import ainput
        initial_username = await ainput("No config found. Enter your desired username: ")
        await create_new_user_config(config_file_path, initial_username)
        await display_startup_message(f"New config created. Welcome, {user_data['original_username']}")

async def create_new_user_config(config_file_path, username):
    """Create a new user configuration file."""
    if not username:
        logging.error("Cannot create user config with empty username.")
        # Handle this error appropriately, maybe re-prompt or exit
        return

    original_username = username
    internal_username = f"{original_username}_{uuid.uuid4()}" # Still useful internally
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    device_id = str(uuid.uuid4()) # Unique ID for this installation

    # Update global state
    user_data.clear()
    user_data.update({
        "original_username": original_username,
        "internal_username": internal_username,
        "public_key": public_key,
        "private_key": private_key,
        "device_id": device_id,
        "ip": await get_own_ip() # Store IP here too
    })

    # Save to file
    try:
        with open(config_file_path, "w") as f:
            json.dump({
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
            }, f, indent=4) # Add indent for readability
        logging.info(f"New user config saved to {config_file_path}")
    except Exception as e:
        logging.exception(f"Failed to save user config: {e}")
        # Decide how to handle this failure (e.g., put error message in queue)
        await message_queue.put(f"[ERROR] Failed to save configuration: {e}")


async def connect_to_peer(peer_ip, requesting_username, target_username, port=8765):
    """Establish a WebSocket connection to a peer."""
    if peer_ip == user_data.get('ip'):
         await message_queue.put("Cannot connect to yourself.")
         return None
    if peer_ip in connections:
        await message_queue.put(f"Already connected to {target_username} ({peer_ip}).")
        return None # Already connected

    uri = f"ws://{peer_ip}:{port}"
    websocket = None # Initialize websocket to None
    try:
        await message_queue.put(f"Attempting to connect to {target_username} at {uri}...")
        websocket = await asyncio.wait_for(
            websockets.connect(uri, ping_interval=20, ping_timeout=20, close_timeout=10),
            timeout=15.0 # Connection timeout
        )
        own_ip = user_data['ip']
        # 1. Send INIT
        await websocket.send(f"INIT {own_ip}")
        # 2. Receive INIT_ACK
        response = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        if not response.startswith("INIT_ACK"):
            raise ConnectionRefusedError("Peer did not send INIT_ACK.")

        # 3. Send CONNECTION_REQUEST (with pubkey)
        public_key_pem = user_data["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        await websocket.send(json.dumps({
            "type": "CONNECTION_REQUEST",
            "requesting_username": requesting_username,
            "target_username": target_username, # Let receiver verify
            "key": public_key_pem
        }))
        await message_queue.put(f"Connection request sent to {target_username}. Waiting for approval...")

        # 4. Receive CONNECTION_RESPONSE (approval/denial)
        approval_response = await asyncio.wait_for(websocket.recv(), timeout=60.0) # Longer timeout for user approval
        approval_data = json.loads(approval_response)
        if not (approval_data.get("type") == "CONNECTION_RESPONSE" and approval_data.get("approved")):
            await message_queue.put(f"Connection to {target_username} was denied by the peer.")
            await websocket.close()
            return None

        # 5. Send IDENTITY (username, pubkey)
        await websocket.send(json.dumps({
            "type": "IDENTITY",
            "username": requesting_username, # Send own username
            "device_id": user_data["device_id"],
            "key": public_key_pem
        }))

        # 6. Receive IDENTITY (peer's username, pubkey)
        identity_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        identity_data = json.loads(identity_message)
        if identity_data.get("type") == "IDENTITY":
            peer_username = identity_data["username"]
            peer_key_pem = identity_data["key"]
            peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_key_pem.encode())
            peer_usernames[peer_username] = peer_ip
            connections[peer_ip] = websocket
            logging.info(f"Successfully connected to {peer_username} ({peer_ip})")
            await message_queue.put(f"*** Connected to {peer_username} ({peer_ip}) ***")
            return websocket # Return the established connection
        else:
            raise ConnectionAbortedError("Peer sent invalid identity response.")

    except websockets.exceptions.InvalidURI:
         await message_queue.put(f"Connection failed: Invalid URI {uri}")
         logging.error(f"Invalid URI: {uri}")
    except ConnectionRefusedError as e:
        await message_queue.put(f"Connection to {target_username} refused: {e}")
        logging.warning(f"Connection to {peer_ip} refused.")
    except asyncio.TimeoutError:
        await message_queue.put(f"Connection to {target_username} timed out.")
        logging.warning(f"Connection or handshake timeout with {peer_ip}.")
    except Exception as e:
        await message_queue.put(f"Connection to {target_username} failed: {e}")
        logging.exception(f"Failed to connect to {peer_ip}: {e}")

    # Cleanup if connection failed at any point
    if websocket and websocket.open:
        await websocket.close()
    # Remove potential partial state
    if peer_ip in connections: del connections[peer_ip]
    if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
    # Find and remove username if it was added
    uname_to_remove = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), None)
    if uname_to_remove: del peer_usernames[uname_to_remove]

    return None


async def disconnect_from_peer(peer_username):
    """Disconnect from a specified peer."""
    if peer_username == user_data['original_username']:
         await message_queue.put("Cannot disconnect from yourself.")
         return

    peer_ip = peer_usernames.get(peer_username)
    if not peer_ip:
        await message_queue.put(f"Not connected to a peer named '{peer_username}'.")
        return

    if peer_ip in connections:
        websocket = connections[peer_ip]
        logging.info(f"Disconnecting from {peer_username} ({peer_ip})...")
        try:
            # Remove state *before* closing to prevent race conditions
            del connections[peer_ip]
            if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
            if peer_username in peer_usernames: del peer_usernames[peer_username]

            if websocket.open:
                await websocket.close(code=1000, reason="User disconnected")
            await message_queue.put(f"*** Disconnected from {peer_username} ({peer_ip}) ***")
            logging.info(f"Successfully disconnected from {peer_username} ({peer_ip}).")
        except Exception as e:
            logging.error(f"Error during disconnection from {peer_username} ({peer_ip}): {e}")
            await message_queue.put(f"Error disconnecting from {peer_username}: {e}")
            # State might already be partially removed, ensure cleanup
            if peer_ip in connections: del connections[peer_ip]
            if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
            if peer_username in peer_usernames: del peer_usernames[peer_username]
    else:
        # Clean up potentially inconsistent state if username exists but connection doesn't
        if peer_username in peer_usernames: del peer_usernames[peer_username]
        if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
        await message_queue.put(f"No active connection found for {peer_username}, but cleaned up state if any.")


async def handle_incoming_connection(websocket, peer_ip):
    """Handle the handshake for an incoming peer connection."""
    global current_connection_approval_ip # Allow modification
    try:
        # 1. Receive INIT
        message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        if shutdown_event.is_set(): return False
        if not message.startswith("INIT "):
             logging.warning(f"Invalid initial message from {peer_ip}: {message}")
             return False
        _sender_ip = message.split(" ", 1)[1] # We know the IP from websocket obj

        # Don't allow connection if already connected or it's self
        if peer_ip == user_data.get('ip'):
             logging.warning(f"Rejected connection attempt from self ({peer_ip})")
             return False
        if peer_ip in connections:
            logging.warning(f"Rejected duplicate connection attempt from {peer_ip}")
            return False

        # 2. Send INIT_ACK
        await websocket.send("INIT_ACK")

        # 3. Receive CONNECTION_REQUEST
        request_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        request_data = json.loads(request_message)

        if request_data.get("type") != "CONNECTION_REQUEST":
            logging.warning(f"Expected CONNECTION_REQUEST from {peer_ip}, got: {request_data.get('type')}")
            return False

        requesting_username = request_data.get("requesting_username")
        target_username = request_data.get("target_username")
        peer_key_pem = request_data.get("key")

        # Validate request
        if not all([requesting_username, target_username, peer_key_pem]):
             logging.warning(f"Incomplete CONNECTION_REQUEST from {peer_ip}")
             return False
        if target_username != user_data["original_username"]:
            logging.warning(f"Connection request for wrong user '{target_username}' from {peer_ip}. Denying.")
            await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False}))
            return False

        # --- Approval Process ---
        approval_future = asyncio.Future()
        pending_connection_approvals[peer_ip] = approval_future

        # Queue message for TUI display
        await message_queue.put({
            "type": "ui_connection_approval_request", # Specific type for UI
            "peer_ip": peer_ip,
            "requesting_username": requesting_username
        })
        # State variable handled by display_messages when it processes the queue item

        approved = False
        try:
            # Wait for the future to be set by user input ("yes"/"no")
            approved = await asyncio.wait_for(approval_future, timeout=60.0) # User decision timeout
        except asyncio.TimeoutError:
            logging.info(f"Connection approval for {requesting_username} ({peer_ip}) timed out.")
            await message_queue.put(f"Approval request from {requesting_username} timed out.")
            # Ensure state is cleaned up if timeout occurs before user input
            if current_connection_approval_ip == peer_ip:
                 current_connection_approval_ip = None
        finally:
             # Clean up pending approval future regardless of outcome
             if peer_ip in pending_connection_approvals:
                 del pending_connection_approvals[peer_ip]


        # 4. Send CONNECTION_RESPONSE
        await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": approved}))

        if not approved:
            logging.info(f"Denied connection from {requesting_username} ({peer_ip}).")
            # Track denials (optional, keep simple for now)
            return False # Close connection handled in main handle_peer_connection finally block

        # --- Connection Approved - Proceed with Identity Exchange ---
        logging.info(f"Connection from {requesting_username} ({peer_ip}) approved.")

        # 5. Receive IDENTITY (peer's username, pubkey) - Already have key from request
        # We already received the peer's key in the request, load it now
        try:
             peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_key_pem.encode())
        except Exception as key_error:
             logging.error(f"Invalid public key received from {peer_ip}: {key_error}")
             return False # Cannot proceed without valid key

        # 6. Send own IDENTITY
        own_public_key_pem = user_data["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        await websocket.send(json.dumps({
            "type": "IDENTITY",
            "username": user_data["original_username"],
            "device_id": user_data["device_id"],
            "key": own_public_key_pem
        }))

        # Final setup
        peer_usernames[requesting_username] = peer_ip
        connections[peer_ip] = websocket
        logging.info(f"Handshake complete. {user_data['original_username']} accepted connection from {requesting_username} ({peer_ip})")
        await message_queue.put(f"*** Connection established with {requesting_username} ({peer_ip}) ***")

        return True # Indicates successful connection, receive loop can start

    except json.JSONDecodeError:
        logging.warning(f"Invalid JSON received from {peer_ip} during handshake.")
    except asyncio.TimeoutError:
        logging.warning(f"Handshake timeout with {peer_ip}.")
    except websockets.exceptions.ConnectionClosed:
        logging.info(f"Connection closed by {peer_ip} during handshake.")
    except Exception as e:
        logging.exception(f"Error during incoming connection handshake with {peer_ip}: {e}")

    # If any error occurs, ensure the connection is not added or is cleaned up
    if peer_ip in connections: del connections[peer_ip]
    if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
    # Find and remove username if it was added
    uname_to_remove = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), None)
    if uname_to_remove: del peer_usernames[uname_to_remove]

    return False # Handshake failed

async def maintain_peer_list(discovery_instance):
    """Periodically update local peer list from discovery and check connections."""
    global peer_list
    while not shutdown_event.is_set():
        try:
            # Check active connections
            disconnected_peers = []
            for peer_ip, websocket in list(connections.items()):
                if shutdown_event.is_set(): break
                try:
                    # Use ping/pong to check liveness
                    await asyncio.wait_for(websocket.ping(), timeout=5.0)
                except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError, ConnectionResetError) as e:
                    logging.warning(f"Connection lost with {peer_ip} ({type(e).__name__}). Marking for removal.")
                    disconnected_peers.append(peer_ip)
                except Exception as e:
                     logging.error(f"Unexpected error pinging {peer_ip}: {e}")
                     # Consider disconnecting on unknown errors too? Maybe safer.
                     disconnected_peers.append(peer_ip)


            # Process disconnections outside the iteration loop
            if disconnected_peers:
                 for peer_ip in disconnected_peers:
                      peer_username = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), "unknown peer")
                      await message_queue.put(f"*** Connection lost with {peer_username} ({peer_ip}) ***")
                      # Ensure full cleanup
                      if peer_ip in connections:
                          try:
                              # Ensure connection is closed if possible
                              if connections[peer_ip].open:
                                   await connections[peer_ip].close()
                          except Exception: pass # Ignore errors during close
                          del connections[peer_ip]
                      if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
                      if peer_username != "unknown peer" and peer_username in peer_usernames:
                          del peer_usernames[peer_username]

            # Update discovered peer list
            peer_list = discovery_instance.peer_list.copy()

            await asyncio.sleep(10) # Check connections every 10 seconds
        except asyncio.CancelledError:
            logging.info("maintain_peer_list task cancelled.")
            break
        except Exception as e:
            logging.exception(f"Error in maintain_peer_list: {e}")
            await asyncio.sleep(10) # Wait before retrying after error
    logging.info("maintain_peer_list exited.")


async def send_message_to_peers(message_content, target_username=None):
    """Send an encrypted message to one or all connected peers."""
    if not message_content: return False

    peers_to_send = {}
    if target_username:
        peer_ip = peer_usernames.get(target_username)
        if not peer_ip:
            await message_queue.put(f"Error: No peer named '{target_username}' connected.")
            return False
        if peer_ip not in connections or not connections[peer_ip].open:
            await message_queue.put(f"Error: Connection to '{target_username}' is closed.")
            # Cleanup inconsistent state if necessary
            if peer_ip in connections: del connections[peer_ip]
            if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
            if target_username in peer_usernames: del peer_usernames[target_username]
            return False
        if peer_ip not in peer_public_keys:
             await message_queue.put(f"Error: Missing public key for '{target_username}'. Cannot encrypt.")
             return False
        peers_to_send[peer_ip] = connections[peer_ip]
    else:
        # Send to all connected peers
        peers_to_send = {ip: ws for ip, ws in connections.items() if ws.open}
        if not peers_to_send:
             await message_queue.put("No peers connected to send message.")
             return False

    sent_count = 0
    failed_peers = []
    for peer_ip, websocket in peers_to_send.items():
        public_key = peer_public_keys.get(peer_ip)
        if not public_key:
            logging.warning(f"Missing public key for {peer_ip}. Skipping message send.")
            failed_peers.append(peer_ip)
            continue

        try:
            encrypted_message = public_key.encrypt(
                message_content.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).hex()

            await websocket.send(
                json.dumps({"type": "MESSAGE", "message": encrypted_message})
            )
            sent_count += 1
        except Exception as e:
            logging.error(f"Failed to send message to {peer_ip}: {e}")
            failed_peers.append(peer_ip)
            # Consider disconnecting from peer if send fails? Optional.

    if failed_peers:
         await message_queue.put(f"Failed to send message to {len(failed_peers)} peer(s).")

    return sent_count > 0

# --- Message Receiving Logic ---

async def handle_received_message(data, peer_ip):
    """Process a received JSON message."""
    global current_file_approval_id # Allow modification
    message_type = data.get("type")
    peer_username = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), "Unknown")

    if message_type == "MESSAGE":
        try:
            encrypted_hex = data["message"]
            decrypted_bytes = user_data["private_key"].decrypt(
                bytes.fromhex(encrypted_hex),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_message = decrypted_bytes.decode()
            await message_queue.put(f"{peer_username}: {decrypted_message}")
        except (ValueError, KeyError) as e:
             logging.error(f"Decryption/Decoding error for message from {peer_ip}: {e}")
             await message_queue.put(f"[System] Error decrypting message from {peer_username}.")
        except Exception as e:
             logging.exception(f"Unexpected error handling MESSAGE from {peer_ip}: {e}")

    elif message_type == "file_transfer_init":
        transfer_id = data.get("transfer_id")
        relative_path = data.get("relative_path") # Use relative_path
        file_size = data.get("filesize")
        expected_hash = data.get("file_hash")

        if not all([transfer_id, relative_path, isinstance(file_size, int)]):
             logging.warning(f"Invalid file_transfer_init from {peer_ip}: Missing data.")
             return

        # Check if transfer already exists (e.g., duplicate init)
        if transfer_id in active_transfers or transfer_id in pending_file_receive_approvals:
             logging.warning(f"Duplicate file transfer init received for ID {transfer_id} from {peer_ip}. Ignoring.")
             return

        # Create placeholder transfer object in PENDING_APPROVAL state
        intended_path = os.path.join("downloads", relative_path)
        transfer = FileTransfer(
            intended_path, peer_ip, direction="receive",
            total_size=file_size, transfer_id=transfer_id
        )
        transfer.expected_hash = expected_hash
        transfer.relative_path = relative_path
        transfer.state = TransferState.PENDING_APPROVAL # Explicitly set
        active_transfers[transfer_id] = transfer # Add to track it

        # Prepare future for user approval
        approval_future = asyncio.Future()
        pending_file_receive_approvals[transfer_id] = approval_future

        # Queue message for TUI display
        await message_queue.put({
            "type": "ui_file_approval_request", # Specific type for UI
            "transfer_id": transfer_id,
            "peer_username": peer_username,
            "relative_path": relative_path,
            "file_size": file_size
        })
        # state variable current_file_approval_id handled by display_messages

        approved = False
        try:
            approved = await asyncio.wait_for(approval_future, timeout=60.0)
        except asyncio.TimeoutError:
            logging.info(f"File transfer approval {transfer_id} from {peer_username} timed out.")
            await message_queue.put(f"Approval for '{relative_path}' from {peer_username} timed out.")
            transfer.update_state(TransferState.DENIED) # Mark as denied on timeout
            # Clean up state variable if this was the current one
            if current_file_approval_id == transfer_id:
                 current_file_approval_id = None
        finally:
            # Clean up pending approval future
            if transfer_id in pending_file_receive_approvals:
                 del pending_file_receive_approvals[transfer_id]

        # Send ACK back to sender
        try:
            websocket = connections.get(peer_ip)
            if websocket and websocket.open:
                await websocket.send(json.dumps({
                    "type": "file_transfer_ack",
                    "transfer_id": transfer_id,
                    "approved": approved
                }))
            else:
                 logging.warning(f"Cannot send file ACK for {transfer_id}, peer {peer_ip} disconnected.")
                 approved = False # Treat as denial if peer disconnected before ACK
                 if transfer.state == TransferState.PENDING_APPROVAL: # Only update if still pending
                      transfer.update_state(TransferState.FAILED)
        except Exception as e:
             logging.error(f"Error sending file ACK for {transfer_id} to {peer_ip}: {e}")
             approved = False # Treat as denial if ACK fails
             if transfer.state == TransferState.PENDING_APPROVAL:
                  transfer.update_state(TransferState.FAILED)


        # If approved, prepare for receiving chunks
        if approved:
            await message_queue.put(f"Approved receiving '{relative_path}'. Preparing download...")
            try:
                # Ensure downloads directory and subdirectories exist
                download_dir = os.path.dirname(intended_path)
                os.makedirs(download_dir, exist_ok=True)

                # Open file and update state
                transfer.file_handle = await aiofiles.open(intended_path, "wb")
                transfer.hash_algo = hashlib.sha256() if expected_hash else None # Reset hash algo
                transfer.transferred_size = 0
                transfer.update_state(TransferState.IN_PROGRESS) # Ready for chunks
                logging.info(f"Transfer {transfer_id}: Approved and ready for chunks at {intended_path}")

            except Exception as e:
                 logging.exception(f"Error preparing file {intended_path} for receiving: {e}")
                 await message_queue.put(f"[ERROR] Could not prepare for download: {e}")
                 transfer.update_state(TransferState.FAILED)
                 # Attempt to inform sender? Maybe too complex, sender will timeout/fail on chunk send.
        else:
             # Denied or failed ACK send
             if transfer.state == TransferState.PENDING_APPROVAL: # Check state before marking denied
                 transfer.update_state(TransferState.DENIED)
             logging.info(f"Transfer {transfer_id} from {peer_username} denied or failed ACK.")
             await message_queue.put(f"Denied file transfer '{relative_path}' from {peer_username}.")
             # update_transfer_progress will remove the denied transfer object


    elif message_type == "file_transfer_ack":
        # Received by the ORIGINAL SENDER
        transfer_id = data.get("transfer_id")
        approved = data.get("approved", False) # Default to False if missing
        ack_map = pending_file_send_acks.get(transfer_id)
        if ack_map:
            future = ack_map.get(peer_ip)
            if future and not future.done():
                future.set_result(approved) # Set the result (True/False)
                logging.debug(f"Received file ACK for {transfer_id} from {peer_ip}: Approved={approved}")
            else:
                 logging.warning(f"Received unexpected/late file ACK for {transfer_id} from {peer_ip}")
        else:
            logging.warning(f"Received file ACK for unknown/completed transfer {transfer_id} from {peer_ip}")


    elif message_type == "file_chunk":
        transfer_id = data.get("transfer_id")
        transfer = active_transfers.get(transfer_id)

        if not transfer:
            logging.warning(f"Received chunk for unknown or completed transfer {transfer_id} from {peer_ip}. Ignoring.")
            return
        if transfer.direction != "receive":
            logging.warning(f"Received file chunk for a 'send' transfer {transfer_id}. Ignoring.")
            return
        if transfer.state != TransferState.IN_PROGRESS:
             # Ignore chunks if paused, completed, failed, etc.
             # Sender might send a few extra if state changes right after check.
             if transfer.state == TransferState.PAUSED:
                  logging.debug(f"Ignoring chunk for paused transfer {transfer_id}")
             else:
                  logging.warning(f"Received chunk for transfer {transfer_id} in unexpected state {transfer.state}. Ignoring.")
             return
        if not transfer.file_handle or transfer.file_handle.closed:
             logging.error(f"Transfer {transfer_id}: File handle closed or missing while receiving chunk.")
             transfer.update_state(TransferState.FAILED)
             return

        try:
            chunk_hex = data.get("chunk")
            if not chunk_hex:
                logging.warning(f"Received empty file chunk data for {transfer_id}. Assuming end?")
                # Should not happen if sender logic is correct, maybe mark failed?
                transfer.update_state(TransferState.FAILED)
                return

            chunk = bytes.fromhex(chunk_hex)
            await transfer.file_handle.write(chunk)
            transfer.transferred_size += len(chunk)
            if transfer.hash_algo:
                transfer.hash_algo.update(chunk)

            # Check completion
            if transfer.transferred_size >= transfer.total_size:
                logging.info(f"Transfer {transfer_id}: Received expected size ({transfer.total_size} bytes). Finalizing...")
                await transfer.file_handle.close()
                transfer.file_handle = None

                # Verify hash if provided
                if transfer.expected_hash:
                    calculated_hash = transfer.hash_algo.hexdigest()
                    if calculated_hash == transfer.expected_hash:
                        transfer.update_state(TransferState.COMPLETED)
                        await message_queue.put(f"✅ File '{transfer.relative_path}' received successfully and verified.")
                        logging.info(f"Transfer {transfer_id}: Hash verification successful.")
                    else:
                        transfer.update_state(TransferState.FAILED)
                        await message_queue.put(f"❌ File '{transfer.relative_path}' failed integrity check! Deleted.")
                        logging.warning(f"Transfer {transfer_id}: Hash mismatch! Expected {transfer.expected_hash}, got {calculated_hash}. Deleting file.")
                        try:
                             os.remove(transfer.file_path)
                        except OSError as e:
                             logging.error(f"Failed to delete corrupted file {transfer.file_path}: {e}")
                else:
                    # No hash provided
                    transfer.update_state(TransferState.COMPLETED)
                    await message_queue.put(f"✅ File '{transfer.relative_path}' received successfully (no hash provided).")
                    logging.info(f"Transfer {transfer_id}: Completed (no hash verification).")

        except ValueError as e: # bytes.fromhex error
             logging.error(f"Transfer {transfer_id}: Invalid hex data in chunk: {e}")
             transfer.update_state(TransferState.FAILED)
             if transfer.file_handle and not transfer.file_handle.closed: await transfer.file_handle.close()
        except Exception as e:
            logging.exception(f"Transfer {transfer_id}: Error writing file chunk: {e}")
            transfer.update_state(TransferState.FAILED)
            if transfer.file_handle and not transfer.file_handle.closed: await transfer.file_handle.close()

    elif message_type == "folder_transfer_init":
         # Received by receiver
         folder_name = data.get("folder_name")
         file_count = data.get("file_count")
         await message_queue.put(f"Receiving folder '{folder_name}' ({file_count} files) from {peer_username}...")
         # Can add more logic here if needed, like creating the top-level folder early

    else:
        logging.debug(f"Received unhandled message type '{message_type}' from {peer_ip}")


async def receive_peer_messages(websocket, peer_ip):
    """Receive and process messages from a connected peer."""
    peer_username = "Unknown" # Placeholder
    try:
        # Ensure peer is fully registered before starting receive loop
        await asyncio.sleep(0.1) # Small delay to allow state update
        peer_username = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), f"Peer_{peer_ip}")
        logging.info(f"Starting message receive loop for {peer_username} ({peer_ip})")

        async for message in websocket:
            if shutdown_event.is_set():
                break
            try:
                # Assume JSON, fallback for plain text? (Less likely with current protocol)
                data = json.loads(message)
                await handle_received_message(data, peer_ip)

            except json.JSONDecodeError:
                 # Handle non-JSON message (e.g., plain text chat if encryption/protocol fails?)
                 # This shouldn't happen with the current strict JSON protocol
                 logging.warning(f"Received non-JSON message from {peer_username} ({peer_ip}): {message[:100]}") # Log truncated message
                 # await message_queue.put(f"{peer_username} (raw): {message}") # Optionally display raw message

            except Exception as e:
                 logging.exception(f"Error processing message from {peer_username} ({peer_ip}): {e}")
                 # Consider if certain errors should cause disconnection

    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"Connection closed normally by {peer_username} ({peer_ip})")
    except websockets.exceptions.ConnectionClosedError as e:
        logging.warning(f"Connection closed with error by {peer_username} ({peer_ip}): {e.code} {e.reason}")
    except asyncio.CancelledError:
         logging.info(f"Receive loop for {peer_username} ({peer_ip}) cancelled.")
    except Exception as e:
         logging.exception(f"Unexpected error in receive loop for {peer_username} ({peer_ip}): {e}")
    finally:
        logging.info(f"Exiting receive loop for {peer_username} ({peer_ip}). Cleaning up...")
        # Ensure cleanup happens if connection drops unexpectedly
        if peer_ip in connections:
            del connections[peer_ip]
        if peer_ip in peer_public_keys:
            del peer_public_keys[peer_ip]
        # Use the potentially updated username
        current_peer_username = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), None)
        if current_peer_username and current_peer_username in peer_usernames:
            del peer_usernames[current_peer_username]
            await message_queue.put(f"*** {current_peer_username} ({peer_ip}) disconnected ***")
        else:
             # If username wasn't found, maybe it changed or wasn't fully set up
             await message_queue.put(f"*** Peer {peer_ip} disconnected ***")

        # Cancel any pending file transfers associated with this peer
        for tid, transfer in list(active_transfers.items()):
             if transfer.peer_ip == peer_ip and transfer.state not in (TransferState.COMPLETED, TransferState.FAILED, TransferState.DENIED):
                 logging.warning(f"Cancelling active transfer {tid} due to peer {peer_ip} disconnection.")
                 transfer.update_state(TransferState.FAILED)
                 if transfer.file_handle: await transfer.file_handle.close() # Close file handle


# --- User Input Handling ---

async def handle_input(message, discovery_instance):
    """Process user input command."""
    global current_connection_approval_ip, current_file_approval_id # Allow modification
    if not message: return

    try:
        if message == "EXIT_APP_SIGNAL": # Handle Ctrl+C/Ctrl+D
            await message_queue.put("Shutdown signal received...")
            shutdown_event.set()
            # TUI will exit automatically, main loop handles task cancellation
            return # Prevent further processing

        elif message == "/exit":
            await message_queue.put("Shutting down application...")
            shutdown_event.set()
            return

        elif message == "/help":
            help_text = """
Available commands:
/connect <username>     - Connect to a discovered peer by username.
/disconnect <username>  - Disconnect from a connected peer.
/msg <username> <text>  - Send a private message to a connected peer.
/send <user> <path>     - Request to send a file to a connected peer.
/sendfolder <user> <path> - Request to send a folder to a connected peer.
/pause <transfer_id>    - Pause an ongoing file transfer.
/resume <transfer_id>   - Resume a paused file transfer.
/transfers              - List active and recent file transfers.
/list                   - Show discovered and connected peers.
/changename <new_name>  - Change your username (requires restart?).
/exit                   - Exit the application.
/help                   - Show this help message.
yes / no                - Respond to connection or file transfer requests.
(Any other text)        - Send message to all connected peers.
"""
            await message_queue.put(help_text)

        elif message == "/list":
            output = ["\n--- Peers ---"]
            own_ip = user_data.get('ip')
            # Connected Peers
            if peer_usernames:
                 output.append("Connected:")
                 for uname, ip in peer_usernames.items():
                      output.append(f"  - {uname} ({ip})")
            # Discovered Peers (not connected)
            discovered_peers = []
            for ip, (uname, _) in peer_list.items():
                 if ip != own_ip and ip not in connections:
                      discovered_peers.append(f"  - {uname} ({ip})")
            if discovered_peers:
                output.append("Discovered:")
                output.extend(discovered_peers)

            if len(output) == 1: # Only the header
                 output.append("No other peers found.")
            await message_queue.put("\n".join(output))


        elif message.startswith("/connect "):
            target_username = message[9:].strip()
            if not target_username:
                 await message_queue.put("Usage: /connect <username>")
                 return
            peer_ip = next((ip for ip, (uname, _) in peer_list.items() if uname == target_username), None)
            if not peer_ip:
                 await message_queue.put(f"Peer '{target_username}' not found in discovered list.")
                 return

            requesting_username = user_data["original_username"]
            # Start connection attempt in background
            asyncio.create_task(connect_to_peer(peer_ip, requesting_username, target_username))

        elif message.startswith("/disconnect "):
            target_username = message[12:].strip()
            if not target_username:
                 await message_queue.put("Usage: /disconnect <username>")
                 return
            await disconnect_from_peer(target_username) # disconnect_from_peer handles messaging

        elif message.startswith("/msg "):
            parts = message[5:].split(" ", 1)
            if len(parts) < 2:
                await message_queue.put("Usage: /msg <username> <message>")
                return
            target_username, msg_content = parts
            if await send_message_to_peers(msg_content, target_username):
                 await message_queue.put(f"Me → {target_username}: {msg_content}")

        elif message.startswith("/send ") or message.startswith("/sendfolder "):
             is_folder = message.startswith("/sendfolder")
             command_len = 12 if is_folder else 6
             parts = message[command_len:].split(" ", 1)
             if len(parts) < 2:
                 await message_queue.put(f"Usage: /{ 'sendfolder' if is_folder else 'send' } <username> <path_to_{ 'folder' if is_folder else 'file' }>")
                 return
             target_username, item_path = parts
             peer_ip = peer_usernames.get(target_username)
             if not peer_ip:
                  await message_queue.put(f"Error: Peer '{target_username}' is not connected.")
                  return
             websocket = connections.get(peer_ip)
             if not websocket or not websocket.open:
                  await message_queue.put(f"Error: Connection to '{target_username}' is closed.")
                  # Consider cleanup? maintain_peer_list should handle it.
                  return

             item_path_abs = os.path.abspath(item_path) # Use absolute path

             if is_folder:
                  if not os.path.isdir(item_path_abs):
                       await message_queue.put(f"Error: Path is not a valid directory: {item_path_abs}")
                       return
                  # Start folder transfer in background
                  asyncio.create_task(send_folder(item_path_abs, peer_ip, websocket))
             else:
                  if not os.path.isfile(item_path_abs):
                       await message_queue.put(f"Error: Path is not a valid file: {item_path_abs}")
                       return
                  # Start file transfer in background
                  asyncio.create_task(send_file(item_path_abs, {peer_ip: websocket}))


        elif message.startswith("/pause "):
            transfer_id = message[7:].strip()
            if not transfer_id:
                 await message_queue.put("Usage: /pause <transfer_id>")
                 return
            transfer = active_transfers.get(transfer_id)
            if transfer:
                await transfer.pause() # pause method logs info
                await message_queue.put(f"Attempted to pause transfer {transfer_id}.")
            else:
                await message_queue.put(f"No active transfer found with ID: {transfer_id}")

        elif message.startswith("/resume "):
            transfer_id = message[8:].strip()
            if not transfer_id:
                 await message_queue.put("Usage: /resume <transfer_id>")
                 return
            transfer = active_transfers.get(transfer_id)
            if transfer:
                await transfer.resume() # resume method logs info
                await message_queue.put(f"Attempted to resume transfer {transfer_id}.")
            else:
                await message_queue.put(f"No active transfer found with ID: {transfer_id}")

        elif message == "/transfers":
            if not active_transfers:
                await message_queue.put("\nNo active file transfers.")
            else:
                output = ["\n--- Active Transfers ---"]
                for tid, t in active_transfers.items():
                    direction = "Sending" if t.direction == "send" else "Receiving"
                    peer_uname = next((uname for uname, ip in peer_usernames.items() if ip == t.peer_ip), t.peer_ip) # Show IP if uname unknown
                    path_display = t.relative_path or os.path.basename(t.file_path)
                    progress = (t.transferred_size / t.total_size * 100) if t.total_size > 0 else (100 if t.state == TransferState.COMPLETED else 0)
                    output.append(f"- ID: {tid}")
                    output.append(f"    {'To' if direction=='Sending' else 'From'}: {peer_uname}")
                    output.append(f"    Item: '{path_display}'")
                    output.append(f"    State: {t.state.value} ({progress:.1f}%)")
                    output.append(f"    Size: {t.transferred_size} / {t.total_size}")
                await message_queue.put("\n".join(output))

        elif message.startswith("/changename "):
            new_username = message[12:].strip()
            if not new_username:
                await message_queue.put("Usage: /changename <new_username>")
                return
            if new_username == user_data.get('original_username'):
                 await message_queue.put("New username is the same as the current one.")
                 return

            config_dir = get_config_directory()
            config_file = os.path.join(config_dir, "user_config.json")
            logging.info(f"Attempting to change username to {new_username}. Config: {config_file}")

            # Re-create config file with new username but same keys/ID
            # Note: This keeps the same identity, just changes display name.
            # Peers will see the new name on next discovery broadcast or reconnection.
            # A more complex approach would involve notifying peers.
            try:
                 # Backup old data just in case
                 old_username = user_data.get('original_username')
                 user_data['original_username'] = new_username
                 # Resave the config file with the updated username
                 with open(config_file, "w") as f:
                     json.dump({
                         "original_username": new_username,
                         "internal_username": user_data['internal_username'], # Keep internal
                         "public_key": user_data['public_key'].public_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PublicFormat.SubjectPublicKeyInfo
                         ).decode(),
                         "private_key": user_data['private_key'].private_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.PKCS8,
                             encryption_algorithm=serialization.NoEncryption()
                         ).decode(),
                         "device_id": user_data['device_id'] # Keep device ID
                     }, f, indent=4)

                 await message_queue.put(f"Username changed to {new_username}. Restart might be needed for full effect.")
                 logging.info(f"Username updated in config file. Sending immediate broadcast.")

                 # Update TUI prompt immediately
                 get_app().layout.get_children()[2].prompt = get_current_prompt # Update prompt callable source data

                 # Send broadcast immediately to announce change
                 await discovery_instance.send_immediate_broadcast()
            except Exception as e:
                 logging.exception("Failed to save config during username change.")
                 await message_queue.put(f"[ERROR] Failed to change username: {e}")
                 # Revert change in memory if save failed
                 user_data['original_username'] = old_username

        elif message.lower() == "yes" or message.lower() == "no":
            is_yes = message.lower() == "yes"
            responded = False
            # Prioritize file approvals as they might be more frequent
            if current_file_approval_id:
                 transfer_id = current_file_approval_id
                 future = pending_file_receive_approvals.get(transfer_id)
                 if future and not future.done():
                      logging.info(f"User responded '{message}' to file transfer {transfer_id}")
                      future.set_result(is_yes)
                      await message_queue.put(f"Response '{message}' sent for file transfer.")
                      responded = True
                 else:
                      logging.warning(f"User response '{message}' but no active file future for {transfer_id}")
                 current_file_approval_id = None # Clear regardless

            # If not handled as file approval, check connection approval
            elif current_connection_approval_ip:
                 peer_ip = current_connection_approval_ip
                 future = pending_connection_approvals.get(peer_ip)
                 if future and not future.done():
                      logging.info(f"User responded '{message}' to connection request from {peer_ip}")
                      future.set_result(is_yes)
                      await message_queue.put(f"Response '{message}' sent for connection request.")
                      responded = True
                 else:
                      logging.warning(f"User response '{message}' but no active connection future for {peer_ip}")
                 current_connection_approval_ip = None # Clear regardless

            if not responded:
                 await message_queue.put(f"'{message}' received, but no pending approval request.")

        elif not message.startswith("/"):
            # Send as broadcast message to all connected peers
            if await send_message_to_peers(message):
                 await message_queue.put(f"Me (to all): {message}")

        else:
             await message_queue.put(f"Unknown command: {message.split()[0]}. Type /help for options.")

    except asyncio.CancelledError:
        raise # Propagate cancellation
    except Exception as e:
        logging.exception(f"Error handling input '{message}': {e}")
        await message_queue.put(f"[ERROR] Failed to process command: {e}")

# --- TUI Runner Task ---

async def user_input(discovery, initial_messages=None): # Added initial_messages parameter
    """Main task to run the TUI and handle input/output."""
    global tui_app, current_connection_approval_ip, current_file_approval_id, message_queue, shutdown_event # Ensure needed globals are accessible

    # Set initial text for the output area from messages passed by main()
    if initial_messages:
        # Join messages with newlines for initial display
        output_area.text = "\n".join(initial_messages)
    else:
        output_area.text = "" # Ensure it starts empty if no messages provided

    # Task to display messages from the queue in the TUI output area
    async def display_messages():
        """Reads from message_queue and updates the TUI output area."""
        global current_connection_approval_ip, current_file_approval_id # Allow modification of approval state

        while not shutdown_event.is_set():
            try:
                # Wait for an item from the queue
                item = await message_queue.get()
                # Check shutdown flag again after await, in case it was set while waiting
                if shutdown_event.is_set():
                    message_queue.task_done() # Mark item as processed to prevent queue buildup on exit
                    break

                # Prepare message string for display based on item type
                display_text = ""
                # Reset approval flags by default, set them if item is an approval request
                is_approval_request = False
                temp_conn_ip = None
                temp_file_id = None

                if isinstance(item, dict):
                    msg_type = item.get("type")
                    if msg_type == "ui_file_approval_request":
                        # Set temporary approval state for this message
                        temp_file_id = item["transfer_id"]
                        # Format the approval request text
                        peer_username = item["peer_username"]
                        relative_path = item["relative_path"]
                        file_size = item["file_size"]
                        display_text = f"❓ File request from {peer_username}: '{relative_path}' ({file_size} bytes). Accept? (yes/no)"
                        is_approval_request = True
                    elif msg_type == "ui_connection_approval_request":
                        # Set temporary approval state for this message
                        temp_conn_ip = item["peer_ip"]
                        # Format the approval request text
                        peer_ip = item["peer_ip"]
                        requesting_username = item["requesting_username"]
                        display_text = f"❓ Connection request from {requesting_username} ({peer_ip}). Accept? (yes/no)"
                        is_approval_request = True
                    else:
                         # Fallback for other dictionary types received
                         display_text = f"[System Dict]: {item}"
                elif isinstance(item, str):
                    # Handle plain string messages
                    display_text = f"{item}"
                else:
                    # Handle unexpected types in the queue
                    display_text = f"[System Unknown Type]: {type(item).__name__}"

                # --- Safely update TUI output area ---
                def update_output(text_to_add, set_conn_ip, set_file_id):
                    """Nested function to perform the actual UI update."""
                    global current_connection_approval_ip, current_file_approval_id
                    try:
                        # Update global approval state *only if* this message is an approval request
                        if set_conn_ip:
                             current_connection_approval_ip = set_conn_ip
                             current_file_approval_id = None # Clear other approval type
                             logging.debug(f"Set pending connection approval for IP: {set_conn_ip}")
                        elif set_file_id:
                             current_file_approval_id = set_file_id
                             current_connection_approval_ip = None # Clear other approval type
                             logging.debug(f"Set pending file approval for ID: {set_file_id}")
                        # If not an approval request, the global state remains as it was

                        # Check if output area is currently empty before adding newline
                        prefix = "\n" if output_area.text else ""
                        # Add display text (strip any accidental leading newline from formatting)
                        new_text_content = output_area.text + prefix + text_to_add.lstrip('\n')

                        # Limit buffer size to prevent excessive memory use (optional)
                        max_lines = 1000 # Adjust as needed
                        lines = new_text_content.split('\n')
                        if len(lines) > max_lines:
                            # Keep the last 'max_lines' lines
                            new_text_content = '\n'.join(lines[-max_lines:])

                        # Update the widget's text attribute directly
                        output_area.text = new_text_content

                    except Exception as update_err:
                         # Log errors occurring within the threadsafe call context
                         logging.error(f"Error inside update_output: {update_err}")

                # --- Schedule UI Update ---
                # Check if the TUI application object is currently running
                if tui_app.is_running:
                     # Get the application's event loop
                     loop = get_app().loop
                     # Schedule the UI update function to run in the application's thread
                     loop.call_soon_threadsafe(update_output, display_text, temp_conn_ip, temp_file_id)
                     # Schedule a redraw of the application
                     loop.call_soon_threadsafe(tui_app.invalidate)
                else:
                    # Fallback if TUI isn't running (e.g., very early messages before run_async starts fully)
                    # This path is less critical now with initial_messages, but kept as safety
                    prefix = "\n" if output_area.text else ""
                    output_area.text += prefix + display_text.lstrip('\n')
                    logging.debug(f"TUI not running, appended message directly: {display_text}")

                # Mark the queued item as processed
                message_queue.task_done()

            except asyncio.CancelledError:
                # Log cancellation and break the loop
                logging.info("Display messages task cancelled.")
                break
            except Exception as e:
                # Log unexpected errors in the display loop
                logging.exception(f"Error in display_messages loop: {e}")
                # Avoid tight loop on continuous errors
                await asyncio.sleep(1)

    # --- Start the Background Display Task ---
    # Create and start the task that handles reading the queue and updating the UI
    display_task = asyncio.create_task(display_messages(), name="MessageDisplay")

    # --- Main TUI Interaction Loop ---
    try:
        # Loop indefinitely until shutdown is triggered
        while not shutdown_event.is_set():
            # Run the prompt_toolkit application asynchronously.
            # It waits for user input and returns the text when Enter is pressed
            # (due to the accept_handler lambda function in input_area setup).
            input_text = await tui_app.run_async()

            # After run_async returns, check if shutdown was triggered
            # or if a special signal was received from keybindings (like Ctrl+C)
            if shutdown_event.is_set() or input_text == "EXIT_APP_SIGNAL":
                 if shutdown_event.is_set():
                      logging.debug("Shutdown event set while TUI was waiting for input or processing.")
                 else:
                      logging.debug("TUI exit signal received.")
                 break # Exit the while loop to proceed to finally block

            # If not shutting down, process the valid input text received
            # handle_input will set shutdown_event if the command was /exit
            await handle_input(input_text, discovery)

    except asyncio.CancelledError:
         # This task itself was cancelled (likely during shutdown)
         logging.info("User input task cancelled.")
    except EOFError:
        # Handle Ctrl+D if pressed when input is focused (might be caught by bindings too)
        logging.info("EOF received, initiating shutdown.")
        # Ensure message queue is used if possible, otherwise print
        try:
            await message_queue.put("EOF received, shutting down...")
        except Exception: # Catch potential errors if queue is broken during shutdown
            print("EOF received, shutting down...")
        shutdown_event.set()
    except Exception as e:
         # Catch any other unexpected errors in the TUI loop itself
         logging.exception(f"Error in user_input TUI loop: {e}")
         shutdown_event.set() # Trigger shutdown on critical TUI error
    finally:
        # --- Cleanup for the user_input task ---
        logging.info("Exiting user input TUI loop.")

        # Ensure the background display task is cancelled
        if display_task and not display_task.done():
            display_task.cancel()
            try:
                # Wait briefly for the display_task to finish cancellation
                await asyncio.wait_for(display_task, timeout=1.0)
            except asyncio.CancelledError:
                pass # Expected outcome of cancellation
            except asyncio.TimeoutError:
                 logging.warning("Timed out waiting for display_task to cancel.")
            except Exception as display_cancel_err:
                 logging.error(f"Error occurred while cancelling display_task: {display_cancel_err}")

        # Ensure the prompt_toolkit application is stopped if it's somehow still running
        if tui_app.is_running:
             try:
                  tui_app.exit()
             except Exception as app_exit_err:
                  # Ignore errors if it's already exiting or fails during shutdown
                  logging.debug(f"Exception during tui_app.exit() in finally block: {app_exit_err}")