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
    active_transfers, message_queue, connections, user_data, peer_public_keys, peer_usernames, shutdown_event, pending_file_approvals
)
from networking.file_transfer import send_file, send_folder, FileTransfer, TransferState
from websockets.connection import State
from appdirs import user_config_dir
from prompt_toolkit import Application
from prompt_toolkit.layout import Layout, HSplit, Window
from prompt_toolkit.widgets import TextArea
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory

# Global state
peer_list = {}  # {ip: (username, last_seen)}
connection_denials = {}  # {target_username: {requesting_username: denial_count}}
pending_approvals = {}  # {peer_ip: asyncio.Future}

def get_prompt():
    return f"{user_data.get('original_username', 'User')} > "

# Define the TUI layout
output_area = TextArea(
    height=10,
    prompt="",
    multiline=True,
    wrap_lines=True,
    read_only=True,
    focusable=False
)
input_area = TextArea(
    height=1,
    prompt=f"{user_data.get('original_username', 'User')} > ",
    multiline=False,
    accept_handler=None,  # We'll handle this manually
    history=InMemoryHistory(),
    completer=WordCompleter(["/connect", "/disconnect", "/msg", "/send", "/pause", "/resume", "/transfers", "/list", "/changename", "/exit", "/help"], ignore_case=True)
)

layout = Layout(
    HSplit([
        output_area,  # Output area for messages
        input_area    # Input area for typing
    ])
)

bindings = KeyBindings()

@bindings.add("enter")
def _(event):
    asyncio.create_task(handle_input(input_area.text))
    input_area.text = ""  # Clear input after sending

app = Application(layout=layout, key_bindings=bindings, full_screen=False)

def get_config_directory():
    """Determine the appropriate config directory based on the OS."""
    appname = "P2PChat"
    appauthor = False
    return user_config_dir(appname, appauthor)

async def initialize_user_config():
    """Load or create user configuration, using a user-specific config directory."""
    config_dir = get_config_directory()
    os.makedirs(config_dir, exist_ok=True)
    config_file_path = os.path.join(config_dir, "user_config.json")
    
    if os.path.exists(config_file_path):
        try:
            with open(config_file_path, "r") as f:
                loaded_data = json.load(f)
            user_data.update(loaded_data)
            user_data["public_key"] = serialization.load_pem_public_key(user_data["public_key"].encode())
            user_data["private_key"] = serialization.load_pem_private_key(user_data["private_key"].encode(), password=None)
            print(f"Welcome back, {user_data['original_username']}!")
        except Exception as e:
            print(f"Error loading config, creating new one: {e}")
            await create_new_user_config(config_file_path)
    else:
        await create_new_user_config(config_file_path)
        print(f"Welcome, {user_data['original_username']}")

async def create_new_user_config(config_file_path, username=None):
    """Create a new user configuration file in the specified path."""
    if username is None:
        from aioconsole import ainput  # Import here to avoid TUI conflict
        original_username = await ainput("Enter your username: ")
    else:
        original_username = username
    
    internal_username = f"{original_username}_{uuid.uuid4()}"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    device_id = str(uuid.uuid4())
    
    user_data.clear()
    user_data.update({
        "original_username": original_username,
        "internal_username": internal_username,
        "public_key": public_key,
        "private_key": private_key,
        "device_id": device_id
    })
    
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
        }, f)

async def connect_to_peer(peer_ip, requesting_username, target_username, port=8765):
    """Establish a WebSocket connection to a peer."""
    if peer_ip in connections:
        return None
    uri = f"ws://{peer_ip}:{port}"
    try:
        websocket = await websockets.connect(uri, ping_interval=None, max_size=None)
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
                    await message_queue.put(f"Connection to {target_username} failed: Invalid identity response.")
                    return None
            else:
                await websocket.close()
                await message_queue.put(f"Connection to {target_username} was denied by the peer.")
                return None
        else:
            await websocket.close()
            await message_queue.put(f"Connection to {target_username} failed: No INIT_ACK received.")
            return None
    except Exception as e:
        logging.exception(f"Failed to connect to {peer_ip}: {e}")
        await message_queue.put(f"Connection to {target_username} failed: {str(e)}")
        if 'websocket' in locals():
            await websocket.close()
        return None

async def disconnect_from_peer(peer_username):
    """Disconnect from a specified peer."""
    if peer_username in peer_usernames:
        peer_ip = peer_usernames[peer_username]
        if peer_ip in connections:
            websocket = connections[peer_ip]
            try:
                await websocket.close()
                del connections[peer_ip]
                del peer_public_keys[peer_ip]
                del peer_usernames[peer_username]
                await message_queue.put(f"Disconnected from {peer_username} ({peer_ip})")
            except Exception as e:
                logging.error(f"Error disconnecting from {peer_username} ({peer_ip}): {e}")
                await message_queue.put(f"Failed to disconnect from {peer_username}: {e}")
        else:
            await message_queue.put(f"Not connected to {peer_username}")
    else:
        await message_queue.put(f"No such peer: {peer_username}")

async def handle_incoming_connection(websocket, peer_ip):
    """Handle an incoming peer connection request."""
    try:
        message = await websocket.recv()
        if shutdown_event.is_set():
            await websocket.close()
            return False
        if message.startswith("INIT "):
            _, sender_ip = message.split(" ", 1)
            own_ip = await get_own_ip()
            if peer_ip not in connections:
                await websocket.send("INIT_ACK")
                request_message = await websocket.recv()
                request_data = json.loads(request_message)
                if request_data["type"] == "CONNECTION_REQUEST":
                    requesting_username = request_data["requesting_username"]
                    target_username = request_data["target_username"]
                    if target_username != user_data["original_username"]:
                        await websocket.send(json.dumps({
                            "type": "CONNECTION_RESPONSE",
                            "approved": False
                        }))
                        await websocket.close()
                        return False

                    approval_future = asyncio.Future()
                    pending_approvals[peer_ip] = approval_future
                    await message_queue.put({
                        "type": "approval_request",
                        "peer_ip": peer_ip,
                        "requesting_username": requesting_username
                    })

                    try:
                        approved = await asyncio.wait_for(approval_future, timeout=30.0)
                    except asyncio.TimeoutError:
                        logging.info(f"Approval for {requesting_username} ({peer_ip}) timed out.")
                        del pending_approvals[peer_ip]
                        await websocket.send(json.dumps({
                            "type": "CONNECTION_RESPONSE",
                            "approved": False
                        }))
                        await websocket.close()
                        return False

                    del pending_approvals[peer_ip]
                    if not approved:
                        if target_username not in connection_denials:
                            connection_denials[target_username] = {}
                        denial_count = connection_denials[target_username].get(requesting_username, 0) + 1
                        connection_denials[target_username][requesting_username] = denial_count
                        await message_queue.put(f"Denied connection from {requesting_username} ({denial_count}/3)")
                        if denial_count >= 3:
                            await message_queue.put(f"{requesting_username} has been blocked for this session.")
                    await websocket.send(json.dumps({
                        "type": "CONNECTION_RESPONSE",
                        "approved": approved
                    }))
                    if not approved:
                        await websocket.close()
                        return False

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
                    identity_message = await websocket.recv()
                    identity_data = json.loads(identity_message)
                    if identity_data["type"] == "IDENTITY":
                        peer_username = identity_data["username"]
                        peer_public_keys[peer_ip] = serialization.load_pem_public_key(identity_data["key"].encode())
                        peer_usernames[peer_username] = peer_ip
                        connections[peer_ip] = websocket
                        logging.info(f"{user_data['original_username']} accepted connection from {peer_username} ({peer_ip})")
                        return True
                    else:
                        await websocket.close()
                        return False
            else:
                await websocket.close()
                return False
    except Exception as e:
        logging.exception(f"Error in connection handshake: {e}")
        if websocket and websocket.state == State.OPEN:
            await websocket.close()
        return False

async def maintain_peer_list(discovery_instance):
    """Maintain the list of connected peers."""
    global peer_list
    while not shutdown_event.is_set():
        try:
            for peer_ip in list(connections.keys()):
                if shutdown_event.is_set():
                    break
                try:
                    await connections[peer_ip].ping()
                except websockets.exceptions.ConnectionClosed:
                    del connections[peer_ip]
                    del peer_public_keys[peer_ip]
                    for username, ip in list(peer_usernames.items()):
                        if ip == peer_ip:
                            del peer_usernames[username]
            peer_list = discovery_instance.peer_list.copy()
            await asyncio.sleep(5)
        except Exception as e:
            logging.exception(f"Error in maintain_peer_list: {e}")
            await asyncio.sleep(5)
    logging.info("maintain_peer_list exited due to shutdown.")

async def send_message_to_peers(message, target_username=None):
    """Send a message to one or all connected peers."""
    if target_username:
        if target_username in peer_usernames:
            peer_ip = peer_usernames[target_username]
            if peer_ip in connections and connections[peer_ip].state == State.OPEN:
                encrypted_message = peer_public_keys[peer_ip].encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).hex()
                try:
                    await connections[peer_ip].send(
                        json.dumps({"type": "MESSAGE", "message": encrypted_message})
                    )
                    return True
                except Exception as e:
                    logging.error(f"Failed to send message to {target_username} ({peer_ip}): {e}")
                    return False
            else:
                logging.warning(f"No active connection to {target_username}")
                return False
        else:
            return False

    for peer_ip, websocket in list(connections.items()):
        if websocket.state == State.OPEN:
            try:
                peer_username = next(u for u, ip in peer_usernames.items() if ip == peer_ip)
                encrypted_msg = peer_public_keys[peer_ip].encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).hex()
                await websocket.send(
                    json.dumps({"type": "MESSAGE", "message": encrypted_msg})
                )
            except Exception as e:
                logging.error(f"Failed to send message to {peer_ip}: {e}")
    return True

async def receive_peer_messages(websocket, peer_ip):
    """Receive messages from a connected peer."""
    try:
        async for message in websocket:
            if shutdown_event.is_set():
                break
            try:
                data = json.loads(message)
                message_type = data.get("type")

                if message_type == "file_transfer_init":
                    transfer_id = data["transfer_id"]
                    relative_path = data["relative_path"]
                    file_size = data["filesize"]
                    expected_hash = data.get("file_hash")
                    peer_username = next(u for u, ip in peer_usernames.items() if ip == peer_ip)
                    await message_queue.put({
                        "type": "file_approval_request",
                        "transfer_id": transfer_id,
                        "peer_username": peer_username,
                        "relative_path": relative_path,
                        "file_size": file_size
                    })
                    approval_future = asyncio.Future()
                    pending_file_approvals[transfer_id] = approval_future
                    try:
                        approved = await asyncio.wait_for(approval_future, timeout=30.0)
                    except asyncio.TimeoutError:
                        approved = False
                    del pending_file_approvals[transfer_id]
                    await websocket.send(json.dumps({
                        "type": "file_transfer_ack",
                        "transfer_id": transfer_id,
                        "approved": approved
                    }))
                    if approved:
                        file_path = os.path.join("downloads", relative_path)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        transfer = FileTransfer(file_path, peer_ip, direction="receive")
                        transfer.transfer_id = transfer_id
                        transfer.total_size = file_size
                        transfer.expected_hash = expected_hash
                        transfer.hash_algo = hashlib.sha256() if expected_hash else None
                        transfer.state = TransferState.IN_PROGRESS
                        transfer.file_handle = await aiofiles.open(file_path, "wb")
                        active_transfers[transfer_id] = transfer
                        logging.info(f"Added transfer {transfer_id} to active_transfers for receiving {relative_path}")
                        await message_queue.put(f"{user_data['original_username']} receiving '{relative_path}' from {peer_username} (Transfer ID: {transfer_id})")
                    else:
                        await message_queue.put(f"{user_data['original_username']} denied file transfer for '{relative_path}' from {peer_username}")

                elif message_type == "file_transfer_ack":
                    transfer_id = data["transfer_id"]
                    approved = data["approved"]
                    if transfer_id in pending_file_approvals and not pending_file_approvals[transfer_id].done():
                        pending_file_approvals[transfer_id].set_result(approved)

                elif message_type == "file_chunk":
                    transfer_id = data["transfer_id"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.direction == "receive":
                        async with transfer.condition:
                            while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                                await transfer.condition.wait()
                            if shutdown_event.is_set():
                                await transfer.file_handle.close()
                                del active_transfers[transfer_id]
                                break
                        chunk = bytes.fromhex(data["chunk"])
                        await transfer.file_handle.write(chunk)
                        transfer.transferred_size += len(chunk)
                        if transfer.hash_algo:
                            transfer.hash_algo.update(chunk)
                        if transfer.transferred_size >= transfer.total_size:
                            await transfer.file_handle.close()
                            transfer.file_handle = None
                            if transfer.expected_hash:
                                calculated_hash = transfer.hash_algo.hexdigest()
                                if calculated_hash != transfer.expected_hash:
                                    os.remove(transfer.file_path)
                                    transfer.state = TransferState.FAILED
                                    await message_queue.put(f"{user_data['original_username']} file transfer failed: integrity check failed")
                                else:
                                    transfer.state = TransferState.COMPLETED
                                    await message_queue.put(f"{user_data['original_username']} file saved as: {transfer.file_path}")
                            else:
                                transfer.state = TransferState.COMPLETED
                                await message_queue.put(f"{user_data['original_username']} file saved as: {transfer.file_path}")

                elif message_type == "MESSAGE":
                    decrypted_message = user_data["private_key"].decrypt(
                        bytes.fromhex(data["message"]),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    ).decode()
                    peer_username = next(u for u, ip in peer_usernames.items() if ip == peer_ip)
                    await message_queue.put(f"{peer_username}: {decrypted_message}")

            except json.JSONDecodeError:
                peer_username = next(u for u, ip in peer_usernames.items() if ip == peer_ip)
                await message_queue.put(f"{peer_username}: {message}")
    except websockets.exceptions.ConnectionClosed:
        peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
        logging.info(f"{user_data['original_username']} connection closed with {peer_username} ({peer_ip})")
    finally:
        if peer_ip in connections:
            del connections[peer_ip]
            del peer_public_keys[peer_ip]
            for username, ip in list(peer_usernames.items()):
                if ip == peer_ip:
                    del peer_usernames[username]

async def handle_input(message):
    """Handle user input from the input area."""
    try:
        if message == "/exit":
            await message_queue.put("Shutting down application...")
            shutdown_event.set()
            app.exit()
            raise asyncio.CancelledError

        elif message == "/help":
            await message_queue.put("\nAvailable commands:\n/connect <username>    - Connect to a peer by username\n/disconnect <username> - Disconnect from a peer by username\n/msg <username> <message> - Send message to a peer by username\n/send <username> <file> - Send file to a peer by username\n/pause <transfer_id>   - Pause a file transfer\n/resume <transfer_id>  - Resume a file transfer\n/transfers             - List active transfers\n/list                  - Show available peers\n/changename <new_username> - Change your username\n/exit                  - Exit the application\n/help                  - Show this help")

        elif message == "/list":
            output = "\nAvailable peers:"
            own_ip = await get_own_ip()
            for ip, (username, _) in peer_list.items():
                if ip == own_ip:
                    output += f"\n- {username} ({ip}, Self)"
                else:
                    status = "Connected" if ip in connections else "Discovered"
                    output += f"\n- {username} ({ip}, {status})"
            await message_queue.put(output)

        elif message.startswith("/connect "):
            target_username = message[9:].strip()
            requesting_username = user_data["original_username"]
            peer_ip = next((ip for ip, (username, _) in peer_list.items() if username == target_username), None)
            if peer_ip:
                await message_queue.put(f"Connection request to {target_username} is pending approval...")
                websocket = await connect_to_peer(peer_ip, requesting_username, target_username)
                if websocket:
                    connections[peer_ip] = websocket
                    asyncio.create_task(receive_peer_messages(websocket, peer_ip))
                    await message_queue.put(f"Connected to {target_username}")
            else:
                await message_queue.put(f"No such peer: {target_username}")

        elif message.startswith("/disconnect "):
            target_username = message[12:].strip()
            await disconnect_from_peer(target_username)

        elif message.startswith("/msg "):
            parts = message[5:].split(" ", 1)
            if len(parts) < 2:
                await message_queue.put("Usage: /msg <username> <message>")
            else:
                target_username, msg_content = parts
                if target_username in peer_usernames:
                    await send_message_to_peers(msg_content, target_username)
                    await message_queue.put(f"{user_data['original_username']} → {target_username}: {msg_content}")
                else:
                    await message_queue.put(f"No such peer: {target_username}")

        elif message.startswith("/send "):
            parts = message[6:].split(" ", 1)
            if len(parts) < 2:
                await message_queue.put("Usage: /send <username> <file_path>")
            else:
                target_username, item_path = parts
                if target_username in peer_usernames:
                    peer_ip = peer_usernames[target_username]
                    if peer_ip in connections:
                        if os.path.isdir(item_path):
                            asyncio.create_task(send_folder(item_path, {peer_ip: connections[peer_ip]}))
                            await message_queue.put(f"Started sending folder {item_path} to {target_username}")
                        elif os.path.isfile(item_path):
                            asyncio.create_task(send_file(item_path, {peer_ip: connections[peer_ip]}))
                            await message_queue.put(f"Started sending file {item_path} to {target_username}")
                        else:
                            await message_queue.put(f"Path does not exist or is not a file/folder: {item_path}")
                    else:
                        await message_queue.put(f"Not connected to {target_username}")
                else:
                    await message_queue.put(f"No such peer: {target_username}")

        elif message.startswith("/pause "):
            transfer_id = message[7:].strip()
            if transfer_id in active_transfers:
                await active_transfers[transfer_id].pause()
                await message_queue.put(f"Paused transfer {transfer_id}")
            else:
                await message_queue.put(f"No such transfer: {transfer_id}")

        elif message.startswith("/resume "):
            transfer_id = message[8:].strip()
            if transfer_id in active_transfers:
                await active_transfers[transfer_id].resume()
                await message_queue.put(f"Resumed transfer {transfer_id}")
            else:
                await message_queue.put(f"No such transfer: {transfer_id}")

        elif message == "/transfers":
            if not active_transfers:
                await message_queue.put("\nNo ongoing file transfers.")
            else:
                output = "\nActive transfers:"
                for transfer_id, transfer in active_transfers.items():
                    direction = "Sending" if transfer.direction == "send" else "Receiving"
                    progress = (transfer.transferred_size / transfer.total_size * 100) if transfer.total_size > 0 else 0
                    peer_ip = transfer.peer_ip
                    peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "Unknown")
                    output += f"\n- {transfer_id}: {direction} '{transfer.file_path}' to/from {peer_username} ({progress:.2f}%, {transfer.state.value})"
                await message_queue.put(output)

        elif message.startswith("/changename "):
            new_username = message[12:].strip()
            if not new_username:
                await message_queue.put("Usage: /changename <new_username>")
            else:
                config_dir = get_config_directory()
                config_file = os.path.join(config_dir, "user_config.json")
                if os.path.exists(config_file):
                    os.remove(config_file)
                await create_new_user_config(config_file, new_username)
                input_area.prompt = f"{new_username} > "  # Update prompt
                await message_queue.put(f"Username changed to {new_username}")
                await discovery.send_immediate_broadcast()

        elif message.lower() in ("yes", "no") and pending_approvals:
            peer_ip, future = next(iter(pending_approvals.items()))
            if not future.done():
                future.set_result(message.lower() == "yes")

        elif message.lower() in ("yes", "no") and pending_file_approvals:
            transfer_id, future = next(iter(pending_file_approvals.items()))
            if not future.done():
                future.set_result(message.lower() == "yes")

        elif not message.startswith("/"):
            if connections:
                await send_message_to_peers(message)
                await message_queue.put(f"{user_data['original_username']} (to all): {message}")
            else:
                await message_queue.put("No peers connected.")

    except asyncio.CancelledError:
        raise
    except Exception as e:
        logging.exception(f"Error in handle_input: {e}")
        await message_queue.put(f"Error: {e}")

async def user_input(discovery):
    """Handle user input with a TUI."""
    global app
    await asyncio.sleep(1)

    async def display_messages():
        while not shutdown_event.is_set():
            try:
                item = await message_queue.get()
                if isinstance(item, dict) and item.get("type") == "file_approval_request":
                    transfer_id = item["transfer_id"]
                    peer_username = item["peer_username"]
                    relative_path = item["relative_path"]
                    file_size = item["file_size"]
                    output_area.text += f"\nFile transfer request from {peer_username}: {relative_path} ({file_size} bytes). Accept? (yes/no)"
                elif isinstance(item, dict) and item.get("type") == "approval_request":
                    peer_ip = item["peer_ip"]
                    requesting_username = item["requesting_username"]
                    output_area.text += f"\nConnection request from {requesting_username} ({peer_ip}). Accept? (yes/no)"
                else:
                    output_area.text += f"\n{item}"
                app.invalidate()  # Refresh the display
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.exception(f"Error displaying message: {e}")
                await asyncio.sleep(1)

    # Start the display task
    display_task = asyncio.create_task(display_messages())
    
    try:
        await app.run_async()
    except asyncio.CancelledError:
        display_task.cancel()
        raise
    finally:
        display_task.cancel()