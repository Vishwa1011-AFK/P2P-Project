import asyncio
import logging
import websockets
import os
import json
import hashlib
import aiofiles
import uuid
from aioconsole import ainput
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from networking.utils import get_own_ip
from networking.shared_state import (
    active_transfers, message_queue, connections, user_data, peer_public_keys,
    peer_usernames, peer_device_ids, shutdown_event
)
from networking.file_transfer import send_file, FileTransfer, TransferState
from websockets.connection import State
from appdirs import user_config_dir

connection_denials = {}
pending_approvals = {}


def get_peer_original_username(peer_ip):
    for uname, uip in peer_usernames.items():
        if uip == peer_ip:
            return uname
    return None

def get_peer_display_name(peer_ip):
    username = get_peer_original_username(peer_ip) or "Unknown"
    device_id = peer_device_ids.get(peer_ip)
    device_suffix = f"({device_id[:8]})" if device_id else "(?)"

    if username == "Unknown":
        return f"Unknown@{peer_ip}"

    username_count = 0
    for ip in connections.keys():
        if get_peer_original_username(ip) == username:
            username_count += 1

    if username_count > 1:
        return f"{username}{device_suffix}"
    else:
        return username


def get_own_display_name():
    username = user_data.get("original_username", "User")
    device_id = user_data.get("device_id")
    device_suffix = f"({device_id[:8]})" if device_id else ""
    return f"{username}{device_suffix}"


async def resolve_peer_target(target_identifier):
    matches = []
    possible_original_username_match = False

    for peer_ip in list(connections.keys()):
        display_name = get_peer_display_name(peer_ip)
        original_username = get_peer_original_username(peer_ip)

        if target_identifier == display_name:
            matches.append(peer_ip)
            if '(' in display_name:
                 return peer_ip, "found"
        elif target_identifier == original_username:
             matches.append(peer_ip)
             possible_original_username_match = True

    unique_matches = list(set(matches))

    if len(unique_matches) == 0:
        return None, "not_found"
    elif len(unique_matches) == 1:
        return unique_matches[0], "found"
    else:
        if possible_original_username_match:
             is_target_just_username = not ('(' in target_identifier and ')' in target_identifier)

             if is_target_just_username:
                 first_match_username = get_peer_original_username(unique_matches[0])
                 all_share_username = True
                 for ip in unique_matches[1:]:
                     if get_peer_original_username(ip) != first_match_username:
                         all_share_username = False
                         break

                 if all_share_username and target_identifier == first_match_username:
                     ambiguous_names = sorted([get_peer_display_name(ip) for ip in unique_matches])
                     return ambiguous_names, "ambiguous"

        ambiguous_names = sorted([get_peer_display_name(ip) for ip in unique_matches])
        return ambiguous_names, "ambiguous"


def get_config_directory():
    appname = "P2PChat"
    appauthor = False
    return user_config_dir(appname, appauthor)


async def initialize_user_config():
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
            print(f"Welcome back, {get_own_display_name()}!")
        except Exception as e:
            print(f"Error loading config, creating new one: {e}")
            await create_new_user_config(config_file_path)
    else:
        await create_new_user_config(config_file_path)
        print(f"Welcome, {get_own_display_name()}!")


async def create_new_user_config(config_file_path, username=None):
    if username is None:
        original_username = await ainput("Enter your desired username: ")
    else:
        original_username = username

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    device_id = str(uuid.uuid4())

    user_data.clear()
    user_data.update({
        "original_username": original_username,
        "public_key": public_key,
        "private_key": private_key,
        "device_id": device_id
    })

    data_to_save = {
        "original_username": original_username,
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
            json.dump(data_to_save, f, indent=4)
    except IOError as e:
        logging.error(f"Failed to save config file {config_file_path}: {e}")
        print(f"Error: Could not save configuration file.")


async def connect_to_peer(peer_ip, requesting_username_ignored, target_username, port=8765):
    own_original_username = user_data["original_username"]
    own_device_id = user_data["device_id"]
    public_key_pem = user_data["public_key"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    if peer_ip in connections:
        print(f"Already connected to {get_peer_display_name(peer_ip)}")
        return connections[peer_ip]

    uri = f"ws://{peer_ip}:{port}"
    websocket = None
    try:
        websocket = await websockets.connect(uri, ping_interval=None, max_size=10*1024*1024)
        own_ip = await get_own_ip()
        await websocket.send(f"INIT {own_ip}")
        response = await websocket.recv()

        if response.startswith("INIT_ACK"):
            await websocket.send(json.dumps({
                "type": "CONNECTION_REQUEST",
                "requesting_username": own_original_username,
                "target_username": target_username,
                "key": public_key_pem,
                "device_id": own_device_id
            }))

            approval_response = await websocket.recv()
            approval_data = json.loads(approval_response)

            if approval_data["type"] == "CONNECTION_RESPONSE" and approval_data["approved"]:
                await websocket.send(json.dumps({
                    "type": "IDENTITY",
                    "username": own_original_username,
                    "device_id": own_device_id,
                    "key": public_key_pem
                }))

                identity_message = await websocket.recv()
                identity_data = json.loads(identity_message)

                if identity_data["type"] == "IDENTITY":
                    peer_recv_username = identity_data["username"]
                    peer_recv_device_id = identity_data["device_id"]
                    peer_recv_key_pem = identity_data["key"]

                    peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_recv_key_pem.encode())
                    peer_usernames[peer_recv_username] = peer_ip
                    peer_device_ids[peer_ip] = peer_recv_device_id
                    connections[peer_ip] = websocket

                    display_name = get_peer_display_name(peer_ip)
                    logging.info(f"{get_own_display_name()} connected to {display_name} ({peer_ip})")
                    await message_queue.put(f"Successfully connected to {display_name}")
                    return websocket
                else:
                    await websocket.close()
                    print(f"Connection to {target_username} failed: Invalid identity response after approval.")
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
    except OSError as e:
         print(f"Connection to {target_username} failed: Network error ({e})")
         if websocket and websocket.state != State.CLOSED: await websocket.close()
         return None
    except Exception as e:
        logging.exception(f"Failed to connect to {peer_ip}: {e}")
        print(f"Connection to {target_username} failed: {str(e)}")
        if websocket and websocket.state != State.CLOSED:
            await websocket.close()
        return None


async def disconnect_from_peer(target_identifier):
    result, status = await resolve_peer_target(target_identifier)

    if status == "not_found":
        print(f"Error: No connected peer found matching: {target_identifier}")
        if target_identifier in peer_usernames:
             ip_maybe = peer_usernames[target_identifier]
             if ip_maybe not in connections:
                  print(f"Cleaning stale mapping for disconnected user '{target_identifier}'.")
                  del peer_usernames[target_identifier]
                  if ip_maybe in peer_public_keys: del peer_public_keys[ip_maybe]
                  if ip_maybe in peer_device_ids: del peer_device_ids[ip_maybe]
    elif status == "ambiguous":
        print(f"Error: Ambiguous target '{target_identifier}'. Matches:")
        for name in result: print(f"  - {name}")
        print("Please use the full display name including the ID suffix.")
    elif status == "found":
        peer_ip_to_disconnect = result
        websocket = connections.get(peer_ip_to_disconnect)
        if not websocket:
            print(f"Error: Peer {get_peer_display_name(peer_ip_to_disconnect)} found but connection missing (internal state issue).")
            if peer_ip_to_disconnect in connections: del connections[peer_ip_to_disconnect]
            if peer_ip_to_disconnect in peer_public_keys: del peer_public_keys[peer_ip_to_disconnect]
            if peer_ip_to_disconnect in peer_device_ids: del peer_device_ids[peer_ip_to_disconnect]
            original_username = get_peer_original_username(peer_ip_to_disconnect)
            if original_username and original_username in peer_usernames and peer_usernames[original_username] == peer_ip_to_disconnect:
                 del peer_usernames[original_username]
            return

        display_name_disconnecting = get_peer_display_name(peer_ip_to_disconnect)
        original_username = get_peer_original_username(peer_ip_to_disconnect)
        try:
            del connections[peer_ip_to_disconnect]
            if peer_ip_to_disconnect in peer_public_keys: del peer_public_keys[peer_ip_to_disconnect]
            if peer_ip_to_disconnect in peer_device_ids: del peer_device_ids[peer_ip_to_disconnect]
            if original_username and original_username in peer_usernames and peer_usernames[original_username] == peer_ip_to_disconnect:
                del peer_usernames[original_username]

            await websocket.close()
            print(f"Disconnected from {display_name_disconnecting}")
        except Exception as e:
            logging.error(f"Error disconnecting from {display_name_disconnecting}: {e}")
            print(f"Failed to cleanly disconnect from {display_name_disconnecting}: {e}")
            if peer_ip_to_disconnect in connections: del connections[peer_ip_to_disconnect]
            if peer_ip_to_disconnect in peer_public_keys: del peer_public_keys[peer_ip_to_disconnect]
            if peer_ip_to_disconnect in peer_device_ids: del peer_device_ids[peer_ip_to_disconnect]
            if original_username and original_username in peer_usernames and peer_usernames[original_username] == peer_ip_to_disconnect:
                del peer_usernames[original_username]


async def handle_incoming_connection(websocket, peer_ip):
    try:
        message = await websocket.recv()
        if shutdown_event.is_set():
            await websocket.close(code=1001, reason="Server shutting down")
            return False

        if message.startswith("INIT "):
            _, sender_ip = message.split(" ", 1)
            if peer_ip in connections:
                 logging.warning(f"Duplicate connection attempt from {peer_ip}. Closing new one.")
                 await websocket.close(code=1008, reason="Already connected")
                 return False

            await websocket.send("INIT_ACK")
            request_message = await websocket.recv()
            request_data = json.loads(request_message)

            if request_data["type"] == "CONNECTION_REQUEST":
                requesting_username = request_data["requesting_username"]
                requesting_device_id = request_data["device_id"]
                target_username = request_data["target_username"]
                peer_key_pem = request_data["key"]

                requesting_display_name = f"{requesting_username}({requesting_device_id[:8]})"

                if target_username != user_data["original_username"]:
                    logging.warning(f"Connection request from {requesting_display_name} for wrong target '{target_username}'. Denying.")
                    await websocket.send(json.dumps({ "type": "CONNECTION_RESPONSE", "approved": False, "reason": "Incorrect target username" }))
                    await websocket.close()
                    return False

                denial_count = connection_denials.get(target_username, {}).get(requesting_username, 0)
                if denial_count >= 3:
                    logging.warning(f"Connection request from blocked user {requesting_display_name}. Denying.")
                    await websocket.send(json.dumps({ "type": "CONNECTION_RESPONSE", "approved": False, "reason": "Connection blocked" }))
                    await websocket.close()
                    return False

                approval_future = asyncio.Future()
                pending_approvals[peer_ip] = approval_future
                await message_queue.put({
                    "type": "approval_request",
                    "peer_ip": peer_ip,
                    "requesting_username": requesting_display_name
                })

                approved = False
                try:
                    approved = await asyncio.wait_for(approval_future, timeout=30.0)
                except asyncio.TimeoutError:
                    logging.info(f"Approval for {requesting_display_name} ({peer_ip}) timed out.")
                    await message_queue.put(f"\nApproval request for {requesting_display_name} timed out.")
                finally:
                    if peer_ip in pending_approvals: del pending_approvals[peer_ip]

                if not approved:
                    if target_username not in connection_denials: connection_denials[target_username] = {}
                    current_denials = connection_denials[target_username]
                    current_denials[requesting_username] = current_denials.get(requesting_username, 0) + 1
                    await message_queue.put(f"Denied connection from {requesting_display_name} ({current_denials[requesting_username]}/3)")
                    if current_denials[requesting_username] >= 3:
                        await message_queue.put(f"{requesting_display_name} has been blocked for this session.")

                await websocket.send(json.dumps({ "type": "CONNECTION_RESPONSE", "approved": approved }))

                if not approved:
                    await websocket.close()
                    return False

                own_public_key_pem = user_data["public_key"].public_bytes( encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo ).decode()
                await websocket.send(json.dumps({
                    "type": "IDENTITY",
                    "username": user_data["original_username"],
                    "device_id": user_data["device_id"],
                    "key": own_public_key_pem
                }))

                identity_message = await websocket.recv()
                identity_data = json.loads(identity_message)
                if identity_data["type"] == "IDENTITY":
                    peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_key_pem.encode())
                    peer_usernames[requesting_username] = peer_ip
                    peer_device_ids[peer_ip] = requesting_device_id
                    connections[peer_ip] = websocket

                    display_name = get_peer_display_name(peer_ip)
                    logging.info(f"{get_own_display_name()} accepted connection from {display_name} ({peer_ip})")
                    await message_queue.put(f"Accepted connection from {display_name}")
                    return True
                else:
                    logging.error(f"Invalid identity message from {peer_ip} after approval. Closing.")
                    await websocket.close()
                    if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
                    if peer_ip in peer_device_ids: del peer_device_ids[peer_ip]
                    if requesting_username in peer_usernames and peer_usernames[requesting_username] == peer_ip:
                        del peer_usernames[requesting_username]
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
        if peer_ip in pending_approvals: del pending_approvals[peer_ip]
        return False
    except Exception as e:
        logging.exception(f"Error in connection handshake with {peer_ip}: {e}")
        if websocket and websocket.state == State.OPEN:
            await websocket.close(code=1011, reason="Internal server error")
        if peer_ip in pending_approvals: del pending_approvals[peer_ip]
        return False


async def maintain_peer_list(discovery_instance):
    while not shutdown_event.is_set():
        try:
            for peer_ip, ws in list(connections.items()):
                if shutdown_event.is_set(): break
                try:
                    await asyncio.wait_for(ws.ping(), timeout=10.0)
                except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                    lost_display_name = get_peer_display_name(peer_ip)
                    logging.warning(f"Connection lost with peer {lost_display_name} ({peer_ip}). Cleaning up.")

                    lost_original_username = get_peer_original_username(peer_ip)

                    if peer_ip in connections: del connections[peer_ip]
                    if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
                    if peer_ip in peer_device_ids: del peer_device_ids[peer_ip]
                    if lost_original_username and lost_original_username in peer_usernames and peer_usernames[lost_original_username] == peer_ip:
                         del peer_usernames[lost_original_username]

                    await message_queue.put(f"Disconnected from {lost_display_name} (connection lost)")

                    if ws.state != State.CLOSED:
                        await ws.close()

            await asyncio.sleep(15)
        except asyncio.CancelledError:
            logging.info("maintain_peer_list task cancelled.")
            break
        except Exception as e:
            logging.exception(f"Error in maintain_peer_list: {e}")
            await asyncio.sleep(15)
    logging.info("maintain_peer_list exited.")


async def send_message_to_peers(message, peer_ip=None):
    if not isinstance(message, str) or not message:
        logging.warning("Attempted to send empty or non-string message.")
        return False

    targets = []

    if peer_ip:
        ws = connections.get(peer_ip)
        key = peer_public_keys.get(peer_ip)
        disp_name = get_peer_display_name(peer_ip)
        if ws and ws.state == State.OPEN and key:
            targets.append((peer_ip, ws, key, disp_name))
        else:
            logging.error(f"send_message_to_peers called with invalid peer_ip/state: {peer_ip}")
            await message_queue.put(f"Error: Cannot send message, connection state invalid for {disp_name}.")
            return False
    else:
        for ip, ws in list(connections.items()):
             if ws.state == State.OPEN:
                 key = peer_public_keys.get(ip)
                 disp_name = get_peer_display_name(ip)
                 if key:
                     targets.append((ip, ws, key, disp_name))
                 else:
                     logging.warning(f"Missing public key for {disp_name} ({ip}). Cannot encrypt message.")

    if not targets:
        if not peer_ip:
             await message_queue.put("No peers connected to send message to.")
        return False

    sent_to_at_least_one = False
    for target_ip, websocket, peer_key, display_name in targets:
        try:
            encrypted_message = peer_key.encrypt( message.encode(), padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None ) ).hex()
            payload = json.dumps({"type": "MESSAGE", "message": encrypted_message})
            await websocket.send(payload)
            sent_to_at_least_one = True
        except Exception as e:
            logging.error(f"Failed to send message to {display_name} ({target_ip}): {e}")
            await message_queue.put(f"Error sending message to {display_name}: {e}")

    return sent_to_at_least_one


async def receive_peer_messages(websocket, peer_ip):
    peer_display_name = f"Peer@{peer_ip}"
    try:
        peer_display_name = get_peer_display_name(peer_ip)

        async for message in websocket:
            if shutdown_event.is_set():
                break
            try:
                data = json.loads(message)
                message_type = data.get("type")

                peer_display_name = get_peer_display_name(peer_ip)

                if message_type == "file_transfer_init":
                    transfer_id = data["transfer_id"]
                    file_name = data["filename"]
                    file_size = data["filesize"]
                    expected_hash = data.get("file_hash")
                    safe_filename_base = os.path.basename(file_name)
                    download_dir = "downloads"
                    os.makedirs(download_dir, exist_ok=True)
                    file_path = os.path.join(download_dir, safe_filename_base)

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
                    await message_queue.put(f"Receiving '{os.path.basename(file_path)}' from {peer_display_name} (ID: {transfer_id[:8]}...)")


                elif message_type == "file_chunk":
                    transfer_id = data["transfer_id"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.direction == "receive":
                        async with transfer.condition:
                            while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                                await transfer.condition.wait()
                            if shutdown_event.is_set():
                                if transfer.file_handle: await transfer.file_handle.close()
                                if transfer_id in active_transfers: del active_transfers[transfer_id]
                                break

                        if transfer.state != TransferState.IN_PROGRESS:
                            continue

                        try:
                            chunk = bytes.fromhex(data["chunk"])

                            await transfer.file_handle.write(chunk)
                            transfer.transferred_size += len(chunk)
                            if transfer.hash_algo:
                                transfer.hash_algo.update(chunk)

                            if transfer.transferred_size >= transfer.total_size:
                                await transfer.file_handle.close()
                                transfer.file_handle = None
                                final_message = ""
                                if transfer.expected_hash:
                                    calculated_hash = transfer.hash_algo.hexdigest()
                                    if calculated_hash == transfer.expected_hash:
                                        transfer.state = TransferState.COMPLETED
                                        final_message = f"'{os.path.basename(transfer.file_path)}' received successfully from {peer_display_name}."
                                    else:
                                        transfer.state = TransferState.FAILED
                                        final_message = f"File integrity check FAILED for '{os.path.basename(transfer.file_path)}' from {peer_display_name}. File deleted."
                                        logging.error(f"Hash mismatch for {transfer_id}. Expected {transfer.expected_hash}, got {calculated_hash}")
                                        try: os.remove(transfer.file_path)
                                        except OSError as rm_err: logging.error(f"Could not remove failed transfer file {transfer.file_path}: {rm_err}")
                                else:
                                    transfer.state = TransferState.COMPLETED
                                    final_message = f"'{os.path.basename(transfer.file_path)}' received from {peer_display_name} (no integrity check)."

                                await message_queue.put(final_message)

                        except Exception as chunk_err:
                             logging.exception(f"Error processing chunk for transfer {transfer_id}: {chunk_err}")
                             await message_queue.put(f"Error receiving file chunk from {peer_display_name}. Transfer failed.")
                             transfer.state = TransferState.FAILED
                             if transfer.file_handle: await transfer.file_handle.close()


                elif message_type == "MESSAGE":
                    try:
                        decrypted_message = user_data["private_key"].decrypt( bytes.fromhex(data["message"]), padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None ) ).decode()
                        await message_queue.put(f"{peer_display_name}: {decrypted_message}")
                    except Exception as decrypt_err:
                        logging.error(f"Failed to decrypt message from {peer_display_name} ({peer_ip}): {decrypt_err}")
                        await message_queue.put(f"[Failed to decrypt message from {peer_display_name}]")

                elif message_type == "TRANSFER_PAUSE":
                    transfer_id = data.get("transfer_id")
                    transfer = active_transfers.get(transfer_id)
                    if transfer:
                        if transfer.peer_ip == peer_ip:
                            if transfer.state == TransferState.IN_PROGRESS:
                                await transfer.pause()
                                await message_queue.put(f"Peer {peer_display_name} paused transfer {transfer_id[:8]}")
                            elif transfer.state != TransferState.PAUSED:
                                logging.warning(f"Received PAUSE for transfer {transfer_id} from {peer_display_name}, but local state is {transfer.state.value}")
                        else: logging.warning(f"Received PAUSE for transfer {transfer_id} from {peer_display_name}, but transfer belongs to {transfer.peer_ip}")
                    else: logging.warning(f"Received PAUSE for unknown transfer {transfer_id} from {peer_display_name}")

                elif message_type == "TRANSFER_RESUME":
                    transfer_id = data.get("transfer_id")
                    transfer = active_transfers.get(transfer_id)
                    if transfer:
                        if transfer.peer_ip == peer_ip:
                            if transfer.state == TransferState.PAUSED:
                                await transfer.resume()
                                await message_queue.put(f"Peer {peer_display_name} resumed transfer {transfer_id[:8]}")
                            elif transfer.state != TransferState.IN_PROGRESS:
                                logging.warning(f"Received RESUME for transfer {transfer_id} from {peer_display_name}, but local state is {transfer.state.value}")
                        else: logging.warning(f"Received RESUME for transfer {transfer_id} from {peer_display_name}, but transfer belongs to {transfer.peer_ip}")
                    else: logging.warning(f"Received RESUME for unknown transfer {transfer_id} from {peer_display_name}")

            except json.JSONDecodeError:
                logging.warning(f"Received invalid JSON from {peer_display_name} ({peer_ip}): {message[:100]}")
                await message_queue.put(f"[{peer_display_name} sent invalid data]")
            except Exception as proc_err:
                logging.exception(f"Error processing message from {peer_display_name} ({peer_ip}): {proc_err}")
                await message_queue.put(f"[Error processing message from {peer_display_name}]")

    except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK) as closed_err:
        logging.info(f"Connection with {peer_display_name} ({peer_ip}) closed: {closed_err}")
    except Exception as e:
        logging.exception(f"Unexpected error receiving from {peer_display_name} ({peer_ip}): {e}")
    finally:
        lost_display_name = get_peer_display_name(peer_ip)
        logging.info(f"Cleaning up connection state for {lost_display_name} ({peer_ip})")
        lost_original_username = get_peer_original_username(peer_ip)
        if peer_ip in connections: del connections[peer_ip]
        if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
        if peer_ip in peer_device_ids: del peer_device_ids[peer_ip]
        if lost_original_username and lost_original_username in peer_usernames and peer_usernames[lost_original_username] == peer_ip:
             del peer_usernames[lost_original_username]

        if not shutdown_event.is_set():
            await message_queue.put(f"Disconnected from {lost_display_name}")


async def user_input(discovery):
    await asyncio.sleep(1)
    my_display_name = get_own_display_name()

    while not shutdown_event.is_set():
        try:
            message = await ainput(f"{my_display_name} > ")
            message = message.strip()
            if not message: continue

            if message == "/exit": break
            if message == "/help":
                 print("\nAvailable commands:")
                 print("  /connect <username>     - Connect to a discovered peer by username")
                 print("  /disconnect <disp/user> - Disconnect from a connected peer")
                 print("  /msg <disp/user> <text> - Send private message to a connected peer")
                 print("  /send <disp/user> <path>- Send file to a connected peer")
                 print("  /pause <transfer_id>    - Pause an active file transfer (by ID prefix)")
                 print("  /resume <transfer_id>   - Resume a paused file transfer (by ID prefix)")
                 print("  /transfers              - List active file transfers")
                 print("  /list                   - Show discovered and connected peers")
                 print("  /changename <new_name>  - Change your username (persists)")
                 print("  /exit                   - Exit the application")
                 print("  /help                   - Show this help message")
                 print("  <message>               - Send message to all connected peers")
                 continue

            if message == "/list":
                print("\nAvailable peers:")
                own_ip = await get_own_ip()
                known_ips = set(connections.keys()) | set(discovery.peer_list.keys())

                if not known_ips:
                    print("  No peers discovered or connected.")
                else:
                    print(f"- {get_own_display_name()} ({own_ip}, Self)")
                    for ip in sorted(list(known_ips - {own_ip})): # Sort IPs for consistent order
                        disc_info = discovery.peer_list.get(ip)
                        is_connected = ip in connections
                        status = "Connected" if is_connected else "Discovered"
                        display_name = get_peer_display_name(ip)
                        if not is_connected and '(' not in display_name: # Only discovered, use original name from discovery
                             if disc_info: display_name = disc_info[0]
                             else: status="Stale?" # Should be cleaned up by discovery

                        print(f"- {display_name} ({ip}, {status})")
                continue

            if message == "/transfers":
                if not active_transfers: print("\nNo active transfers."); continue
                print("\nActive transfers:")
                for transfer_id, transfer in list(active_transfers.items()):
                     direction = "Sending" if transfer.direction == "send" else "Receiving"
                     progress = 0.0; total_size_mb = 0.0; transferred_mb = 0.0
                     if transfer.total_size > 0:
                          progress = (transfer.transferred_size / transfer.total_size * 100)
                          total_size_mb = transfer.total_size / (1024 * 1024)
                          transferred_mb = transfer.transferred_size / (1024 * 1024)
                     peer_display = get_peer_display_name(transfer.peer_ip)
                     print(f"- ID: {transfer_id[:8]}... State: {transfer.state.value}")
                     print(f"    {direction} '{os.path.basename(transfer.file_path)}' {'to' if direction == 'Sending' else 'from'} {peer_display}")
                     print(f"    Progress: {progress:.1f}% ({transferred_mb:.2f}/{total_size_mb:.2f} MB)")
                continue

            if message.startswith("/changename "):
                 new_username = message[len("/changename "):].strip()
                 if not new_username: print("Usage: /changename <new_username>"); continue
                 if new_username == user_data['original_username']: print("Username unchanged."); continue

                 print(f"Changing username to '{new_username}'...")
                 config_dir = get_config_directory()
                 config_file_path = os.path.join(config_dir, "user_config.json")

                 old_username = user_data['original_username']
                 user_data['original_username'] = new_username
                 my_display_name = get_own_display_name()

                 data_to_save = {}
                 for key, value in user_data.items():
                    if key == "public_key" and isinstance(value, RSAPublicKey):
                         data_to_save[key] = value.public_bytes( encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo ).decode()
                    elif key == "private_key" and isinstance(value, RSAPrivateKey):
                         data_to_save[key] = value.private_bytes( encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption() ).decode()
                    else: data_to_save[key] = value

                 try:
                     with open(config_file_path, "w") as f: json.dump(data_to_save, f, indent=4)
                     print(f"Username changed to '{new_username}' and saved.")
                     await discovery.send_immediate_broadcast()
                 except Exception as e:
                     logging.exception(f"Failed to save config during username change: {e}")
                     print(f"Error saving config. Reverting username change.")
                     user_data['original_username'] = old_username
                     my_display_name = get_own_display_name()
                 continue

            if message.lower() in ("yes", "y", "no", "n") and pending_approvals:
                 peer_ip_to_approve = next(iter(pending_approvals))
                 future = pending_approvals.pop(peer_ip_to_approve)
                 if not future.done():
                      is_approved = message.lower() in ("yes", "y")
                      future.set_result(is_approved)
                 else: print("Approval already processed."); continue


            if message.startswith("/connect "):
                target_username = message[len("/connect "):].strip()
                if not target_username: print("Usage: /connect <username>"); continue
                if target_username == user_data['original_username']: print("Cannot connect to yourself."); continue

                peer_ip = None
                for ip, (username, _) in discovery.peer_list.items():
                    if username == target_username:
                        peer_ip = ip
                        break

                if peer_ip:
                    if peer_ip in connections:
                        print(f"Already connected to {get_peer_display_name(peer_ip)}")
                    else:
                        print(f"Attempting connection to {target_username} ({peer_ip})...")
                        asyncio.create_task(connect_and_handle(peer_ip, user_data["original_username"], target_username))
                else:
                    print(f"Peer '{target_username}' not found in discovered list.")
                continue

            if message.startswith("/disconnect "):
                target_identifier = message[len("/disconnect "):].strip()
                if not target_identifier: print("Usage: /disconnect <display_name_or_username>"); continue
                await disconnect_from_peer(target_identifier)
                continue

            if message.startswith("/msg "):
                parts = message[len("/msg "):].split(" ", 1)
                if len(parts) < 2: print("Usage: /msg <display_name_or_username> <message>"); continue
                target_identifier, msg_content = parts

                result, status = await resolve_peer_target(target_identifier)

                if status == "not_found":
                    print(f"Error: No connected peer found matching: {target_identifier}.")
                elif status == "ambiguous":
                    print(f"Error: Ambiguous target '{target_identifier}'. Matches:")
                    for name in result: print(f"  - {name}")
                    print("Please use the full display name including the ID suffix.")
                elif status == "found":
                    peer_ip = result
                    if await send_message_to_peers(msg_content, peer_ip=peer_ip):
                         resolved_display_name = get_peer_display_name(peer_ip)
                         await message_queue.put(f"You -> {resolved_display_name}: {msg_content}")
                continue

            if message.startswith("/send "):
                parts = message[len("/send "):].split(" ", 1)
                if len(parts) < 2: print("Usage: /send <display_name_or_username> <file_path>"); continue
                target_identifier, file_path = parts

                if not os.path.exists(file_path): print(f"Error: File not found: {file_path}"); continue
                if not os.path.isfile(file_path): print(f"Error: Not a file: {file_path}"); continue

                result, status = await resolve_peer_target(target_identifier)

                if status == "not_found":
                    print(f"Error: No connected peer found matching: {target_identifier}.")
                elif status == "ambiguous":
                    print(f"Error: Ambiguous target '{target_identifier}'. Matches:")
                    for name in result: print(f"  - {name}")
                    print("Please use the full display name including the ID suffix.")
                elif status == "found":
                    peer_ip = result
                    ws = connections.get(peer_ip)
                    if ws and ws.state == State.OPEN:
                         resolved_display_name = get_peer_display_name(peer_ip)
                         print(f"Starting send '{os.path.basename(file_path)}' to {resolved_display_name}...")
                         asyncio.create_task(send_file(file_path, {peer_ip: ws}))
                    else:
                         print(f"Error: Connection state invalid for resolved peer {get_peer_display_name(peer_ip)}.")
                continue

            if message.startswith(("/pause ", "/resume ")):
                 command, potential_id = message.split(" ", 1)
                 transfer_id_prefix = potential_id.strip()
                 if not transfer_id_prefix: print(f"Usage: {command} <transfer_id_prefix>"); continue

                 matched_transfer = None; match_count = 0
                 for tid, transfer in active_transfers.items():
                     if tid.startswith(transfer_id_prefix): matched_transfer = transfer; match_count += 1
                 if match_count == 0: print(f"No transfer matching '{transfer_id_prefix}'"); continue
                 if match_count > 1: print(f"Multiple transfers match '{transfer_id_prefix}'. Be more specific."); continue

                 action = command.strip('/')
                 peer_ip = matched_transfer.peer_ip; transfer_id = matched_transfer.transfer_id
                 if peer_ip not in connections or connections[peer_ip].state != State.OPEN:
                     print(f"Cannot {action} transfer {transfer_id[:8]}: Peer offline."); continue

                 websocket = connections[peer_ip]; notification_payload = {"transfer_id": transfer_id}
                 local_action_func = None; target_state_msg = ""
                 if action == "pause":
                     if matched_transfer.state == TransferState.IN_PROGRESS:
                         notification_payload["type"] = "TRANSFER_PAUSE"; local_action_func = matched_transfer.pause; target_state_msg = "paused"
                     elif matched_transfer.state == TransferState.PAUSED: print(f"Already paused.")
                     else: print(f"Cannot pause (state: {matched_transfer.state.value})")
                 elif action == "resume":
                     if matched_transfer.state == TransferState.PAUSED:
                         notification_payload["type"] = "TRANSFER_RESUME"; local_action_func = matched_transfer.resume; target_state_msg = "resumed"
                     elif matched_transfer.state == TransferState.IN_PROGRESS: print(f"Already in progress.")
                     else: print(f"Cannot resume (state: {matched_transfer.state.value})")

                 if local_action_func:
                     try:
                         await websocket.send(json.dumps(notification_payload))
                         await local_action_func()
                         print(f"Transfer {transfer_id[:8]} {target_state_msg}.")
                     except Exception as e: print(f"Error sending {action} notification: {e}")
                 continue


            else:
                if connections:
                    if await send_message_to_peers(message):
                         await message_queue.put(f"You (to all): {message}")
                else: print("No peers connected."); continue

        except asyncio.CancelledError: break
        except Exception as e:
            logging.exception(f"Error in user_input loop: {e}")
            print(f"\nAn error occurred: {e}"); await asyncio.sleep(1)

    logging.info("user_input task finished.")


async def display_messages():
    while not shutdown_event.is_set():
        try:
            item = await message_queue.get()
            if isinstance(item, dict) and item.get("type") == "approval_request":
                requesting_display_name = item["requesting_username"]
                print(f"\n\n>> Connection request from {requesting_display_name}. Approve? (yes/no) <<")
            elif isinstance(item, str):
                print(f"\n{item}")
            else:
                 logging.warning(f"Unknown item type in message queue: {type(item)}")
            message_queue.task_done()
        except asyncio.CancelledError: break
        except Exception as e:
            logging.exception(f"Error displaying message: {e}"); await asyncio.sleep(1)
    logging.info("display_messages task finished.")


async def connect_and_handle(peer_ip, requesting_username, target_username):
     websocket = await connect_to_peer(peer_ip, requesting_username, target_username)
     if websocket:
         await receive_peer_messages(websocket, peer_ip)