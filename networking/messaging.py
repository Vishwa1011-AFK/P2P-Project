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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature, InvalidKey, UnsupportedAlgorithm, AlreadyFinalized, NotYetFinalized
from networking.utils import get_own_ip
from networking.shared_state import (
    active_transfers, message_queue, connections, user_data, peer_public_keys,
    peer_usernames, peer_device_ids, shutdown_event
)
from networking.file_transfer import send_file, FileTransfer, TransferState
from websockets.connection import State
from networking.shared_state import connections_lock
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
    exact_display_name_match_with_id = None

    async with connections_lock:
        current_connections = list(connections.keys())

    for peer_ip in current_connections:
        display_name = get_peer_display_name(peer_ip)
        original_username = get_peer_original_username(peer_ip)

        if target_identifier == display_name and '(' in display_name and ')' in display_name:
            exact_display_name_match_with_id = peer_ip
            logging.debug(f"Found exact match with device ID for '{target_identifier}': {peer_ip}")
            break 

        if target_identifier == display_name:
            matches.append(peer_ip)
            logging.debug(f"Found potential display name match for '{target_identifier}': {peer_ip}")

        elif target_identifier == original_username:
            matches.append(peer_ip)
            possible_original_username_match = True
            logging.debug(f"Found potential original username match for '{target_identifier}': {peer_ip}")


    if exact_display_name_match_with_id:
        return exact_display_name_match_with_id, "found"


    unique_matches = list(set(matches))

    if len(unique_matches) == 0:
        logging.debug(f"No matches found for target '{target_identifier}'")
        return None, "not_found"

    elif len(unique_matches) == 1:
        logging.debug(f"Found unique match for target '{target_identifier}': {unique_matches[0]}")
        return unique_matches[0], "found"

    else:
        logging.warning(f"Ambiguous target '{target_identifier}'. Multiple matches found: {unique_matches}")
        is_target_just_username = not ('(' in target_identifier and ')' in target_identifier)

        if possible_original_username_match and is_target_just_username:
            first_match_username = get_peer_original_username(unique_matches[0])
            all_share_target_username = target_identifier == first_match_username
            if all_share_target_username:
                for ip in unique_matches[1:]:
                    if get_peer_original_username(ip) != first_match_username:
                        all_share_target_username = False
                        break

            if all_share_target_username:
                 ambiguous_names = sorted([get_peer_display_name(ip) for ip in unique_matches])
                 logging.debug(f"Ambiguity for '{target_identifier}' resolved to multiple devices with same username: {ambiguous_names}")
                 return ambiguous_names, "ambiguous"

        ambiguous_names = sorted([get_peer_display_name(ip) for ip in unique_matches])
        logging.debug(f"Ambiguity for '{target_identifier}' resolved to multiple different matches: {ambiguous_names}")
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
        except (json.JSONDecodeError, KeyError, ValueError, TypeError, UnsupportedAlgorithm) as e:
             print(f"Error loading config file ({config_file_path}): {e}. Creating a new one.")
             await create_new_user_config(config_file_path)
        except OSError as e:
             print(f"OS error loading config file ({config_file_path}): {e}. Creating a new one.")
             await create_new_user_config(config_file_path)
        except Exception as e:
            logging.exception(f"Unexpected error loading config file {config_file_path}: {e}")
            print(f"Unexpected error loading config, creating new one: {e}")
            await create_new_user_config(config_file_path)
    else:
        await create_new_user_config(config_file_path)
        print(f"Welcome, {get_own_display_name()}!")

async def create_new_user_config(config_file_path, username=None):
    if username is None:
        try:
            original_username = await ainput("Enter your desired username: ")
            if not original_username:
                print("Username cannot be empty.")
                return False # Indicate failure
        except Exception as input_err:
             logging.error(f"Error reading username input: {input_err}")
             print("Error reading username input.")
             return False
    else:
        original_username = username

    password = None
    try:
        print("\nEnter a password to encrypt your private key (leave blank for no encryption - not recommended):")
        password_input = await ainput("Password: ")
        if password_input:
            password = password_input
    except Exception as e:
        logging.error(f"Error getting password input: {e}")
        print("\nWarning: Could not get password input. Continuing without private key encryption.")

    try:
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
        logging.info(f"Generated new keys and device ID for user: {original_username}")


        encryption_algorithm = serialization.NoEncryption()
        if password:
            logging.info(f"Using password encryption for private key in config file.")
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
             logging.warning(f"Saving private key without encryption in config file.")


        data_to_save = {
            "original_username": original_username,
            "public_key": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "private_key": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm 
            ).decode(),
            "device_id": device_id
        }

        os.makedirs(os.path.dirname(config_file_path), exist_ok=True)

        with open(config_file_path, "w") as f:
            json.dump(data_to_save, f, indent=4)

        logging.info(f"Successfully saved new configuration to {config_file_path}")
        print(f"Configuration saved successfully to {config_file_path}.")
        return True 

    except (OSError, IOError) as e:
        logging.error(f"Failed to save config file {config_file_path}: {e}")
        print(f"Error: Could not save configuration file to {config_file_path}.")
        user_data.clear()
        return False
    except Exception as e:
         logging.exception(f"Unexpected error creating config file {config_file_path}: {e}")
         print(f"Error: Unexpected issue creating configuration.")
         user_data.clear()
         return False

async def connect_to_peer(peer_ip, requesting_username_ignored, target_username, port=8765):
    own_original_username = user_data.get("original_username", "unknown")
    own_device_id = user_data.get("device_id", "unknown")
    if "public_key" not in user_data:
        logging.error("Cannot connect: User public key not loaded/found in user_data.")
        print("Error: Your identity information is missing. Cannot initiate connection.")
        return None
    public_key_pem = user_data["public_key"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    if peer_ip in connections:
        print(f"Already connected to {get_peer_display_name(peer_ip)}")
        return connections.get(peer_ip) 

    uri = f"wss://{peer_ip}:{port}"
    websocket = None
    retry_count = 0
    max_retries = 3

    while retry_count < max_retries:
        try:
            logging.info(f"Attempting connection to {uri} (Attempt {retry_count + 1}/{max_retries})")

            websocket = await asyncio.wait_for(
                websockets.connect(uri, ping_interval=20, ping_timeout=20, max_size=10*1024*1024),
                timeout=10.0 
            )
            logging.info(f"WebSocket connection established to {uri}")

            own_ip_internal = await get_own_ip()
            await websocket.send(f"INIT {own_ip_internal or 'unknown'}")
            response = await asyncio.wait_for(websocket.recv(), timeout=10.0)

            if response.startswith("INIT_ACK"):
                logging.debug(f"Received INIT_ACK from {peer_ip}")
                await websocket.send(json.dumps({
                    "type": "CONNECTION_REQUEST",
                    "requesting_username": own_original_username,
                    "target_username": target_username, 
                    "key": public_key_pem,
                    "device_id": own_device_id
                }))

                approval_response = await asyncio.wait_for(websocket.recv(), timeout=60.0) 
                approval_data = json.loads(approval_response)

                if approval_data.get("type") == "CONNECTION_RESPONSE" and approval_data.get("approved"):
                    logging.info(f"Connection request approved by {peer_ip}")
                    await websocket.send(json.dumps({
                        "type": "IDENTITY",
                        "username": own_original_username,
                        "device_id": own_device_id,
                        "key": public_key_pem
                    }))

                    identity_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
                    identity_data = json.loads(identity_message)

                    if identity_data.get("type") == "IDENTITY":
                        peer_recv_username = identity_data.get("username")
                        peer_recv_device_id = identity_data.get("device_id")
                        peer_recv_key_pem = identity_data.get("key")

                        if not all([peer_recv_username, peer_recv_device_id, peer_recv_key_pem]):
                             raise ValueError("Received incomplete IDENTITY data from peer.")

                        peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_recv_key_pem.encode())
                        peer_usernames[peer_recv_username] = peer_ip 
                        peer_device_ids[peer_ip] = peer_recv_device_id
                        connections[peer_ip] = websocket

                        display_name = get_peer_display_name(peer_ip)
                        logging.info(f"{get_own_display_name()} successfully connected to {display_name} ({peer_ip})")
                        await message_queue.put(f"Successfully connected to {display_name}")
                        return websocket 
                    else:
                        logging.error(f"Handshake failed with {peer_ip}: Invalid identity response after approval. Data: {identity_data}")
                        await websocket.close(code=1002, reason="Invalid identity response")
                        print(f"Connection to {target_username} failed: Invalid identity response.")
                        return None 
                else: 
                    denial_reason = approval_data.get("reason", "Connection was denied by the peer.")
                    logging.warning(f"Connection request to {peer_ip} denied or failed. Reason: {denial_reason}")
                    await websocket.close(code=1008, reason=f"Connection denied: {denial_reason[:100]}")
                    print(f"Connection to {target_username} failed: {denial_reason}")
                    return None 
            else: 
                logging.error(f"Handshake failed with {peer_ip}: No INIT_ACK received. Got: {response[:100]}")
                await websocket.close(code=1002, reason="Handshake error: No INIT_ACK")
                print(f"Connection to {target_username} failed: Handshake protocol error.")
                return None 

        except ConnectionRefusedError:
            logging.warning(f"Connection to {peer_ip} refused (Attempt {retry_count + 1}/{max_retries})")
            retry_count += 1
            if retry_count < max_retries:
                wait_time = 2 ** retry_count 
                print(f"Connection refused, retrying in {wait_time}s... ({retry_count}/{max_retries})")
                await asyncio.sleep(wait_time)
                continue 
            else:
                print(f"Connection to {target_username} ({peer_ip}) refused after {max_retries} attempts.")
                break

        except websockets.exceptions.InvalidURI:
             logging.error(f"Invalid URI for connection: {uri}")
             print(f"Connection to {target_username} failed: Invalid URI '{uri}'")
             return None 
        except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK) as e:
            logging.warning(f"Connection closed during handshake with {peer_ip} (Attempt {retry_count + 1}): {e}")
            print(f"Connection to {target_username} closed unexpectedly during handshake.")
            return None 
        except OSError as e:
             logging.warning(f"OS error connecting to {peer_ip} (Attempt {retry_count + 1}): {e}")

             print(f"Connection to {target_username} failed: Network error ({e})")
             return None 
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON received during handshake with {peer_ip}: {e}")
            print(f"Connection to {target_username} failed: Invalid data received.")
            if websocket and websocket.open: await websocket.close(code=1007, reason="Invalid JSON")
            return None 
        except asyncio.TimeoutError:
             logging.warning(f"Connection or receive timed out for {peer_ip} (Attempt {retry_count + 1})")
             retry_count += 1
             if retry_count < max_retries:
                 wait_time = 2 ** retry_count
                 print(f"Connection attempt timed out, retrying in {wait_time}s... ({retry_count}/{max_retries})")
                 if websocket and not websocket.closed: await websocket.close() 
                 await asyncio.sleep(wait_time)
                 continue
             else:
                 print(f"Connection attempt to {target_username} timed out after {max_retries} attempts.")
                 if websocket and not websocket.closed: await websocket.close()
                 break 

        except Exception as e: 
            logging.exception(f"Unexpected error connecting to {peer_ip} (Attempt {retry_count + 1}): {e}")
            print(f"Connection to {target_username} failed: Unexpected error ({type(e).__name__})")
            if websocket and not websocket.closed: await websocket.close()
            return None 

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
        except Exception as e: # Catch broad exception during close, as state is already cleaned
            logging.error(f"Error during websocket close for {display_name_disconnecting}: {e}")
            print(f"Error closing connection to {display_name_disconnecting}: {e}")


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
    except websockets.exceptions.ConnectionClosed:
        logging.info(f"Connection closed by {peer_ip} during handshake.")
        if peer_ip in pending_approvals: del pending_approvals[peer_ip]
        return False
    except asyncio.TimeoutError: # Catch timeout during recv
         logging.warning(f"Timeout waiting for message from {peer_ip} during handshake.")
         if websocket and websocket.state != State.CLOSED: await websocket.close()
         if peer_ip in pending_approvals: del pending_approvals[peer_ip]
         return False
    except Exception as e: # Catch-all for unexpected handshake errors
        logging.exception(f"Unexpected error in connection handshake with {peer_ip}: {e}")
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
                except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed) as ping_err:
                    lost_display_name = get_peer_display_name(peer_ip)
                    logging.warning(f"Connection lost with {lost_display_name} ({peer_ip}): {type(ping_err).__name__}. Cleaning up.")

                    lost_original_username = get_peer_original_username(peer_ip)

                    if peer_ip in connections: del connections[peer_ip]
                    if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
                    if peer_ip in peer_device_ids: del peer_device_ids[peer_ip]
                    if lost_original_username and lost_original_username in peer_usernames and peer_usernames[lost_original_username] == peer_ip:
                         del peer_usernames[lost_original_username]

                    await cleanup_transfers_for_peer(peer_ip, lost_display_name)
                    await message_queue.put(f"Disconnected from {lost_display_name} (connection lost)")

                    if ws.state != State.CLOSED:
                        try: await ws.close()
                        except Exception: pass # Ignore errors during cleanup close

            await asyncio.sleep(15)
        except asyncio.CancelledError:
            logging.info("maintain_peer_list task cancelled.")
            break
        except Exception as e: # Broad catch for the background task loop
            logging.exception(f"Error in maintain_peer_list loop: {e}")
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
            encrypted_message = peer_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).hex()

            message_id = str(uuid.uuid4())[:8]
            payload = json.dumps({
                "type": "MESSAGE",
                "message": encrypted_message,
                "message_id": message_id
            })

            await websocket.send(payload)
            logging.debug(f"Sent message {message_id} to {display_name}")

            asyncio.create_task(wait_for_message_ack(message_id, display_name, 5.0))

            sent_to_at_least_one = True
        except (ValueError, TypeError) as crypto_err:
             logging.error(f"Encryption error sending message to {display_name} ({target_ip}): {crypto_err}")
             await message_queue.put(f"Error encrypting message for {display_name}.")
        except websockets.exceptions.ConnectionClosed:
             logging.warning(f"Connection closed while sending message to {display_name} ({target_ip}).")
             await message_queue.put(f"Error sending message to {display_name}: Connection closed.")
        except Exception as e:
            logging.error(f"Failed to send message to {display_name} ({target_ip}): {e}")
            await message_queue.put(f"Error sending message to {display_name}: {e}")

    return sent_to_at_least_one

async def wait_for_message_ack(message_id, recipient, timeout):
    await asyncio.sleep(timeout)
    logging.debug(f"Timeout reached for message {message_id} acknowledgment from {recipient}.")
 
async def receive_peer_messages(websocket, peer_ip):
    peer_display_name = f"Peer@{peer_ip}"
    current_receiving_transfer_id = None

    try:
        peer_display_name = get_peer_display_name(peer_ip)

        async for message in websocket:
            if shutdown_event.is_set(): break

            try:
                data = None
                is_binary = isinstance(message, bytes)

                if not is_binary:
                    try:
                        data = json.loads(message)
                        message_type = data.get("type")
                    except json.JSONDecodeError:
                        logging.warning(f"Received invalid JSON from {peer_display_name} ({peer_ip}): {message[:100]}")
                        await message_queue.put(f"[{peer_display_name} sent invalid data]")
                        continue

                peer_display_name = get_peer_display_name(peer_ip)

                if data:
                    if message_type == "file_transfer_init":
                        transfer_id = data["transfer_id"]
                        file_name = data["filename"]
                        file_size = data["filesize"]
                        expected_hash = data.get("file_hash")
                        
                        safe_filename_base = os.path.basename(file_name.replace('\\', '/'))
                        
                        if safe_filename_base != file_name:
                            logging.warning(f"Potential path traversal attempt from {peer_display_name}: {file_name}")
                        
                        download_dir = os.path.abspath("downloads")
                        os.makedirs(download_dir, exist_ok=True)
                        
                        file_path = os.path.normpath(os.path.join(download_dir, safe_filename_base))
                        if not file_path.startswith(download_dir):
                            logging.error(f"Security violation: File path escapes download directory: {file_path}")
                            await message_queue.put(f"Security error: Invalid filename from {peer_display_name}")
                            continue

                        safe_filename_base = os.path.basename(file_name)
                        download_dir = "downloads"
                        os.makedirs(download_dir, exist_ok=True)
                        file_path = os.path.join(download_dir, safe_filename_base)

                        counter = 1
                        base, ext = os.path.splitext(safe_filename_base)
                        while os.path.exists(file_path):
                            file_path = os.path.join(download_dir, f"{base}({counter}){ext}")
                            counter += 1

                        async with active_transfers_lock:
                             if transfer_id in active_transfers:
                                 logging.warning(f"Received init for existing transfer ID {transfer_id} from {peer_display_name}. Ignoring.")
                                 continue

                             transfer = FileTransfer(file_path, peer_ip, direction="receive")
                             transfer.transfer_id = transfer_id
                             transfer.total_size = file_size
                             transfer.expected_hash = expected_hash
                             transfer.hash_algo = hashlib.sha256() if expected_hash else None
                             transfer.state = TransferState.STARTING

                             try:
                                 transfer.file_handle = await aiofiles.open(file_path, "wb")
                                 transfer.state = TransferState.IN_PROGRESS
                                 active_transfers[transfer_id] = transfer
                                 current_receiving_transfer_id = transfer_id
                                 await message_queue.put(f"Receiving '{os.path.basename(file_path)}' from {peer_display_name} (Size: {file_size} bytes, ID: {transfer_id[:8]}...)")
                                 logging.info(f"Started receiving transfer {transfer_id} to {file_path}")
                             except OSError as file_open_err:
                                 logging.exception(f"Failed to open file for receiving transfer {transfer_id}: {file_open_err}")
                                 await message_queue.put(f"Error starting file receive from {peer_display_name}: Cannot open file {os.path.basename(file_path)}")


                    elif message_type == "MESSAGE":
                        encrypted_msg_hex = data.get("message")
                        message_id = data.get("message_id") 
                        if not encrypted_msg_hex:
                             logging.warning(f"Received MESSAGE from {peer_display_name} without 'message' field.")
                             continue
                        try:
                            decrypted_message = user_data["private_key"].decrypt(
                                bytes.fromhex(encrypted_msg_hex),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            ).decode()
                            await message_queue.put(f"{peer_display_name}: {decrypted_message}")

                            if message_id:
                                try:
                                    ack_payload = json.dumps({"type": "MESSAGE_ACK", "message_id": message_id})
                                    await websocket.send(ack_payload)
                                    logging.debug(f"Sent ACK for message {message_id} to {peer_display_name}")
                                except websockets.exceptions.ConnectionClosed:
                                     logging.warning(f"Connection closed before sending ACK for {message_id} to {peer_display_name}")
                                except Exception as ack_err:
                                     logging.error(f"Failed to send ACK for message {message_id} to {peer_display_name}: {ack_err}")

                        except (ValueError, TypeError) as decrypt_err:
                            logging.error(f"Failed to decrypt message from {peer_display_name} ({peer_ip}): {decrypt_err}")
                            await message_queue.put(f"[Failed to decrypt message from {peer_display_name}]")
                        except Exception as decrypt_general_err:
                             logging.exception(f"Unexpected error decrypting message from {peer_display_name}: {decrypt_general_err}")
                             await message_queue.put(f"[Error processing message from {peer_display_name}]")

                    elif message_type == "TRANSFER_PAUSE":
                        transfer_id = data.get("transfer_id")
                        if not transfer_id: continue
                        async with active_transfers_lock:
                            transfer = active_transfers.get(transfer_id)
                            if transfer and hasattr(transfer, 'peer_ip') and transfer.peer_ip == peer_ip:
                                if transfer.state == TransferState.IN_PROGRESS:
                                    await transfer.pause()
                                    await message_queue.put(f"Peer {peer_display_name} paused transfer {transfer_id[:8]}")
                                    logging.info(f"Paused transfer {transfer_id} by request from {peer_display_name}")
                                elif transfer.state != TransferState.PAUSED: logging.warning(f"Received PAUSE for transfer {transfer_id} from {peer_display_name}, but local state is {transfer.state.value}")
                            elif transfer: logging.warning(f"Received PAUSE for transfer {transfer_id} from {peer_display_name}, but transfer belongs to {transfer.peer_ip}")
                            else: logging.warning(f"Received PAUSE for unknown or inactive transfer {transfer_id} from {peer_display_name}")

                    elif message_type == "TRANSFER_RESUME":
                        transfer_id = data.get("transfer_id")
                        if not transfer_id: continue
                        async with active_transfers_lock:
                            transfer = active_transfers.get(transfer_id)
                            if transfer and hasattr(transfer, 'peer_ip') and transfer.peer_ip == peer_ip:
                                if transfer.state == TransferState.PAUSED:
                                    await transfer.resume()
                                    await message_queue.put(f"Peer {peer_display_name} resumed transfer {transfer_id[:8]}")
                                    logging.info(f"Resumed transfer {transfer_id} by request from {peer_display_name}")
                                elif transfer.state != TransferState.IN_PROGRESS: logging.warning(f"Received RESUME for transfer {transfer_id} from {peer_display_name}, but local state is {transfer.state.value}")
                            elif transfer: logging.warning(f"Received RESUME for transfer {transfer_id} from {peer_display_name}, but transfer belongs to {transfer.peer_ip}")
                            else: logging.warning(f"Received RESUME for unknown or inactive transfer {transfer_id} from {peer_display_name}")

                    elif message_type == "transfer_complete":
                         transfer_id = data.get("transfer_id")
                         logging.debug(f"Received transfer_complete message for {transfer_id} from {peer_display_name}. Receiver handles completion based on bytes/hash.")

                    elif message_type == "MESSAGE_ACK": 
                        ack_message_id = data.get("message_id")
                        if ack_message_id:
                             logging.debug(f"Received ACK for message {ack_message_id} from {peer_display_name}")
                             pass 

                elif is_binary:
                    transfer = None 
                    if current_receiving_transfer_id:
                        async with active_transfers_lock: 
                             transfer = active_transfers.get(current_receiving_transfer_id)

                        if not transfer:
                            logging.warning(f"Received binary data for unknown/inactive transfer ID {current_receiving_transfer_id} from {peer_display_name}. Discarding.")
                            continue

                        if not hasattr(transfer, 'peer_ip') or transfer.peer_ip != peer_ip:
                            logging.error(f"SECURITY ALERT: Binary data for transfer {current_receiving_transfer_id} " +
                                         f"came from wrong peer! Expected {getattr(transfer, 'peer_ip', 'N/A')}, got {peer_ip}")
                            continue

                        if not hasattr(transfer, 'direction') or transfer.direction != "receive":
                            logging.warning(f"Received binary data for a non-receiving transfer {current_receiving_transfer_id} (Direction: {getattr(transfer, 'direction', 'N/A')}). Discarding.")
                            continue

                        async with transfer.condition: 
                            while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                                await transfer.condition.wait()
                            if shutdown_event.is_set(): break

                        if transfer.state != TransferState.IN_PROGRESS:
                            logging.warning(f"Skipping chunk for {transfer.transfer_id}, state is {transfer.state.value}")
                            continue

                        try:
                            chunk = message

                            if transfer.file_handle and not transfer.file_handle.closed:
                                await transfer.file_handle.write(chunk)
                                transfer.transferred_size += len(chunk)
                                if transfer.hash_algo:
                                    transfer.hash_algo.update(chunk)

                                if transfer.transferred_size >= transfer.total_size:
                                    logging.info(f"Received expected size {transfer.total_size} for {transfer.transfer_id}. Closing file.")
                                    await transfer.file_handle.close()
                                    transfer.file_handle = None
                                    active_transfer_id_finished = current_receiving_transfer_id
                                    current_receiving_transfer_id = None

                                    final_message = ""
                                    if transfer.expected_hash:
                                        calculated_hash = transfer.hash_algo.hexdigest()
                                        if calculated_hash == transfer.expected_hash:
                                            transfer.state = TransferState.COMPLETED
                                            final_message = f"'{os.path.basename(transfer.file_path)}' received successfully from {peer_display_name}."
                                            logging.info(f"Transfer {active_transfer_id_finished} completed successfully with matching hash.")
                                        else:
                                            transfer.state = TransferState.FAILED
                                            transfer.error_message = f"Hash mismatch. Expected {transfer.expected_hash}, got {calculated_hash}"
                                            failed_path = f"{transfer.file_path}.failed"
                                            try:
                                                await asyncio.to_thread(os.rename, transfer.file_path, failed_path)
                                                final_message = f"Integrity check FAILED for file from {peer_display_name}. " + \
                                                               f"File saved as '{os.path.basename(failed_path)}'. Use /retry {active_transfer_id_finished[:8]} to request again."
                                                logging.error(f"Hash mismatch {active_transfer_id_finished}. Expected {transfer.expected_hash}, got {calculated_hash}. Renamed to {failed_path}")
                                            except OSError as rename_err:
                                                final_message = f"Integrity check FAILED for file from {peer_display_name}. File could not be preserved due to: {rename_err}"
                                                logging.error(f"Hash mismatch {active_transfer_id_finished}. Expected {transfer.expected_hash}, got {calculated_hash}. FAILED to rename: {rename_err}")

                                    else: 
                                        transfer.state = TransferState.COMPLETED
                                        final_message = f"'{os.path.basename(transfer.file_path)}' received from {peer_display_name} (no integrity check)."
                                        logging.info(f"Transfer {active_transfer_id_finished} completed successfully (no hash check).")

                                    await message_queue.put(final_message)

                            else:
                                 logging.warning(f"Received chunk for {transfer.transfer_id} but file handle was closed or missing.")
                                 async with active_transfers_lock:
                                      transfer_obj = active_transfers.get(transfer.transfer_id)
                                      if transfer_obj:
                                           transfer_obj.state = TransferState.FAILED
                                           transfer_obj.error_message = "File handle closed unexpectedly during receive"
                                 current_receiving_transfer_id = None


                        except IOError as write_err:
                             logging.exception(f"IO error writing chunk for {transfer.transfer_id}: {write_err}")
                             await message_queue.put(f"IO Error receiving file chunk from {peer_display_name}. Transfer failed.")
                             async with active_transfers_lock:
                                 transfer_obj = active_transfers.get(transfer.transfer_id)
                                 if transfer_obj:
                                     transfer_obj.state = TransferState.FAILED
                                     transfer_obj.error_message = f"IO error: {write_err}"
                                     if transfer_obj.file_handle and not transfer_obj.file_handle.closed: await transfer_obj.file_handle.close()
                             current_receiving_transfer_id = None
                        except Exception as chunk_err:
                             logging.exception(f"Error processing binary chunk for {transfer.transfer_id}: {chunk_err}")
                             await message_queue.put(f"Error receiving file chunk from {peer_display_name}. Transfer failed.")
                             async with active_transfers_lock:
                                 transfer_obj = active_transfers.get(transfer.transfer_id)
                                 if transfer_obj:
                                     transfer_obj.state = TransferState.FAILED
                                     transfer_obj.error_message = f"Chunk processing error: {chunk_err}"
                                     if transfer_obj.file_handle and not transfer_obj.file_handle.closed: await transfer_obj.file_handle.close()
                             current_receiving_transfer_id = None
                    else:
                         logging.warning(f"Received unexpected {len(message)} bytes of binary data from {peer_display_name} when not in transfer mode")


            except Exception as proc_err:
                logging.exception(f"Unexpected error processing message from {peer_display_name} ({peer_ip}): {proc_err}")
                await message_queue.put(f"[Unexpected error processing message from {peer_display_name}]")

    except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError) as close_err:
        logging.info(f"Connection loop for {peer_display_name} ({peer_ip}) terminated: {type(close_err).__name__}")
    except Exception as e:
        logging.exception(f"Unexpected error in receive loop for {peer_display_name} ({peer_ip}): {e}")
    finally:
        lost_display_name = get_peer_display_name(peer_ip)
        logging.info(f"Cleaning up connection state for {lost_display_name} ({peer_ip}) after receive loop exit.")
        lost_original_username = get_peer_original_username(peer_ip)

        connections.pop(peer_ip, None)
        peer_public_keys.pop(peer_ip, None)
        peer_device_ids.pop(peer_ip, None)
        if lost_original_username and peer_usernames.get(lost_original_username) == peer_ip:
             peer_usernames.pop(lost_original_username, None)

        await cleanup_transfers_for_peer(peer_ip, lost_display_name)

        if not shutdown_event.is_set():
            await message_queue.put(f"Disconnected from {lost_display_name}")

async def cleanup_transfers_for_peer(peer_ip, display_name):
    logging.debug(f"Cleaning up transfers associated with peer {display_name} ({peer_ip})")
    transfers_to_process = []
    async with active_transfers_lock:
        transfers_to_process = [(tid, transfer) for tid, transfer in active_transfers.items()
                                if hasattr(transfer, 'peer_ip') and transfer.peer_ip == peer_ip]

    if not transfers_to_process:
        logging.debug(f"No active transfers found for peer {display_name} ({peer_ip}) during cleanup.")
        return

    for transfer_id, transfer in transfers_to_process:
        try:

            if transfer.state in (TransferState.IN_PROGRESS, TransferState.PAUSED):
                direction_msg = "Receiving" if transfer.direction == "receive" else "Sending"
                filename = os.path.basename(transfer.file_path) if hasattr(transfer, 'file_path') and transfer.file_path else "unknown file"

                logging.warning(f"Peer {display_name} disconnected during {direction_msg.lower()} transfer {transfer_id} ('{filename}'). Marking as failed.")

                transfer.state = TransferState.FAILED
                transfer.error_message = f"{display_name} disconnected during transfer."

                await message_queue.put(f"{direction_msg} transfer {transfer_id[:8]} ('{filename}') failed: {display_name} disconnected.")

                if transfer.file_handle and not transfer.file_handle.closed:
                    try:
                        await transfer.file_handle.close()
                        transfer.file_handle = None 
                        logging.info(f"Closed file handle for failed transfer {transfer_id} due to peer disconnect.")
                    except Exception as e:
                        logging.error(f"Error closing file handle for failed transfer {transfer_id} after peer disconnect: {e}")
            else:
                 logging.debug(f"Transfer {transfer_id} for peer {display_name} was not in progress or paused (State: {transfer.state.value}), no action needed.")

        except AttributeError as ae:
            logging.error(f"Attribute error processing transfer {transfer_id} during peer cleanup for {display_name}: {ae}")
        except Exception as e:
            logging.exception(f"Unexpected error cleaning up transfer {transfer_id} for peer {display_name}: {e}")

    logging.debug(f"Finished cleanup for peer {display_name} ({peer_ip}). Processed {len(transfers_to_process)} related transfers.")

async def user_input(discovery):
    await asyncio.sleep(1)
    my_display_name = get_own_display_name()

    while not shutdown_event.is_set():
        try:
            message = await ainput(f"{my_display_name} > ")
            message = message.strip()
            if not message: continue

            if message.startswith("/"):
                parts = message.split(maxsplit=1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""
                
            if message == "/exit":
                print("Initiating shutdown...")
                shutdown_event.set()
                break

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
                    for ip in sorted(list(known_ips - {own_ip})):
                        disc_info = discovery.peer_list.get(ip)
                        is_connected = ip in connections
                        status = "Connected" if is_connected else "Discovered"
                        display_name = get_peer_display_name(ip)
                        if not is_connected and '(' not in display_name:
                             if disc_info: display_name = disc_info[0]
                             else: status="Stale?"

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
                 except (IOError, OSError) as e:
                     logging.error(f"Failed to save updated config file {config_file_path}: {e}")
                     print(f"Error: Could not save configuration. Reverting username change.")
                     user_data['original_username'] = old_username
                     my_display_name = get_own_display_name()
                 except Exception as e: # Catch unexpected save errors
                     logging.exception(f"Unexpected error saving config during username change: {e}")
                     print(f"Unexpected error saving config. Reverting username change.")
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

                try:
                    if not os.path.exists(file_path):
                        print(f"Error: File not found: {file_path}")
                        continue
                    if not os.path.isfile(file_path):
                        print(f"Error: Not a file: {file_path}")
                        continue
                except OSError as e:
                     print(f"Error accessing file path '{file_path}': {e}")
                     continue

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
                     except websockets.exceptions.ConnectionClosed:
                          print(f"Error sending {action} notification: Connection closed.")
                     except Exception as e: 
                          logging.error(f"Error sending {action} notification for {transfer_id}: {e}")
                          print(f"Error sending {action} notification: {e}")
                 continue


            else:
                if connections:
                    if await send_message_to_peers(message):
                         await message_queue.put(f"You (to all): {message}")
                else: print("No peers connected."); continue

        except asyncio.CancelledError: break 
        except FileNotFoundError as e: 
            print(f"Error: {e}")
        except Exception as e: 
            logging.exception(f"Error in user_input loop: {e}")
            print(f"\nAn error occurred in the command handler: {type(e).__name__}")
            await asyncio.sleep(0.1)

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
        except Exception as e: # Broad catch for display task safety
            logging.exception(f"Error displaying message: {e}"); await asyncio.sleep(1)
    logging.info("display_messages task finished.")


async def connect_and_handle(peer_ip, requesting_username, target_username):
     websocket = await connect_to_peer(peer_ip, requesting_username, target_username)
     if websocket:
         await receive_peer_messages(websocket, peer_ip)