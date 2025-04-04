import asyncio
import json
import os
import logging
import websockets
from appdirs import user_config_dir
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from networking.shared_state import (
    connections, user_data, peer_usernames, peer_device_ids, peer_public_keys,
    shutdown_event, message_queue
)
from networking.utils import get_own_ip as network_get_own_ip

def get_peer_display_name(peer_ip):
    """Return the display name for a peer based on username and device ID."""
    username = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), "Unknown")
    device_id = peer_device_ids.get(peer_ip)
    device_suffix = f"({device_id[:8]})" if device_id else "(?)"
    username_count = sum(1 for ip in connections if get_peer_original_username(ip) == username)
    return f"{username}{device_suffix}" if username_count > 1 or username == "Unknown" else username

def get_peer_original_username(peer_ip):
    """Return the original username associated with a peer IP."""
    return next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), None)

def get_own_display_name():
    """Return the display name for the local user."""
    username = user_data.get("original_username", "User")
    device_id = user_data.get("device_id")
    return f"{username}({device_id[:8]})" if device_id else username

async def get_own_ip():
    """Get the local machine's IP address."""
    return await network_get_own_ip()

async def resolve_peer_target(target_identifier):
    """Resolve a target identifier to a peer IP, handling ambiguity."""
    matches = []
    for peer_ip in connections:
        display_name = get_peer_display_name(peer_ip)
        original_username = get_peer_original_username(peer_ip)
        if target_identifier == display_name:
            matches.append(peer_ip)
            if '(' in display_name:  # Exact match with device ID takes priority
                return peer_ip, "found"
        elif target_identifier == original_username:
            matches.append(peer_ip)
    unique_matches = list(set(matches))
    if not unique_matches:
        return None, "not_found"
    elif len(unique_matches) == 1:
        return unique_matches[0], "found"
    else:
        return [get_peer_display_name(ip) for ip in unique_matches], "ambiguous"

def get_config_directory():
    """Return the user configuration directory for storing keys and settings."""
    return user_config_dir("P2PChat", False)

async def initialize_user_config():
    """Initialize user configuration, including keys and username."""
    config_dir = get_config_directory()
    os.makedirs(config_dir, exist_ok=True)

    keys_file = os.path.join(config_dir, "keys.json")
    if os.path.exists(keys_file):
        with open(keys_file, "r") as f:
            data = json.load(f)
            user_data["original_username"] = data["username"]
            user_data["device_id"] = data["device_id"]
            user_data["private_key"] = serialization.load_pem_private_key(
                data["private_key"].encode(), password=None
            )
            user_data["public_key"] = serialization.load_pem_public_key(
                data["public_key"].encode()
            )
        logging.info(f"Loaded user config from {keys_file}")
        await message_queue.put(f"Welcome back, {user_data['original_username']}!")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        username = input("Enter your username: ").strip()
        while not username:
            username = input("Username cannot be empty. Enter your username: ").strip()
        device_id = os.urandom(16).hex()  # Unique device identifier

        user_data["original_username"] = username
        user_data["device_id"] = device_id
        user_data["private_key"] = private_key
        user_data["public_key"] = public_key

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        with open(keys_file, "w") as f:
            json.dump({
                "username": username,
                "device_id": device_id,
                "private_key": private_key_pem,
                "public_key": public_key_pem
            }, f, indent=4)
        logging.info(f"Created new user config at {keys_file}")
        await message_queue.put(f"Welcome, {username}! Your keys have been generated.")

async def connect_to_peer(peer_ip, requesting_username, target_username):
    """Establish a WebSocket connection to a peer."""
    uri = f"ws://{peer_ip}:8765"
    try:
        async with websockets.connect(uri, ping_interval=None, max_size=10 * 1024 * 1024) as websocket:
            own_ip = await get_own_ip()
            await websocket.send(f"INIT {own_ip}")

            ack = await websocket.recv()
            if ack != "INIT_ACK":
                logging.error(f"Invalid INIT_ACK from {peer_ip}: {ack}")
                await message_queue.put(f"Failed to connect to {peer_ip}: Invalid handshake")
                return

            public_key_pem = user_data["public_key"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            request_message = json.dumps({
                "type": "CONNECTION_REQUEST",
                "requesting_username": requesting_username,
                "device_id": user_data["device_id"],
                "target_username": target_username,
                "key": public_key_pem
            })
            await websocket.send(request_message)

            response = await websocket.recv()
            response_data = json.loads(response)
            if response_data["type"] != "CONNECTION_RESPONSE" or not response_data.get("approved"):
                reason = response_data.get("reason", "No reason provided")
                logging.info(f"Connection to {peer_ip} denied: {reason}")
                await message_queue.put(f"Connection to {target_username} denied: {reason}")
                return

            await websocket.send(json.dumps({
                "type": "IDENTITY",
                "username": user_data["original_username"],
                "device_id": user_data["device_id"],
                "key": public_key_pem
            }))

            identity_message = await websocket.recv()
            identity_data = json.loads(identity_message)
            if identity_data["type"] == "IDENTITY":
                peer_public_keys[peer_ip] = serialization.load_pem_public_key(identity_data["key"].encode())
                peer_usernames[identity_data["username"]] = peer_ip
                peer_device_ids[peer_ip] = identity_data["device_id"]
                connections[peer_ip] = websocket
                display_name = get_peer_display_name(peer_ip)
                await message_queue.put(f"Connected to {display_name}")
                from networking.messaging.core import receive_peer_messages
                await receive_peer_messages(websocket, peer_ip)
            else:
                logging.error(f"Invalid identity response from {peer_ip}")
                await message_queue.put(f"Failed to connect to {peer_ip}: Invalid identity response")
    except (websockets.exceptions.WebSocketException, json.JSONDecodeError) as e:
        logging.error(f"Failed to connect to {peer_ip}: {e}")
        await message_queue.put(f"Failed to connect to {target_username} ({peer_ip}): {e}")
    except Exception as e:
        logging.exception(f"Unexpected error connecting to {peer_ip}: {e}")
        await message_queue.put(f"Unexpected error connecting to {target_username} ({peer_ip})")

async def disconnect_from_peer(peer_ip):
    """Disconnect from a specific peer."""
    ws = connections.get(peer_ip)
    if ws and ws.open:
        try:
            await ws.close()
        except Exception as e:
            logging.error(f"Error closing connection to {peer_ip}: {e}")
        finally:
            if peer_ip in connections:
                del connections[peer_ip]
            if peer_ip in peer_public_keys:
                del peer_public_keys[peer_ip]
            if peer_ip in peer_device_ids:
                del peer_device_ids[peer_ip]
            username = [u for u, ip in peer_usernames.items() if ip == peer_ip]
            if username and peer_usernames[username[0]] == peer_ip:
                del peer_usernames[username[0]]
            await message_queue.put(f"Disconnected from {get_peer_display_name(peer_ip)}")
    else:
        logging.warning(f"No active connection to disconnect from {peer_ip}")
        await message_queue.put(f"No active connection to {get_peer_display_name(peer_ip)}")