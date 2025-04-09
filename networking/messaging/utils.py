import asyncio
import json
import os
import websockets
from websockets.connection import State
from appdirs import user_config_dir
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from networking.shared_state import (
    connections, user_data, peer_usernames, peer_device_ids, peer_public_keys,
    shutdown_event, message_queue
)
from networking.utils import get_own_ip as network_get_own_ip
from networking.messaging.core import receive_peer_messages

def get_peer_display_name(peer_ip):
    username = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), "unknown")
    device_id = peer_device_ids.get(peer_ip, "unknown")
    device_suffix = f"({device_id[:8]})" if device_id != "unknown" else "(?)"
    username_count = sum(1 for ip in connections if get_peer_original_username(ip) == username)
    return f"{username}{device_suffix}" if username_count > 1 or username == "unknown" else username

def get_peer_original_username(peer_ip):
    return next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), None)

def get_own_display_name():
    username = user_data.get("original_username", "User")
    device_id = user_data.get("device_id")
    return f"{username}({device_id[:8]})" if device_id else username

async def get_own_ip():
    return await network_get_own_ip()

async def resolve_peer_target(target_identifier):
    matches = []
    for peer_ip in connections:
        display_name = get_peer_display_name(peer_ip)
        original_username = get_peer_original_username(peer_ip)
        if target_identifier == display_name:
            matches.append(peer_ip)
            if '(' in display_name:
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
    return user_config_dir("P2PChat", False)

async def initialize_user_config():
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
            user_data["banned_users"] = data.get("banned_users", [])
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        username = input("Enter your username: ").strip()
        while not username:
            username = input("Username cannot be empty. Enter your username: ").strip()
        device_id = os.urandom(16).hex()

        user_data["original_username"] = username
        user_data["device_id"] = device_id
        user_data["private_key"] = private_key
        user_data["public_key"] = public_key
        user_data["banned_users"] = []

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
                "public_key": public_key_pem,
                "banned_users": []
            }, f, indent=4)
    await message_queue.put(f"Welcome back, {user_data['original_username']}!")

async def connect_to_peer(peer_ip, requesting_username, target_username=None):
    if peer_ip == await get_own_ip():
        await message_queue.put(f"Skipping connection to self ({peer_ip})")
        return
    uri = f"ws://{peer_ip}:8765"
    try:
        async with websockets.connect(uri, ping_interval=None, max_size=10 * 1024 * 1024) as websocket:
            public_key_pem = user_data["public_key"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
            hello_message = json.dumps({
                "type": "HELLO",
                "public_key": public_key_pem,
                "username": requesting_username,
                "device_id": user_data["device_id"]
            })
            await websocket.send(hello_message)
            connections[peer_ip] = websocket
            await receive_peer_messages(websocket, peer_ip)
    except (websockets.exceptions.WebSocketException, json.JSONDecodeError) as e:
        target = target_username if target_username else peer_ip
        await message_queue.put(f"Failed to connect to {target} ({peer_ip}): {e}")
    except Exception as e:
        target = target_username if target_username else peer_ip
        await message_queue.put(f"Unexpected error connecting to {target} ({peer_ip}): {e}")

async def disconnect_from_peer(peer_ip):
    ws = connections.get(peer_ip)
    if ws and ws.state == State.OPEN:
        try:
            await ws.close()
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
        await message_queue.put(f"No active connection to {get_peer_display_name(peer_ip)}")