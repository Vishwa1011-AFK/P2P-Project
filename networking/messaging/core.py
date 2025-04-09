import asyncio
import json
import logging
import os
import hashlib
import aiofiles
import websockets
from websockets.connection import State
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from networking.shared_state import (
    active_transfers, completed_transfers, message_queue, connections, user_data, peer_public_keys, 
    peer_usernames, peer_device_ids, shutdown_event, pending_approvals, connection_denials,
    groups, pending_invites, pending_join_requests, username_to_ip
)
from networking.file_transfer import FileTransfer, TransferState
from networking.messaging.helpers import get_peer_display_name, get_own_ip
from networking.messaging.utils import connect_to_peer, receive_peer_messages
from networking.messaging.groups import send_group_update_message

peer_list = {}

async def handle_incoming_connection(websocket, peer_ip):
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                message_type = data.get("type")

                if message_type == "HELLO":
                    public_key_pem = bytes.fromhex(data["public_key"])
                    public_key = serialization.load_pem_public_key(public_key_pem)
                    username = data["username"]
                    device_id = data["device_id"]

                    if peer_ip in peer_public_keys:
                        logging.info(f"Received redundant HELLO from {peer_ip}, closing connection")
                        await websocket.close(code=1000, reason="Already connected")
                        break

                    if "banned_users" in user_data and username in user_data["banned_users"]:
                        await websocket.close(code=1008, reason="User is banned")
                        break

                    peer_public_keys[peer_ip] = public_key
                    peer_usernames[username] = peer_ip
                    peer_device_ids[peer_ip] = device_id
                    display_name = f"{username}({device_id[:8]})" if device_id else username
                    username_to_ip[display_name] = peer_ip  # Update mapping

                    if user_data.get("connection_approval", "auto") == "manual":
                        requesting_username = display_name
                        pending_approvals[peer_ip] = {"username": username, "device_id": device_id, "websocket": websocket}
                        await message_queue.put({"type": "approval_request", "requesting_username": requesting_username})
                        break
                    else:
                        connections[peer_ip] = websocket
                        logging.info(f"New connection from {display_name} accepted automatically")
                        await message_queue.put(f"Connected to {display_name}")

                        own_public_key_pem = user_data["public_key"].public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).hex()
                        hello_back = json.dumps({
                            "type": "HELLO",
                            "public_key": own_public_key_pem,
                            "username": user_data["original_username"],
                            "device_id": user_data["device_id"]
                        })
                        await websocket.send(hello_back)
                        asyncio.create_task(receive_peer_messages(websocket, peer_ip))
                        return True

            except json.JSONDecodeError:
                logging.warning(f"Invalid HELLO message from {peer_ip}")
                await websocket.close(code=1003, reason="Invalid HELLO message")
                break
            except Exception as e:
                logging.error(f"Error processing HELLO from {peer_ip}: {e}")
                await websocket.close(code=1011, reason="Internal server error")
                break

    except websockets.exceptions.ConnectionClosed:
        logging.info(f"Initial connection from {peer_ip} closed during HELLO")
    except Exception as e:
        logging.error(f"Error in handle_incoming_connection: {e}")
        if websocket.state == State.OPEN:
            await websocket.close(code=1011, reason="Internal server error")
    return False

async def send_message_to_peers(message, target=None):
    success = False
    if shutdown_event.is_set():
        return success
    own_ip = await get_own_ip()
    signature = user_data["private_key"].sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    message_data = json.dumps({
        "type": "MESSAGE",
        "message": message,
        "signature": signature.hex()
    })

    if isinstance(target, str):
        peer_ip = username_to_ip.get(target, target)  # Resolve display name or assume IP if direct
        ws = connections.get(peer_ip)
        if ws and ws.state == State.OPEN:
            try:
                await ws.send(message_data)
                success = True
            except Exception as e:
                logging.error(f"Failed to send message to {target}: {e}")
        return success
    elif isinstance(target, list):
        for peer_ip in target:
            ws = connections.get(peer_ip)
            if ws and ws.state == State.OPEN:
                try:
                    await ws.send(message_data)
                    success = True
                except Exception as e:
                    logging.error(f"Failed to send message to {peer_ip}: {e}")
        return success
    else:
        for peer_ip, ws in list(connections.items()):
            if peer_ip == own_ip:
                continue
            if ws.state == State.OPEN:
                try:
                    await ws.send(message_data)
                    success = True
                except Exception as e:
                    logging.error(f"Failed to send message to {peer_ip}: {e}")
        return success

async def send_file_chunks(transfer, websocket):
    try:
        async with aiofiles.open(transfer.file_path, "rb") as f:
            while transfer.state == TransferState.IN_PROGRESS:
                chunk = await f.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                await websocket.send(json.dumps({
                    "type": "FILE_DATA",
                    "transfer_id": transfer.transfer_id,
                    "chunk": chunk.hex()
                }))
                transfer.transferred_size += len(chunk)
                await asyncio.sleep(0.01)  # Prevent overwhelming the network
            if transfer.transferred_size >= transfer.total_size:
                transfer.state = TransferState.COMPLETED
                completed_transfers[transfer.transfer_id] = {
                    "direction": transfer.direction,
                    "file_path": transfer.file_path,
                    "total_size": transfer.total_size,
                    "transferred_size": transfer.transferred_size,
                    "state": transfer.state.value,
                    "peer_ip": transfer.peer_ip
                }
                del active_transfers[transfer.transfer_id]
                await message_queue.put(f"Sent '{os.path.basename(transfer.file_path)}' to {get_peer_display_name(transfer.peer_ip)}")
    except Exception as e:
        transfer.state = TransferState.FAILED
        del active_transfers[transfer.transfer_id]
        await message_queue.put(f"Failed to send '{os.path.basename(transfer.file_path)}' to {get_peer_display_name(transfer.peer_ip)}: {e}")

async def maintain_peer_list(peer_discovery):
    while not shutdown_event.is_set():
        try:
            peers = peer_discovery.peer_list
            requesting_username = user_data.get("original_username", "unknown")
            own_ip = await get_own_ip()
            for peer_ip, (target_username, _) in peers.items():
                if peer_ip == own_ip:
                    continue
                display_name = next((d_name for d_name, ip in username_to_ip.items() if ip == peer_ip), 
                                  f"{target_username}({peer_device_ids.get(peer_ip, 'unknown')[:8]})")
                username_to_ip[display_name] = peer_ip  # Update mapping
                if peer_ip not in connections and peer_ip not in peer_list:
                    peer_list[peer_ip] = True
                    logging.info(f"Attempting to connect to {display_name}")
                    asyncio.create_task(connect_to_peer(peer_ip, requesting_username, target_username))
            await asyncio.sleep(10)
        except Exception as e:
            logging.error(f"Error in maintain_peer_list: {e}")
            await asyncio.sleep(10)