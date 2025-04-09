import asyncio
import json
import os
import aiofiles
import websockets
from websockets.connection import State
from appdirs import user_config_dir
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from networking.shared_state import (
    connections, user_data, peer_usernames, peer_device_ids, peer_public_keys,
    shutdown_event, message_queue, active_transfers, completed_transfers,
    groups, pending_invites, pending_join_requests, username_to_ip
)
from networking.file_transfer import FileTransfer, TransferState
from networking.messaging.helpers import get_peer_display_name, get_own_display_name, get_own_ip
from networking.messaging.groups import send_group_update_message

async def resolve_peer_target(target_identifier):
    # Check if it's a group
    if target_identifier in groups:
        return list(groups[target_identifier]["members"]), "group"
    # Check connected peers by display name or username
    matches = []
    for peer_ip in connections:
        display_name = get_peer_display_name(peer_ip)
        original_username = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), None)
        if target_identifier == display_name or target_identifier == original_username:
            matches.append(peer_ip)
    # Check discovered peers in username_to_ip
    if not matches and target_identifier in username_to_ip:
        matches.append(username_to_ip[target_identifier])
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

async def connect_to_peer(target_identifier, requesting_username, target_username=None):
    own_ip = await get_own_ip()
    peer_ip, status = await resolve_peer_target(target_identifier)
    if status == "not_found":
        await message_queue.put(f"No peer found with username or display name '{target_identifier}'")
        return
    elif status == "ambiguous":
        await message_queue.put(f"Multiple peers match '{target_identifier}': {', '.join(peer_ip)}. Please use the full display name.")
        return
    elif peer_ip == own_ip:
        await message_queue.put(f"Cannot connect to self ({target_identifier})")
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
        target = target_username if target_username else target_identifier
        await message_queue.put(f"Failed to connect to {target}: {e}")
    except Exception as e:
        target = target_username if target_username else target_identifier
        await message_queue.put(f"Unexpected error connecting to {target}: {e}")

async def disconnect_from_peer(target_identifier):
    peer_ip, status = await resolve_peer_target(target_identifier)
    if status == "not_found":
        await message_queue.put(f"No connected peer found with '{target_identifier}'")
        return
    elif status == "ambiguous":
        await message_queue.put(f"Multiple peers match '{target_identifier}': {', '.join(peer_ip)}. Please use the full display name.")
        return

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

async def receive_peer_messages(websocket, peer_ip):
    folder_transfers = {}
    try:
        async for message in websocket:
            if shutdown_event.is_set():
                if websocket.state == State.OPEN:
                    await websocket.close(code=1001, reason="Server shutting down")
                break
            try:
                data = json.loads(message)
                message_type = data.get("type")

                if message_type == "MESSAGE":
                    signature = bytes.fromhex(data["signature"])
                    message_content = data["message"].encode()
                    sender_public_key = peer_public_keys.get(peer_ip)

                    if not sender_public_key:
                        logging.warning(f"No public key for {peer_ip}, dropping message")
                        continue

                    sender_public_key.verify(
                        signature,
                        message_content,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    sender_display_name = get_peer_display_name(peer_ip)
                    await message_queue.put(f"{sender_display_name}: {data['message']}")

                elif message_type == "FILE_TRANSFER":
                    transfer_id = data["transfer_id"]
                    file_path = data["file_path"]
                    total_size = data["file_size"]
                    folder_id = data.get("folder_id")

                    if folder_id and folder_id in folder_transfers:
                        folder_transfers[folder_id].append(transfer_id)
                    elif folder_id:
                        folder_transfers[folder_id] = [transfer_id]

                    file_transfer = FileTransfer(peer_ip, "receive", file_path, total_size, transfer_id, folder_id=folder_id)
                    active_transfers[transfer_id] = file_transfer

                    approval_msg = {
                        "type": "file_transfer_approval",
                        "message": f"Receiving '{os.path.basename(file_path)}' ({total_size / (1024 * 1024):.2f} MB) from {get_peer_display_name(peer_ip)}. Accept? (/accept_file {transfer_id} or /deny_file {transfer_id})"
                    }
                    await message_queue.put(approval_msg)

                elif message_type == "FILE_DATA":
                    transfer_id = data["transfer_id"]
                    chunk = bytes.fromhex(data["chunk"])
                    transfer = active_transfers.get(transfer_id)

                    if not transfer or transfer.state != TransferState.IN_PROGRESS:
                        continue

                    await transfer.file_handle.write(chunk)
                    transfer.transferred_size += len(chunk)

                    if transfer.transferred_size >= transfer.total_size:
                        await transfer.file_handle.close()
                        transfer.state = TransferState.COMPLETED
                        completed_transfers[transfer_id] = {
                            "direction": transfer.direction,
                            "file_path": transfer.file_path,
                            "total_size": transfer.total_size,
                            "transferred_size": transfer.transferred_size,
                            "state": transfer.state.value,
                            "peer_ip": transfer.peer_ip
                        }
                        del active_transfers[transfer_id]
                        folder_id = transfer.folder_id
                        if folder_id and folder_id in folder_transfers and transfer_id in folder_transfers[folder_id]:
                            folder_transfers[folder_id].remove(transfer_id)
                            if not folder_transfers[folder_id]:
                                del folder_transfers[folder_id]
                                await message_queue.put(f"Folder transfer {folder_id} completed from {get_peer_display_name(peer_ip)}")
                        await message_queue.put(f"Received '{os.path.basename(transfer.file_path)}' from {get_peer_display_name(peer_ip)}")

                elif message_type == "FILE_TRANSFER_RESPONSE":
                    transfer_id = data["transfer_id"]
                    approved = data["approved"]
                    transfer = active_transfers.get(transfer_id)

                    if transfer and transfer.direction == "send":
                        if approved:
                            transfer.state = TransferState.IN_PROGRESS
                            asyncio.create_task(send_file_chunks(transfer, websocket))
                        else:
                            transfer.state = TransferState.FAILED
                            del active_transfers[transfer_id]
                            await message_queue.put(f"File transfer '{os.path.basename(transfer.file_path)}' to {get_peer_display_name(peer_ip)} denied by recipient")

                elif message_type == "TRANSFER_PAUSE":
                    transfer_id = data["transfer_id"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.state == TransferState.IN_PROGRESS:
                        await transfer.pause(peer_ip)
                        await message_queue.put(f"Transfer {transfer_id[:8]} paused by {get_peer_display_name(peer_ip)}")

                elif message_type == "TRANSFER_RESUME":
                    transfer_id = data["transfer_id"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.state == TransferState.PAUSED:
                        await transfer.resume(peer_ip)
                        if transfer.direction == "send":
                            asyncio.create_task(send_file_chunks(transfer, websocket))
                        await message_queue.put(f"Transfer {transfer_id[:8]} resumed by {get_peer_display_name(peer_ip)}")

                elif message_type == "GROUP_CREATE":
                    groupname = data["groupname"]
                    admin_ip = data["admin_ip"]
                    groups[groupname] = {"admin": admin_ip, "members": {admin_ip}}
                    await message_queue.put(f"Group '{groupname}' created by {get_peer_display_name(admin_ip)}")

                elif message_type == "GROUP_INVITE":
                    groupname = data["groupname"]
                    inviter_ip = data["inviter_ip"]
                    own_ip = await get_own_ip()
                    pending_invites[own_ip].add((groupname, inviter_ip))
                    await message_queue.put(f"Invited to group '{groupname}' by {get_peer_display_name(inviter_ip)}. (/accept_invite {groupname} or /decline_invite {groupname})")

                elif message_type == "GROUP_INVITE_RESPONSE":
                    groupname = data["groupname"]
                    invitee_ip = data["invitee_ip"]
                    accepted = data["accepted"]
                    if accepted and groupname in groups and await get_own_ip() == groups[groupname]["admin"]:
                        groups[groupname]["members"].add(invitee_ip)
                        await send_group_update_message(groupname, groups[groupname]["members"])
                        await message_queue.put(f"{get_peer_display_name(invitee_ip)} accepted invite to '{groupname}'")
                    elif not accepted:
                        await message_queue.put(f"{get_peer_display_name(invitee_ip)} declined invite to '{groupname}'")

                elif message_type == "GROUP_JOIN_REQUEST":
                    groupname = data["groupname"]
                    requester_ip = data["requester_ip"]
                    requester_username = data["requester_username"]
                    if groupname in groups and await get_own_ip() == groups[groupname]["admin"]:
                        pending_join_requests[groupname].append({"username": requester_username, "ip": requester_ip})
                        await message_queue.put(f"{requester_username} requests to join '{groupname}'. (/approve_join {groupname} {requester_username} or /deny_join {groupname} {requester_username})")

                elif message_type == "GROUP_JOIN_RESPONSE":
                    groupname = data["groupname"]
                    requester_ip = data["requester_ip"]
                    approved = data["approved"]
                    own_ip = await get_own_ip()
                    if approved and groupname in groups and requester_ip == own_ip:
                        groups[groupname]["members"].add(own_ip)
                        await message_queue.put(f"You have joined '{groupname}'")
                    elif not approved and requester_ip == own_ip:
                        await message_queue.put(f"Join request for '{groupname}' denied")

                elif message_type == "GROUP_UPDATE":
                    groupname = data["groupname"]
                    members = set(data["members"])
                    if groupname in groups:
                        groups[groupname]["members"] = members
                        await message_queue.put(f"Group '{groupname}' updated. New member list: {', '.join(get_peer_display_name(ip) for ip in members)}")

            except json.JSONDecodeError:
                peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
                await message_queue.put(f"{peer_username}: {message}")
            except Exception as e:
                logging.error(f"Error processing message from {peer_ip}: {e}")

    except websockets.exceptions.ConnectionClosed:
        if peer_ip in connections:
            del connections[peer_ip]
        if peer_ip in peer_public_keys:
            del peer_public_keys[peer_ip]
        if peer_ip in peer_device_ids:
            del peer_device_ids[peer_ip]
        username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), None)
        if username:
            del peer_usernames[username]
        for groupname in list(groups.keys()):
            if peer_ip in groups[groupname]["members"]:
                groups[groupname]["members"].remove(peer_ip)
                await send_group_update_message(groupname, groups[groupname]["members"])
                if not groups[groupname]["members"]:
                    del groups[groupname]
        await message_queue.put(f"Disconnected from {get_peer_display_name(peer_ip)}")
    except Exception as e:
        logging.error(f"Error receiving message from {peer_ip}: {e}")
    finally:
        if websocket.state == State.OPEN:
            await websocket.close(code=1000, reason="Normal closure")

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