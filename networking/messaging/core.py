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
    groups, pending_invites, pending_join_requests
)
from networking.utils import get_own_ip
from networking.file_transfer import FileTransfer, TransferState
from networking.messaging.utils import get_peer_display_name, connect_to_peer
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

                    if user_data.get("connection_approval", "auto") == "manual":
                        requesting_username = f"{username}({device_id})"
                        pending_approvals[peer_ip] = {"username": username, "device_id": device_id, "websocket": websocket}
                        await message_queue.put({"type": "approval_request", "requesting_username": requesting_username})
                        break
                    else:
                        connections[peer_ip] = websocket
                        logging.info(f"New connection from {peer_ip} accepted automatically")
                        await message_queue.put(f"Connected to {username}({device_id}) at {peer_ip}")

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
                    admin_ip = peer_ip
                    groups[groupname] = {"admin": admin_ip, "members": {admin_ip}}
                    await message_queue.put(f"Group '{groupname}' created by {get_peer_display_name(peer_ip)}")

                elif message_type == "GROUP_INVITE":
                    groupname = data["groupname"]
                    own_ip = await get_own_ip()
                    pending_invites[own_ip].append((groupname, peer_ip))
                    await message_queue.put(f"Invited to group '{groupname}' by {get_peer_display_name(peer_ip)}. (/accept_invite {groupname} or /decline_invite {groupname})")

                elif message_type == "GROUP_INVITE_RESPONSE":
                    groupname = data["groupname"]
                    accepted = data["accepted"]
                    member_ip = peer_ip
                    if accepted and groupname in groups and await get_own_ip() == groups[groupname]["admin"]:
                        groups[groupname]["members"].add(member_ip)
                        await send_group_update_message(groupname, groups[groupname]["members"])
                        await message_queue.put(f"{get_peer_display_name(member_ip)} accepted invite to '{groupname}'")
                    elif not accepted:
                        await message_queue.put(f"{get_peer_display_name(member_ip)} declined invite to '{groupname}'")

                elif message_type == "GROUP_JOIN_REQUEST":
                    groupname = data["groupname"]
                    requester_ip = peer_ip
                    requester_username = next((u for u, ip in peer_usernames.items() if ip == requester_ip), "unknown")
                    if groupname in groups and await get_own_ip() == groups[groupname]["admin"]:
                        pending_join_requests[groupname].append({"username": requester_username, "ip": requester_ip})
                        await message_queue.put(f"{requester_username} requests to join '{groupname}'. (/approve_join {groupname} {requester_username} or /deny_join {groupname} {requester_username})")

                elif message_type == "GROUP_JOIN_RESPONSE":
                    groupname = data["groupname"]
                    approved = data["approved"]
                    own_ip = await get_own_ip()
                    if approved and groupname in groups:
                        groups[groupname]["members"].add(own_ip)
                        await message_queue.put(f"You have joined '{groupname}'")
                    elif not approved:
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
        ws = connections.get(target)
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
            logging.info(f"Discovered peers: {peers}")
            for peer_ip, (target_username, _) in peers.items():
                if peer_ip == own_ip:
                    logging.info(f"Skipping self-connection to {peer_ip}")
                    continue
                if peer_ip not in connections and peer_ip not in peer_list:
                    peer_list[peer_ip] = True
                    logging.info(f"Attempting to connect to {peer_ip} ({target_username})")
                    asyncio.create_task(connect_to_peer(peer_ip, requesting_username, target_username))
            await asyncio.sleep(10)
        except Exception as e:
            logging.error(f"Error in maintain_peer_list: {e}")
            await asyncio.sleep(10)