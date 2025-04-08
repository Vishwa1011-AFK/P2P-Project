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
    peer_usernames, shutdown_event, pending_approvals, connection_denials
)
from networking.utils import get_own_ip
from networking.file_transfer import FileTransfer, TransferState
from networking.messaging.utils import get_peer_display_name, connect_to_peer

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

                    if username in user_data["banned_users"]:
                        await websocket.close(code=1008, reason="User is banned")
                        break

                    peer_public_keys[peer_ip] = public_key
                    peer_usernames[username] = peer_ip
                    peer_device_ids[peer_ip] = device_id

                    if user_data["connection_approval"] == "manual":
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
    folder_transfers = {}  # {folder_id: base_dir}
    try:
        async for message in websocket:
            if shutdown_event.is_set():
                if websocket.state == State.OPEN:
                    await websocket.close(code=1001, reason="Server shutting down")
                break
            try:
                data = json.loads(message)
                message_type = data.get("type")

                if message_type == "file_transfer_request":
                    transfer_id = data["transfer_id"]
                    file_name = data["filename"]
                    file_size = data["filesize"]
                    expected_hash = data.get("file_hash")
                    folder_id = data.get("folder_id")
                    peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
                    file_size_mb = file_size / (1024 * 1024)
                    await message_queue.put({
                        "type": "file_transfer_approval",
                        "transfer_id": transfer_id,
                        "peer_ip": peer_ip,
                        "message": f"Do you want to accept '{file_name}' from {peer_username} of {file_size_mb:.2f} MB? (/accept_file {transfer_id} or /deny_file {transfer_id})"
                    })
                    if folder_id:
                        folder_transfers[folder_id] = os.path.dirname(file_name)

                elif message_type == "file_transfer_response":
                    transfer_id = data["transfer_id"]
                    approved = data["approved"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.direction == "send":
                        if approved:
                            transfer.state = TransferState.IN_PROGRESS
                            await message_queue.put(f"File transfer '{os.path.basename(transfer.file_path)}' approved by {get_peer_display_name(peer_ip)}.")
                        else:
                            del active_transfers[transfer_id]
                            await message_queue.put(f"File transfer '{os.path.basename(transfer.file_path)}' denied by {get_peer_display_name(peer_ip)}.")

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
                                    await message_queue.put(f"File transfer failed: integrity check failed for '{transfer.file_path}'")
                                else:
                                    if transfer.folder_id:
                                        base_dir = folder_transfers.get(transfer.folder_id, "downloads")
                                        final_path = os.path.join("downloads", transfer.file_path)
                                        os.makedirs(os.path.dirname(final_path), exist_ok=True)
                                        os.rename(transfer.file_path, final_path)
                                        transfer.file_path = final_path
                                    transfer.state = TransferState.COMPLETED
                                    await message_queue.put(f"File saved as: {transfer.file_path}")
                            else:
                                transfer.state = TransferState.COMPLETED
                                await message_queue.put(f"File saved as: {transfer.file_path}")
                            completed_transfers[transfer_id] = {
                                "file_path": transfer.file_path,
                                "peer_ip": transfer.peer_ip,
                                "direction": transfer.direction,
                                "total_size": transfer.total_size,
                                "transferred_size": transfer.transferred_size,
                                "state": transfer.state.value,
                                "folder_id": transfer.folder_id
                            }
                            del active_transfers[transfer_id]

                elif message_type == "TRANSFER_PAUSE":
                    transfer_id = data["transfer_id"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.direction == "receive":
                        await transfer.pause(peer_ip)

                elif message_type == "TRANSFER_RESUME":
                    transfer_id = data["transfer_id"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.direction == "receive":
                        await transfer.resume(peer_ip)

                elif message_type == "MESSAGE":
                    decrypted_message = user_data["private_key"].decrypt(
                        bytes.fromhex(data["message"]),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    ).decode()
                    peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
                    await message_queue.put(f"{peer_username}: {decrypted_message}")

                elif message_type == "GROUP_CREATE":
                    groupname = data["groupname"]
                    admin_ip = data["admin_ip"]
                    from networking.shared_state import groups
                    groups[groupname]["admin"] = admin_ip
                    groups[groupname]["members"].add(admin_ip)
                    await message_queue.put(f"Group '{groupname}' created by {get_peer_display_name(admin_ip)}")

                elif message_type == "GROUP_INVITE":
                    groupname = data["groupname"]
                    inviter_ip = data["inviter_ip"]
                    from networking.shared_state import pending_invites
                    own_ip = await get_own_ip()
                    pending_invites[own_ip].add((groupname, inviter_ip))
                    await message_queue.put(f"Received invite to join '{groupname}' from {get_peer_display_name(inviter_ip)}")

                elif message_type == "GROUP_INVITE_RESPONSE":
                    groupname = data["groupname"]
                    invitee_ip = data["invitee_ip"]
                    accepted = data["accepted"]
                    own_ip = await get_own_ip()
                    if own_ip == groups[groupname]["admin"] and accepted:
                        groups[groupname]["members"].add(invitee_ip)
                        await send_group_update_message(groupname, groups[groupname]["members"])
                        await message_queue.put(f"{get_peer_display_name(invitee_ip)} joined '{groupname}'")

                elif message_type == "GROUP_JOIN_REQUEST":
                    groupname = data["groupname"]
                    requester_ip = data["requester_ip"]
                    requester_username = data["requester_username"]
                    own_ip = await get_own_ip()
                    from networking.shared_state import pending_join_requests
                    if own_ip == groups[groupname]["admin"]:
                        pending_join_requests[groupname].append({"ip": requester_ip, "username": requester_username})
                        await message_queue.put(f"Join request for '{groupname}' from {requester_username}")

                elif message_type == "GROUP_JOIN_RESPONSE":
                    groupname = data["groupname"]
                    requester_ip = data["requester_ip"]
                    approved = data["approved"]
                    own_ip = await get_own_ip()
                    if own_ip == requester_ip and approved:
                        groups[groupname]["members"].add(own_ip)
                        await message_queue.put(f"You have joined '{groupname}'")

                elif message_type == "GROUP_UPDATE":
                    groupname = data["groupname"]
                    members = set(data["members"])
                    own_ip = await get_own_ip()
                    if own_ip in members:
                        groups[groupname]["members"] = members
                        await message_queue.put(f"Group '{groupname}' updated with members: {', '.join(map(get_peer_display_name, members))}")

                else:
                    logging.info(f"Received unknown control message from {peer_ip}: {data}")

            except json.JSONDecodeError:
                peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
                await message_queue.put(f"{peer_username}: {message}")

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
        from networking.shared_state import groups
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

    if isinstance(target, list):  # Group message
        for peer_ip in target:
            if peer_ip in connections and connections[peer_ip].state == State.OPEN:
                try:
                    encrypted_message = peer_public_keys[peer_ip].encrypt(
                        message.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    ).hex()
                    await connections[peer_ip].send(
                        json.dumps({"type": "MESSAGE", "message": encrypted_message})
                    )
                    success = True
                except Exception as e:
                    logging.error(f"Failed to send message to {peer_ip}: {e}")
    elif target:  # Single peer
        peer_ip = peer_usernames.get(target, target)
        if peer_ip in connections and connections[peer_ip].state == State.OPEN:
            try:
                encrypted_message = peer_public_keys[peer_ip].encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).hex()
                await connections[peer_ip].send(
                    json.dumps({"type": "MESSAGE", "message": encrypted_message})
                )
                success = True
            except Exception as e:
                logging.error(f"Failed to send message to {peer_ip}: {e}")
    else:
        # Broadcast to all
        for peer_ip, websocket in list(connections.items()):
            if websocket.state == State.OPEN:
                try:
                    encrypted_message = peer_public_keys[peer_ip].encrypt(
                        message.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    ).hex()
                    await websocket.send(
                        json.dumps({"type": "MESSAGE", "message": encrypted_message})
                    )
                    success = True
                except Exception as e:
                    logging.error(f"Failed to send message to {peer_ip}: {e}")
                    if websocket.state == State.OPEN:
                        await websocket.close(code=1011, reason="Internal error")

    return success

async def maintain_peer_list(peer_discovery):
    while not shutdown_event.is_set():
        try:
            peers = peer_discovery.peer_list  # Dictionary of {peer_ip: (username, timestamp)}
            requesting_username = user_data.get("original_username", "unknown")
            own_ip = await get_own_ip()
            for peer_ip, (target_username, _) in peers.items():
                if peer_ip == own_ip:  # Skip self
                    continue
                if peer_ip not in connections and peer_ip not in peer_list:
                    peer_list[peer_ip] = True
                    asyncio.create_task(connect_to_peer(peer_ip, requesting_username, target_username))
            await asyncio.sleep(10)
        except Exception as e:
            logging.error(f"Error in maintain_peer_list: {e}")
            await asyncio.sleep(10)

from networking.messaging.groups import send_group_update_message