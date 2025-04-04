import asyncio
import json
import os
import hashlib
import aiofiles
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from networking.shared_state import (
    connections, message_queue, peer_public_keys, peer_usernames, peer_device_ids,
    shutdown_event, active_transfers, user_data, groups, pending_invites, pending_join_requests,
    connection_denials, pending_approvals
)
from networking.messaging.groups import (
    send_group_create_message, send_group_invite_message, send_group_invite_response,
    send_group_join_request, send_group_join_response, send_group_update_message
)
from networking.messaging.utils import get_peer_display_name, get_own_display_name, get_own_ip
from networking.file_transfer import FileTransfer, TransferState

connection_denials = connection_denials if 'connection_denials' in globals() else {}
pending_approvals = pending_approvals if 'pending_approvals' in globals() else {}

async def send_message_to_peers(message, peer_ip=None):
    """Send an encrypted message to one or all connected peers."""
    if not isinstance(message, str) or not message:
        return False

    targets = []
    if peer_ip:
        ws = connections.get(peer_ip)
        key = peer_public_keys.get(peer_ip)
        disp_name = get_peer_display_name(peer_ip)
        if ws and not ws.closed and key:  # Changed from ws.open to not ws.closed
            targets.append((peer_ip, ws, key, disp_name))
        else:
            await message_queue.put(f"Error: Cannot send message, connection state invalid for {disp_name}.")
            return False
    else:
        for ip, ws in list(connections.items()):
            if not ws.closed:  # Changed from ws.open to not ws.closed
                key = peer_public_keys.get(ip)
                disp_name = get_peer_display_name(ip)
                if key:
                    targets.append((ip, ws, key, disp_name))

    if not targets:
        if not peer_ip:
            await message_queue.put("No peers connected to send message to.")
        return False

    sent_to_at_least_one = False
    for target_ip, websocket, peer_key, display_name in targets:
        try:
            encrypted_message = peer_key.encrypt(
                message.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).hex()
            payload = json.dumps({"type": "MESSAGE", "message": encrypted_message})
            await websocket.send(payload)
            sent_to_at_least_one = True
        except Exception as e:
            await message_queue.put(f"Error sending message to {display_name}: {e}")

    return sent_to_at_least_one

async def receive_peer_messages(websocket, peer_ip):
    """Handle incoming messages from a peer."""
    peer_display_name = f"Peer@{peer_ip}"
    current_receiving_transfer_id = None

    try:
        peer_display_name = get_peer_display_name(peer_ip)
        async for message in websocket:
            if shutdown_event.is_set():
                break

            is_binary = isinstance(message, bytes)
            data = None
            if not is_binary:
                try:
                    data = json.loads(message)
                    message_type = data.get("type")
                except json.JSONDecodeError:
                    continue

            if data:
                if message_type == "MESSAGE":
                    try:
                        decrypted_message = user_data["private_key"].decrypt(
                            bytes.fromhex(data["message"]),
                            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        ).decode()
                        await message_queue.put(f"{peer_display_name}: {decrypted_message}")
                    except Exception:
                        await message_queue.put(f"[Failed to decrypt message from {peer_display_name}]")

                elif message_type == "file_transfer_init":
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
                    try:
                        transfer.file_handle = await aiofiles.open(file_path, "wb")
                        active_transfers[transfer_id] = transfer
                        current_receiving_transfer_id = transfer_id
                        await message_queue.put(f"Receiving '{os.path.basename(file_path)}' from {peer_display_name} (ID: {transfer_id[:8]}...)")
                    except OSError as e:
                        await message_queue.put(f"Error receiving file from {peer_display_name}: Cannot open file")

                elif message_type == "TRANSFER_PAUSE":
                    transfer_id = data.get("transfer_id")
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.peer_ip == peer_ip and transfer.state == TransferState.IN_PROGRESS:
                        await transfer.pause()
                        await message_queue.put(f"Peer {peer_display_name} paused transfer {transfer_id[:8]}")

                elif message_type == "TRANSFER_RESUME":
                    transfer_id = data.get("transfer_id")
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.peer_ip == peer_ip and transfer.state == TransferState.PAUSED:
                        await transfer.resume()
                        await message_queue.put(f"Peer {peer_display_name} resumed transfer {transfer_id[:8]}")

                elif message_type == "GROUP_CREATE":
                    groupname = data["groupname"]
                    admin_ip = data["admin_ip"]
                    groups[groupname] = {"admin": admin_ip, "members": {admin_ip}}
                    await message_queue.put(f"Group '{groupname}' created by {get_peer_display_name(admin_ip)}")

                elif message_type == "GROUP_INVITE":
                    groupname = data["groupname"]
                    inviter_ip = data["inviter_ip"]
                    pending_invites.append({"groupname": groupname, "inviter_ip": inviter_ip})
                    await message_queue.put(f"Received invite to join '{groupname}' from {get_peer_display_name(inviter_ip)}")

                elif message_type == "GROUP_INVITE_RESPONSE":
                    groupname = data["groupname"]
                    invitee_ip = data["invitee_ip"]
                    accepted = data["accepted"]
                    own_ip = await get_own_ip()
                    if own_ip == groups[groupname]["admin"]:
                        if accepted:
                            groups[groupname]["members"].add(invitee_ip)
                            await send_group_update_message(groupname, list(groups[groupname]["members"]))
                            await message_queue.put(f"{get_peer_display_name(invitee_ip)} joined '{groupname}'")
                        else:
                            await message_queue.put(f"{get_peer_display_name(invitee_ip)} declined invite to '{groupname}'")

                elif message_type == "GROUP_JOIN_REQUEST":
                    groupname = data["groupname"]
                    requester_ip = data["requester_ip"]
                    requester_username = data["requester_username"]
                    own_ip = await get_own_ip()
                    if own_ip == groups[groupname]["admin"]:
                        pending_join_requests[groupname].append({"requester_ip": requester_ip, "requester_username": requester_username})
                        await message_queue.put(f"Join request for '{groupname}' from {requester_username}")

                elif message_type == "GROUP_JOIN_RESPONSE":
                    groupname = data["groupname"]
                    requester_ip = data["requester_ip"]
                    approved = data["approved"]
                    if approved:
                        groups[groupname]["members"].add(requester_ip)
                        await message_queue.put(f"{get_peer_display_name(requester_ip)} joined '{groupname}'")
                    else:
                        await message_queue.put(f"Join request for '{groupname}' by {get_peer_display_name(requester_ip)} denied")

                elif message_type == "GROUP_UPDATE":
                    groupname = data["groupname"]
                    members = set(data["members"])
                    if groupname in groups:
                        groups[groupname]["members"] = members
                        await message_queue.put(f"Group '{groupname}' members updated")

            elif is_binary and current_receiving_transfer_id:
                transfer = active_transfers.get(current_receiving_transfer_id)
                if transfer and transfer.direction == "receive":
                    async with transfer.condition:
                        while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                            await transfer.condition.wait()
                        if transfer.state != TransferState.IN_PROGRESS:
                            continue
                        chunk = message
                        await transfer.file_handle.write(chunk)
                        transfer.transferred_size += len(chunk)
                        if transfer.hash_algo:
                            transfer.hash_algo.update(chunk)
                        if transfer.transferred_size >= transfer.total_size:
                            await transfer.file_handle.close()
                            transfer.file_handle = None
                            current_receiving_transfer_id = None
                            if transfer.expected_hash:
                                calculated_hash = transfer.hash_algo.hexdigest()
                                if calculated_hash == transfer.expected_hash:
                                    transfer.state = TransferState.COMPLETED
                                    await message_queue.put(f"'{os.path.basename(transfer.file_path)}' received successfully from {peer_display_name}.")
                                else:
                                    transfer.state = TransferState.FAILED
                                    await message_queue.put(f"Integrity check FAILED for '{os.path.basename(transfer.file_path)}'. File deleted.")
                                    os.remove(transfer.file_path)
                            else:
                                transfer.state = TransferState.COMPLETED
                                await message_queue.put(f"'{os.path.basename(transfer.file_path)}' received from {peer_display_name} (no integrity check).")

    except websockets.exceptions.ConnectionClosed:
        await message_queue.put(f"Disconnected from {peer_display_name}")
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

aasync def handle_incoming_connection(websocket, peer_ip):
    """Handle a new incoming WebSocket connection from a peer."""
    try:
        # Get own IP to check against peer_ip
        own_ip = await get_own_ip()
        if peer_ip == own_ip:
            await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False, "reason": "Cannot connect to self"}))
            await websocket.close(code=1008, reason="Self-connection rejected")
            await message_queue.put("Rejected connection attempt from self.")
            return False

        message = await websocket.recv()
        if shutdown_event.is_set():
            await websocket.close(code=1001, reason="Server shutting down")
            return False

        if message.startswith("INIT "):
            _, sender_ip = message.split(" ", 1)
            if peer_ip in connections:
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
                    await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False, "reason": "Incorrect target username"}))
                    await websocket.close()
                    return False

                denial_count = connection_denials.get(target_username, {}).get(requesting_username, 0)
                if denial_count >= 3:
                    await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False, "reason": "Connection blocked"}))
                    await websocket.close()
                    return False

                approval_future = asyncio.Future()
                pending_approvals[(peer_ip, requesting_username)] = approval_future
                await message_queue.put({
                    "type": "approval_request",
                    "peer_ip": peer_ip,
                    "requesting_username": requesting_display_name
                })

                approved = False
                try:
                    approved = await asyncio.wait_for(approval_future, timeout=30.0)
                except asyncio.TimeoutError:
                    await message_queue.put(f"\nApproval request for {requesting_display_name} timed out.")
                finally:
                    if (peer_ip, requesting_username) in pending_approvals:
                        del pending_approvals[(peer_ip, requesting_username)]

                if not approved:
                    if target_username not in connection_denials:
                        connection_denials[target_username] = {}
                    current_denials = connection_denials[target_username]
                    current_denials[requesting_username] = current_denials.get(requesting_username, 0) + 1
                    await message_queue.put(f"Denied connection from {requesting_display_name} ({current_denials[requesting_username]}/3)")
                    if current_denials[requesting_username] >= 3:
                        await message_queue.put(f"{requesting_display_name} has been blocked for this session.")

                await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": approved}))

                if not approved:
                    await websocket.close()
                    return False

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

                identity_message = await websocket.recv()
                identity_data = json.loads(identity_message)
                if identity_data["type"] == "IDENTITY":
                    peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_key_pem.encode())
                    peer_usernames[requesting_username] = peer_ip
                    peer_device_ids[peer_ip] = requesting_device_id
                    connections[peer_ip] = websocket
                    display_name = get_peer_display_name(peer_ip)
                    await message_queue.put(f"Accepted connection from {display_name}")
                    return True
                else:
                    await websocket.close(code=1002, reason="Unexpected message type")
                    return False
            else:
                await websocket.close(code=1002, reason="Unexpected message type")
                return False
        else:
            await websocket.close(code=1002, reason="Invalid initial message")
            return False
    except json.JSONDecodeError:
        if websocket.open:
            await websocket.close(code=1007, reason="Invalid JSON")
        return False
    except websockets.exceptions.ConnectionClosed:
        if (peer_ip, requesting_username) in pending_approvals:
            del pending_approvals[(peer_ip, requesting_username)]
        return False
    except Exception as e:
        if websocket.open:
            await websocket.close(code=1011, reason="Internal server error")
        if (peer_ip, requesting_username) in pending_approvals:
            del pending_approvals[(peer_ip, requesting_username)]
        return False

async def maintain_peer_list(discovery_instance):
    """Periodically check and maintain the list of connected peers."""
    while not shutdown_event.is_set():
        try:
            for peer_ip, ws in list(connections.items()):
                if shutdown_event.is_set():
                    break
                try:
                    await asyncio.wait_for(ws.ping(), timeout=10.0)
                except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                    lost_display_name = get_peer_display_name(peer_ip)
                    if peer_ip in connections:
                        del connections[peer_ip]
                    if peer_ip in peer_public_keys:
                        del peer_public_keys[peer_ip]
                    if peer_ip in peer_device_ids:
                        del peer_device_ids[peer_ip]
                    username = [u for u, ip in peer_usernames.items() if ip == peer_ip]
                    if username and peer_usernames[username[0]] == peer_ip:
                        del peer_usernames[username[0]]
                    await message_queue.put(f"Disconnected from {lost_display_name} (connection lost)")
                    if not ws.closed:
                        await ws.close()
            await asyncio.sleep(15)
        except Exception:
            await asyncio.sleep(15)