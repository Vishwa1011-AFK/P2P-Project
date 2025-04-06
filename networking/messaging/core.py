import asyncio
import json
import logging
import os
import hashlib
import aiofiles
import websockets
from websockets.connection import State
from cryptography.hazmat.primitives import hashes, padding, serialization
from networking.shared_state import (
    active_transfers, message_queue, connections, user_data, peer_public_keys, 
    peer_usernames, shutdown_event, pending_approvals, connection_denials
)
from networking.utils import get_own_ip
from networking.file_transfer import FileTransfer, TransferState
from networking.messaging.utils import get_peer_display_name

# Global peer_list to maintain connected peers
peer_list = {}  # {ip: (username, last_seen)}

async def handle_incoming_connection(websocket, peer_ip):
    """Handle a new incoming WebSocket connection from a peer."""
    try:
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
        if websocket.state == State.OPEN:
            await websocket.close(code=1007, reason="Invalid JSON")
        return False
    except websockets.exceptions.ConnectionClosed:
        if 'requesting_username' in locals() and (peer_ip, requesting_username) in pending_approvals:
            del pending_approvals[(peer_ip, requesting_username)]
        return False
    except Exception as e:
        logging.error(f"Error in handle_incoming_connection: {e}")
        if websocket.state == State.OPEN:
            await websocket.close(code=1011, reason="Internal server error")
        if 'requesting_username' in locals() and (peer_ip, requesting_username) in pending_approvals:
            del pending_approvals[(peer_ip, requesting_username)]
        return False

async def receive_peer_messages(websocket, peer_ip):
    """Receive messages from a connected peer and handle them accordingly."""
    try:
        async for message in websocket:
            if shutdown_event.is_set():
                if websocket.state == State.OPEN:
                    await websocket.close(code=1001, reason="Server shutting down")
                break
            try:
                data = json.loads(message)
                message_type = data.get("type")

                if message_type == "file_transfer_init":
                    transfer_id = data["transfer_id"]
                    file_name = data["filename"]
                    file_size = data["filesize"]
                    expected_hash = data.get("file_hash")
                    file_path = os.path.join("downloads", file_name)
                    os.makedirs("downloads", exist_ok=True)
                    transfer = FileTransfer(file_path, peer_ip, direction="receive")
                    transfer.transfer_id = transfer_id
                    transfer.total_size = file_size
                    transfer.expected_hash = expected_hash
                    transfer.hash_algo = hashlib.sha256() if expected_hash else None
                    transfer.state = TransferState.IN_PROGRESS
                    transfer.file_handle = await aiofiles.open(file_path, "wb")
                    active_transfers[transfer_id] = transfer
                    peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
                    await message_queue.put(
                        f"{user_data['original_username']} receiving '{file_name}' from {peer_username} (Transfer ID: {transfer_id})"
                    )

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
                                    os.remove(file_path)
                                    transfer.state = TransferState.FAILED
                                    await message_queue.put(
                                        f"{user_data['original_username']} file transfer failed: integrity check failed"
                                    )
                                else:
                                    transfer.state = TransferState.COMPLETED
                                    await message_queue.put(
                                        f"{user_data['original_username']} file saved as: {file_path}"
                                    )
                            else:
                                transfer.state = TransferState.COMPLETED
                                await message_queue.put(
                                    f"{user_data['original_username']} file saved as: {file_path}"
                                )

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

                else:
                    logging.info(f"Received unknown control message from {peer_ip}: {data}")

            except json.JSONDecodeError:
                peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
                await message_queue.put(f"{peer_username}: {message}")

    except websockets.exceptions.ConnectionClosed:
        peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
        logging.info(f"{user_data['original_username']} connection closed with {peer_username} ({peer_ip})")
    except Exception as e:
        logging.error(f"Error receiving message from {peer_ip}: {e}")
    finally:
        if peer_ip in connections:
            if connections[peer_ip].state == State.OPEN:
                await connections[peer_ip].close(code=1001, reason="Server shutting down")
            del connections[peer_ip]
            del peer_public_keys[peer_ip]
            for username, ip in list(peer_usernames.items()):
                if ip == peer_ip:
                    del peer_usernames[username]

async def send_message_to_peers(message, target=None):
    """Send a message to one or all connected peers."""
    success = False
    if shutdown_event.is_set():
        return success

    if target:  # Could be username or peer_ip
        peer_ip = peer_usernames.get(target, target)  # Try username first, then assume IP
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
            logging.warning(f"No active connection to {target}")
    else:
        # Broadcast to all connected peers
        for peer_ip, websocket in list(connections.items()):
            if websocket.state == State.OPEN:
                try:
                    peer_username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
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
                    success = True
                except Exception as e:
                    logging.error(f"Failed to send message to {peer_ip}: {e}")

    return success

async def maintain_peer_list(discovery_instance):
    """Maintain the list of connected peers by periodically checking connection status."""
    global peer_list
    while not shutdown_event.is_set():
        try:
            for peer_ip in list(connections.keys()):
                if shutdown_event.is_set():
                    break
                websocket = connections[peer_ip]
                if websocket.state != State.OPEN:
                    logging.info(f"Detected closed connection to {peer_ip}, removing from state.")
                    del connections[peer_ip]
                    del peer_public_keys[peer_ip]
                    for username, ip in list(peer_usernames.items()):
                        if ip == peer_ip:
                            del peer_usernames[username]
                else:
                    try:
                        await websocket.ping()
                    except websockets.exceptions.ConnectionClosed:
                        logging.info(f"Ping failed, removing {peer_ip} from state.")
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
    # Close all connections on shutdown
    close_tasks = [
        ws.close(code=1001, reason="Server shutting down")
        for ws in connections.values()
        if ws.state == State.OPEN
    ]
    if close_tasks:
        await asyncio.gather(*close_tasks, return_exceptions=True)
    connections.clear()
    peer_public_keys.clear()
    peer_usernames.clear()
    logging.info("maintain_peer_list exited due to shutdown.")