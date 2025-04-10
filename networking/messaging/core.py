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
    active_transfers, completed_transfers, message_queue, connections, user_data,
    peer_public_keys, peer_usernames, peer_device_ids, shutdown_event,
    pending_approvals, connection_denials, groups, pending_invites,
    pending_join_requests, username_to_ip, discovered_peers_by_username # Added
)
from networking.file_transfer import FileTransfer, TransferState
from networking.messaging.helpers import get_peer_display_name, get_own_ip, get_peer_original_username
from networking.messaging.utils import connect_to_peer, receive_peer_messages # Ensure this import cycle is handled if needed
from networking.messaging.groups import send_group_update_message

async def handle_incoming_connection(websocket, peer_ip):
    try:
        # Only expect one HELLO message for the handshake
        message = await asyncio.wait_for(websocket.recv(), timeout=15.0)

        try:
            data = json.loads(message)
            message_type = data.get("type")

            if message_type == "HELLO":
                public_key_pem = bytes.fromhex(data["public_key"])
                public_key = serialization.load_pem_public_key(public_key_pem)
                username = data["username"]
                device_id = data["device_id"]
                display_name = f"{username}({device_id[:8]})" if device_id else username


                if peer_ip in peer_public_keys and peer_ip in connections:
                    logging.info(f"Received HELLO from already connected peer {display_name} ({peer_ip}). Ignoring redundant HELLO.")
                    # Don't close, just ignore HELLO if already connected
                    # But maybe we should reset the state if this happens unexpectedly?
                    # For now, return True because they *are* connected, even if the HELLO was weird.
                    return True


                if "banned_users" in user_data and username in user_data["banned_users"]:
                    logging.warning(f"Connection attempt from banned user {username} ({peer_ip}). Closing.")
                    await websocket.close(code=1008, reason="User is banned")
                    return False # Connection failed (banned)


                # Store peer info *before* manual approval check
                peer_public_keys[peer_ip] = public_key
                peer_usernames[username] = peer_ip
                peer_device_ids[peer_ip] = device_id
                username_to_ip[display_name] = peer_ip


                if user_data.get("connection_approval", "auto") == "manual":
                    requesting_username = display_name
                    pending_approvals[peer_ip] = {"username": username, "device_id": device_id, "websocket": websocket}
                    await message_queue.put({
                        "type": "approval_request",
                        "message": f"\nConnection request from {requesting_username}. Approve? (/approve {username} or /deny {username})"
                     })
                    logging.info(f"Incoming connection from {display_name} ({peer_ip}) requires manual approval.")
                    # Return False here, the /approve command will handle the rest
                    return False


                else: # Auto-approval
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
                    return True # Connection successful and handled


            else: # Received something other than HELLO first
                logging.warning(f"Invalid first message type '{message_type}' from {peer_ip}. Expected HELLO. Closing.")
                await websocket.close(code=1002, reason="Protocol violation: Expected HELLO")
                return False


        except json.JSONDecodeError:
            logging.warning(f"Invalid JSON in initial message from {peer_ip}. Closing connection.")
            await websocket.close(code=1003, reason="Invalid JSON in handshake")
            return False
        except KeyError as e:
            logging.warning(f"Malformed HELLO message from {peer_ip} (missing key: {e}). Closing.")
            await websocket.close(code=1003, reason=f"Malformed HELLO (missing {e})")
            return False
        except asyncio.TimeoutError:
             logging.warning(f"Timeout waiting for initial HELLO from {peer_ip}. Closing.")
             # Websocket might already be closed by library on timeout
             if websocket.state == State.OPEN:
                  await websocket.close(code=1008, reason="Handshake timeout")
             return False
        except Exception as e:
            logging.error(f"Error processing initial message from {peer_ip}: {e}")
            if websocket.state == State.OPEN:
                 await websocket.close(code=1011, reason="Internal server error during handshake")
            return False


    except websockets.exceptions.ConnectionClosed as e:
        logging.info(f"Connection from {peer_ip} closed during initial handshake. Code: {e.code}, Reason: {e.reason}")
        # Cleanup if info was partially added before close
        if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
        uname = next((u for u, ip in peer_usernames.items() if ip == peer_ip), None)
        if uname and uname in peer_usernames: del peer_usernames[uname]
        if peer_ip in peer_device_ids: del peer_device_ids[peer_ip]
        dname = next((d for d, ip in username_to_ip.items() if ip == peer_ip), None)
        if dname and dname in username_to_ip: del username_to_ip[dname]
        return False
    except Exception as e:
        logging.error(f"Unexpected error in handle_incoming_connection for {peer_ip}: {e}")
        if websocket.state == State.OPEN:
            await websocket.close(code=1011, reason="Internal server error during handling")
        return False


async def send_message_to_peers(message_text, target_ips=None):
    """Sends a signed message to specified target IPs or all connected peers."""
    success_count = 0
    total_targets = 0
    if shutdown_event.is_set():
        logging.warning("Shutdown in progress, cannot send message.")
        return False

    try:
        signature = user_data["private_key"].sign(
            message_text.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        logging.error(f"Failed to sign message: {e}")
        return False

    message_data_str = json.dumps({
        "type": "MESSAGE",
        "message": message_text,
        "signature": signature.hex()
    })

    target_peer_ips = []
    if target_ips is None:
        # Send to all connected peers (excluding self if connected)
        own_ip = await get_own_ip()
        target_peer_ips = [ip for ip in connections.keys() if ip != own_ip]
    elif isinstance(target_ips, str):
        # Send to a single IP
        target_peer_ips = [target_ips]
    elif isinstance(target_ips, list):
        # Send to a list of IPs
        target_peer_ips = target_ips
    else:
        logging.error(f"Invalid target type for send_message_to_peers: {type(target_ips)}")
        return False

    total_targets = len(target_peer_ips)
    if total_targets == 0:
        # Don't log error if target_ips was None (broadcast attempt with no peers)
        if target_ips is not None:
             logging.warning("No valid target IPs specified for message sending.")
        return False # No one to send to

    for peer_ip in target_peer_ips:
        websocket = connections.get(peer_ip)
        if websocket and websocket.state == State.OPEN:
            try:
                await websocket.send(message_data_str)
                success_count += 1
            except websockets.exceptions.ConnectionClosed:
                 logging.warning(f"Connection to {get_peer_display_name(peer_ip)} closed while trying to send message.")
                 # Trigger cleanup? receive_peer_messages should handle this.
            except Exception as e:
                 logging.error(f"Failed to send message to {get_peer_display_name(peer_ip)}: {e}")
        else:
            logging.warning(f"No active connection to {get_peer_display_name(peer_ip)} to send message.")

    return success_count > 0 # Return True if sent to at least one peer


async def maintain_peer_list(peer_discovery):
    """Keeps track of discovered peers and updates shared state."""
    while not shutdown_event.is_set():
        try:
            # Get snapshot of discovered peers from the discovery instance
            peers_from_discovery = list(peer_discovery.peer_list.items()) # Snapshot
            own_ip = await get_own_ip()

            current_discovered_usernames = set()

            for peer_ip, (username, last_seen) in peers_from_discovery:
                if peer_ip == own_ip:
                    continue

                current_discovered_usernames.add(username)

                # Update the mapping for discovered peers (username -> IP)
                # This is useful for /connect <username> even before connection
                if username not in discovered_peers_by_username or discovered_peers_by_username[username] != peer_ip:
                     logging.debug(f"Updating discovered_peers_by_username: {username} -> {peer_ip}")
                     discovered_peers_by_username[username] = peer_ip


            # Clean up stale entries from discovered_peers_by_username
            stale_usernames = [
                uname for uname in discovered_peers_by_username
                if uname not in current_discovered_usernames
            ]

            for uname in stale_usernames:
                 # Check if the peer is actually connected - if so, don't remove discovery mapping yet
                 peer_ip_check = discovered_peers_by_username.get(uname)
                 if peer_ip_check and peer_ip_check in connections:
                      continue # Peer is connected, keep the mapping for now

                 # If not connected and not in current discovery list, remove mapping
                 logging.debug(f"Removing stale entry from discovered_peers_by_username: {uname}")
                 del discovered_peers_by_username[uname]


            await asyncio.sleep(15) # Check discovery list periodically


        except asyncio.CancelledError:
             logging.info("maintain_peer_list task cancelled.")
             break
        except Exception as e:
            logging.error(f"Error in maintain_peer_list: {e}")
            logging.exception("Maintain peer list error details:")
            await asyncio.sleep(30) # Wait longer after an error


# send_file_chunks moved to networking/messaging/utils.py
# receive_peer_messages moved to networking/messaging/utils.py