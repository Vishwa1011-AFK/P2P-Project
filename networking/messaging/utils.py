import asyncio
import json
import os
import aiofiles
import websockets
import logging
import ipaddress
from websockets.connection import State
from appdirs import user_config_dir
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import sys # Added for sys.exit
from networking.shared_state import (
    connections, user_data, peer_usernames, peer_device_ids, peer_public_keys,
    shutdown_event, message_queue, active_transfers, completed_transfers,
    groups, pending_invites, pending_join_requests, username_to_ip,
    discovered_peers_by_username
)
from networking.file_transfer import FileTransfer, TransferState
from networking.messaging.helpers import get_peer_display_name, get_own_display_name, get_own_ip, get_peer_original_username
from networking.messaging.groups import send_group_update_message


async def resolve_peer_target(target_identifier):
    if not target_identifier:
         return None, "not_found"

    if target_identifier in groups:
        return list(groups[target_identifier].get("members", set())), "group"

    matches = []
    found_ips = set()
    is_ip = False
    try:
        ipaddress.ip_address(target_identifier)
        is_ip = True
        if target_identifier in connections:
            matches.append(target_identifier)
            found_ips.add(target_identifier)
        elif target_identifier in [ip for username, ip in discovered_peers_by_username.items()]:
             matches.append(target_identifier)
             found_ips.add(target_identifier)
    except ValueError:
        pass

    for display_name, peer_ip in username_to_ip.items():
        if target_identifier == display_name and peer_ip not in found_ips:
            if peer_ip in connections:
                matches.append(peer_ip)
                found_ips.add(peer_ip)

    for original_username, peer_ip in peer_usernames.items():
         if target_identifier == original_username and peer_ip not in found_ips:
             if peer_ip in connections:
                matches.append(peer_ip)
                found_ips.add(peer_ip)

    if not is_ip and target_identifier in discovered_peers_by_username:
        peer_ip = discovered_peers_by_username[target_identifier]
        if peer_ip not in found_ips and peer_ip not in connections:
            matches.append(peer_ip)
            found_ips.add(peer_ip)

    unique_matches = list(set(matches))

    if not unique_matches:
        if is_ip:
            return None, "not_found"
        else:
            return None, "not_found"
    elif len(unique_matches) == 1:
        return unique_matches[0], "found"
    else:
        ambiguous_names = sorted([get_peer_display_name(ip) for ip in unique_matches])
        return ambiguous_names, "ambiguous"


def get_config_directory():
    return user_config_dir("P2PChat", False)


async def initialize_user_config():
    from aioconsole import ainput # Import locally for setup
    config_dir = get_config_directory()
    os.makedirs(config_dir, exist_ok=True)
    logging.info(f"Using config directory: {config_dir}")

    keys_file = os.path.join(config_dir, "keys.json")
    loaded = False
    if os.path.exists(keys_file):
        try:
            with open(keys_file, "r") as f:
                data = json.load(f)
                user_data["original_username"] = data["username"]
                user_data["device_id"] = data["device_id"]
                user_data["private_key"] = serialization.load_pem_private_key(
                    data["private_key"].encode(), password=None
                )
                user_data["public_key"] = user_data["private_key"].public_key()
                user_data["banned_users"] = data.get("banned_users", [])
                stored_pub_key = serialization.load_pem_public_key(data["public_key"].encode())
                if stored_pub_key.public_numbers() != user_data["public_key"].public_numbers():
                     logging.warning("Stored public key does not match derived public key. Using derived key.")
                loaded = True
                print(f"Welcome back, {get_own_display_name()}!")
        except (json.JSONDecodeError, KeyError, FileNotFoundError, Exception) as e:
             logging.error(f"Failed to load existing configuration from {keys_file}: {e}")
             print(f"Error loading config file {keys_file}. A new one will be created.")
             try: os.rename(keys_file, keys_file + ".corrupted")
             except OSError: pass

    if not loaded:
        print("No valid configuration found. Let's set up your identity.")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        username = ""
        while not username:
             try:
                  username = (await ainput("Enter your desired username: ")).strip()
                  if not username: print("Username cannot be empty.")
             except EOFError:
                  print("\nExiting setup.")
                  sys.exit(1)

        device_id = os.urandom(16).hex()

        user_data["original_username"] = username
        user_data["device_id"] = device_id
        user_data["private_key"] = private_key
        user_data["public_key"] = public_key
        user_data["banned_users"] = []

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        try:
            with open(keys_file, "w") as f:
                json.dump({
                    "username": username,
                    "device_id": device_id,
                    "private_key": private_key_pem,
                    "public_key": public_key_pem,
                    "banned_users": []
                }, f, indent=4)
            print(f"Configuration saved. Your display name is: {get_own_display_name()}")
        except Exception as e:
             logging.critical(f"Failed to save new configuration file {keys_file}: {e}")
             print(f"CRITICAL ERROR: Could not save configuration. Exiting.")
             sys.exit(1)

    os.makedirs("downloads", exist_ok=True)


async def connect_to_peer(target_identifier, requesting_username):
    own_ip = await get_own_ip()
    resolved_result, status = await resolve_peer_target(target_identifier)

    if status == "not_found":
        await message_queue.put(f"No peer found matching '{target_identifier}'. Use /list to see discovered peers.")
        return
    elif status == "ambiguous":
        await message_queue.put(f"Multiple peers match '{target_identifier}': {', '.join(resolved_result)}. Please use a more specific identifier (e.g., display name with device ID or IP address).")
        return
    elif status == "group":
         await message_queue.put(f"Cannot directly connect to a group ('{target_identifier}').")
         return

    peer_ip = resolved_result

    if peer_ip == own_ip:
        await message_queue.put(f"Cannot connect to self ({target_identifier}).")
        return

    if peer_ip in connections:
        await message_queue.put(f"Already connected to {get_peer_display_name(peer_ip)}.")
        return

    if peer_ip in pending_approvals:
         await message_queue.put(f"Connection to {get_peer_display_name(peer_ip)} is already pending your approval.")
         return

    uri = f"ws://{peer_ip}:8765"
    display_target = get_peer_display_name(peer_ip) if (peer_ip in peer_device_ids or peer_ip in username_to_ip) else target_identifier
    logging.info(f"Attempting to connect to {display_target} ({peer_ip})...")
    await message_queue.put(f"Attempting to connect to {display_target} ({peer_ip})...")

    websocket = None
    try:
        async with asyncio.timeout(15):
             websocket = await websockets.connect(
                 uri,
                 ping_interval=20,
                 ping_timeout=20,
                 max_size=10 * 1024 * 1024,
                 open_timeout=10
                 )

        logging.info(f"WebSocket connection established to {peer_ip}, sending HELLO...")

        public_key_pem = user_data["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        hello_message = json.dumps({
            "type": "HELLO",
            "public_key": public_key_pem,
            "username": user_data["original_username"],
            "device_id": user_data["device_id"]
        })
        await websocket.send(hello_message)

        await receive_peer_messages(websocket, peer_ip)

    except asyncio.TimeoutError:
         await message_queue.put(f"Connection attempt to {display_target} ({peer_ip}) timed out.")
         logging.warning(f"Connection timeout for {peer_ip}.")
         if websocket and websocket.state == State.OPEN: await websocket.close()
    except (websockets.exceptions.WebSocketException, ConnectionRefusedError, OSError) as e:
        await message_queue.put(f"Failed to connect to {display_target} ({peer_ip}): {e}")
        logging.error(f"Connection failed for {peer_ip}: {e}")
    except Exception as e:
        await message_queue.put(f"Unexpected error connecting to {display_target} ({peer_ip}): {e}")
        logging.exception(f"Unexpected connection error for {peer_ip}:")
    finally:
        if peer_ip not in connections and websocket and not websocket.closed:
             logging.debug(f"Closing websocket manually in connect_to_peer finally block for {peer_ip}")
             await websocket.close()

        if peer_ip not in connections:
             if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
             uname = next((u for u, ip in peer_usernames.items() if ip == peer_ip), None)
             if uname: del peer_usernames[uname]
             if peer_ip in peer_device_ids: del peer_device_ids[peer_ip]
             dname = next((d for d, ip in username_to_ip.items() if ip == peer_ip), None)
             if dname: del username_to_ip[dname]


async def disconnect_from_peer(target_identifier):
    resolved_result, status = await resolve_peer_target(target_identifier)

    if status == "not_found":
        denied_ip = None
        if target_identifier in [data['username'] for data in pending_approvals.values()]:
             print(f"'{target_identifier}' is pending approval. Use /deny {target_identifier} instead.")
        else:
             print(f"No connected peer found matching '{target_identifier}'.")
        return
    elif status == "ambiguous":
        print(f"Multiple connected peers match '{target_identifier}': {', '.join(resolved_result)}. Please use a more specific identifier (e.g., display name with device ID or IP address).")
        return
    elif status == "group":
         print(f"Cannot disconnect from a group ('{target_identifier}'). Disconnect from individual members.")
         return

    peer_ip = resolved_result
    display_name = get_peer_display_name(peer_ip)
    websocket = connections.get(peer_ip)

    if websocket and not websocket.closed:
        logging.info(f"Disconnecting from {display_name} ({peer_ip})...")
        await message_queue.put(f"Disconnecting from {display_name}...")
        try:
            await websocket.close(code=1000, reason="User initiated disconnect")
        except Exception as e:
            logging.error(f"Error closing connection to {display_name}: {e}")
    else:
        await message_queue.put(f"Already disconnected from {display_name}.")

    if peer_ip in connections: del connections[peer_ip]
    if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
    if peer_ip in peer_device_ids: del peer_device_ids[peer_ip]
    uname = next((u for u, ip in peer_usernames.items() if ip == peer_ip), None)
    if uname and uname in peer_usernames: del peer_usernames[uname]
    dname = next((d for d, ip in username_to_ip.items() if ip == peer_ip), None)
    if dname and dname in username_to_ip: del username_to_ip[dname]


async def send_file_chunks(transfer, websocket):
    if not transfer or transfer.state != TransferState.IN_PROGRESS:
         logging.warning(f"send_file_chunks called for transfer {transfer.transfer_id} not in IN_PROGRESS state.")
         return

    peer_ip = transfer.peer_ip # For logging context
    peer_display = get_peer_display_name(peer_ip)
    file_basename = os.path.basename(transfer.file_path)
    logging.info(f"Starting chunk send for '{file_basename}' ({transfer.transfer_id[:8]}) to {peer_display}")

    try:
        # Start reading from the beginning (or resume point if pause/resume implemented seeking)
        # Simple resume implementation reads from beginning until transferred_size reached
        # More robust would store file handle offset, but requires careful state management.
        current_pos = 0
        if transfer.transferred_size > 0:
             logging.info(f"Resuming send for {transfer.transfer_id[:8]} from byte {transfer.transferred_size}")
             # Note: Simple resume reads through skipped chunks, could be optimized with seek
             current_pos = transfer.transferred_size # Set initial read position for resume


        async with aiofiles.open(transfer.file_path, "rb") as f:
             # If resuming, seek to the correct position (more efficient than reading through)
             if current_pos > 0:
                  await f.seek(current_pos)

             while transfer.state == TransferState.IN_PROGRESS:
                 if websocket.closed:
                      logging.warning(f"Websocket closed during file send for {transfer.transfer_id[:8]} to {peer_display}")
                      transfer.state = TransferState.FAILED # Mark as failed
                      break

                 chunk = await f.read(1024 * 1024) # 1MB chunk
                 if not chunk:
                      # End of file reached
                      if transfer.transferred_size >= transfer.total_size:
                           transfer.state = TransferState.COMPLETED
                           logging.info(f"Finished sending '{file_basename}' ({transfer.transfer_id[:8]}) to {peer_display}")
                           # Notify completion? maybe implicitly handled by receiver
                      else:
                           logging.error(f"EOF reached for {transfer.transfer_id[:8]} but size mismatch: {transfer.transferred_size}/{transfer.total_size}")
                           transfer.state = TransferState.FAILED
                      break # Exit while loop

                 chunk_hex = chunk.hex()
                 data_packet = json.dumps({
                      "type": "FILE_DATA",
                      "transfer_id": transfer.transfer_id,
                      "chunk": chunk_hex
                 })

                 try:
                      await websocket.send(data_packet)
                      transfer.transferred_size += len(chunk)
                      # Optional: Add slight delay to prevent overwhelming receiver/network
                      # await asyncio.sleep(0.001)
                 except websockets.exceptions.ConnectionClosed:
                      logging.warning(f"Connection closed while sending chunk for {transfer.transfer_id[:8]}")
                      transfer.state = TransferState.FAILED
                      break # Exit while loop
                 except Exception as send_err:
                      logging.error(f"Error sending chunk for {transfer.transfer_id[:8]}: {send_err}")
                      transfer.state = TransferState.FAILED
                      break


    except FileNotFoundError:
        logging.error(f"File not found during send operation: {transfer.file_path} (ID: {transfer.transfer_id[:8]})")
        transfer.state = TransferState.FAILED
        # Try to notify peer of failure?
        if websocket and not websocket.closed:
            try: await websocket.send(json.dumps({"type": "TRANSFER_ERROR", "transfer_id": transfer.transfer_id, "reason": "Sender file not found"}))
            except: pass # Best effort notification
    except Exception as e:
        logging.exception(f"Unexpected error sending file chunks for {transfer.transfer_id[:8]}: {e}")
        transfer.state = TransferState.FAILED
        if websocket and not websocket.closed:
             try: await websocket.send(json.dumps({"type": "TRANSFER_ERROR", "transfer_id": transfer.transfer_id, "reason": f"Sender error: {e}"}))
             except: pass


    # Final state update after loop/error handling
    if transfer.state != TransferState.IN_PROGRESS: # If state changed from IN_PROGRESS
         if transfer.state == TransferState.COMPLETED:
              msg = f"Sent '{file_basename}' to {peer_display}."
              completed_transfers[transfer.transfer_id] = {
                   "direction": "send", "file_path": transfer.file_path,
                   "total_size": transfer.total_size, "transferred_size": transfer.transferred_size,
                   "state": transfer.state.value, "peer_ip": peer_ip
              }
         else: # FAILED or PAUSED (if pause happened during send)
              msg = f"Failed to send '{file_basename}' to {peer_display}. State: {transfer.state.value}"
              # Keep in active if paused, otherwise move to completed/failed
              if transfer.state == TransferState.FAILED:
                   completed_transfers[transfer.transfer_id] = {
                        "direction": "send", "file_path": transfer.file_path,
                        "total_size": transfer.total_size, "transferred_size": transfer.transferred_size,
                        "state": transfer.state.value, "peer_ip": peer_ip
                   }

         # Remove from active only if completed or failed
         if transfer.state != TransferState.PAUSED:
              if transfer.transfer_id in active_transfers:
                   del active_transfers[transfer.transfer_id]

         await message_queue.put(msg)


async def receive_peer_messages(websocket, peer_ip):
    is_connection_established = False
    sender_display_name = f"peer({peer_ip})"
    current_transfer_file_handle = None # Store handle here if needed across iterations
    folder_transfers = {} # Track files within a folder transfer {folder_id: [transfer_ids]}


    try:
        async for message in websocket:
            if shutdown_event.is_set():
                break

            try:
                data = json.loads(message)
                message_type = data.get("type")
                timestamp = asyncio.get_event_loop().time()

                logging.debug(f"Received msg type '{message_type}' from {peer_ip}")

                if message_type == "HELLO":
                     public_key_pem = bytes.fromhex(data["public_key"])
                     public_key = serialization.load_pem_public_key(public_key_pem)
                     username = data["username"]
                     device_id = data["device_id"]
                     received_display_name = f"{username}({device_id[:8]})" if device_id else username

                     if "banned_users" in user_data and username in user_data["banned_users"]:
                         logging.warning(f"Received HELLO from banned user {username} ({peer_ip}) after connection attempt. Closing.")
                         await websocket.close(code=1008, reason="User is banned")
                         break

                     if not is_connection_established:
                          peer_public_keys[peer_ip] = public_key
                          peer_usernames[username] = peer_ip
                          peer_device_ids[peer_ip] = device_id
                          username_to_ip[received_display_name] = peer_ip
                          connections[peer_ip] = websocket

                          sender_display_name = received_display_name
                          is_connection_established = True
                          await message_queue.put(f"Successfully connected to {sender_display_name}")
                          logging.info(f"Handshake complete with {sender_display_name} ({peer_ip}).")
                     else:
                           logging.warning(f"Received unexpected subsequent HELLO from {sender_display_name} ({peer_ip}). Ignoring.")
                     continue

                if not is_connection_established:
                     logging.warning(f"Received message type '{message_type}' from {peer_ip} before HELLO handshake completed. Ignoring.")
                     continue

                if message_type == "MESSAGE":
                    signature_hex = data["signature"]
                    message_content = data["message"]
                    sender_public_key = peer_public_keys.get(peer_ip)

                    if not sender_public_key:
                        logging.warning(f"No public key found for {sender_display_name} ({peer_ip}). Dropping message.")
                        continue

                    try:
                        signature = bytes.fromhex(signature_hex)
                        sender_public_key.verify(
                            signature,
                            message_content.encode('utf-8'),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        await message_queue.put(f"{sender_display_name}: {message_content}")
                    except InvalidSignature:
                         logging.warning(f"Invalid message signature from {sender_display_name} ({peer_ip}). Message dropped.")
                    except Exception as e:
                         logging.error(f"Error verifying message signature from {sender_display_name}: {e}")
                    continue # End MESSAGE processing

                elif message_type == "FILE_TRANSFER":
                    transfer_id = data["transfer_id"]
                    relative_file_path = data["file_path"] # Expecting relative path from sender
                    total_size = data["file_size"]
                    folder_id = data.get("folder_id") # Optional

                    if transfer_id in active_transfers or transfer_id in completed_transfers:
                         logging.warning(f"Received duplicate file transfer request ID {transfer_id[:8]} from {sender_display_name}. Ignoring.")
                         continue

                    # Construct initial FileTransfer object
                    file_transfer = FileTransfer(peer_ip, "receive", relative_file_path, total_size, transfer_id, folder_id=folder_id)
                    active_transfers[transfer_id] = file_transfer # Add to active transfers in PENDING state

                    # Store in folder tracking if needed
                    if folder_id:
                        folder_transfers.setdefault(folder_id, []).append(transfer_id)

                    # Notify user for approval
                    file_basename = os.path.basename(relative_file_path)
                    approval_msg = {
                         "type": "file_transfer_approval", # Specific type for display handling
                         "message": f"\nIncoming file transfer request: '{file_basename}' ({total_size / (1024 * 1024):.2f} MB) from {sender_display_name}.\nAccept? (/accept_file {transfer_id[:8]} or /deny_file {transfer_id[:8]})"
                     }
                    await message_queue.put(approval_msg)
                    continue # End FILE_TRANSFER processing

                elif message_type == "FILE_TRANSFER_RESPONSE":
                    transfer_id = data["transfer_id"]
                    approved = data["approved"]
                    transfer = active_transfers.get(transfer_id)

                    if transfer and transfer.direction == "send":
                         if approved:
                             if transfer.state == TransferState.PENDING:
                                  transfer.state = TransferState.IN_PROGRESS
                                  await message_queue.put(f"Transfer {transfer_id[:8]} approved by {sender_display_name}. Sending...")
                                  # Start sending chunks in a background task
                                  asyncio.create_task(send_file_chunks(transfer, websocket))
                             else:
                                  logging.warning(f"Received approval for already active/completed transfer {transfer_id[:8]}. Ignoring.")
                         else:
                              transfer.state = TransferState.FAILED
                              # Move to completed/failed transfers
                              file_basename = os.path.basename(transfer.file_path)
                              completed_transfers[transfer_id] = {
                                   "direction": "send", "file_path": transfer.file_path,
                                   "total_size": transfer.total_size, "transferred_size": 0,
                                   "state": transfer.state.value, "peer_ip": peer_ip
                                   }
                              del active_transfers[transfer_id]
                              await message_queue.put(f"File transfer '{file_basename}' ({transfer_id[:8]}) was denied by {sender_display_name}.")
                    else:
                         logging.warning(f"Received FILE_TRANSFER_RESPONSE for unknown or non-sending transfer ID: {transfer_id[:8]}")
                    continue # End FILE_TRANSFER_RESPONSE processing

                elif message_type == "FILE_DATA":
                     transfer_id = data["transfer_id"]
                     chunk_hex = data["chunk"]
                     transfer = active_transfers.get(transfer_id)

                     if not transfer or transfer.direction != "receive":
                          logging.warning(f"Received FILE_DATA for unknown or non-receiving transfer ID: {transfer_id[:8]}")
                          continue

                     if transfer.state == TransferState.PAUSED:
                          logging.debug(f"Received FILE_DATA for paused transfer {transfer_id[:8]}. Ignoring chunk.")
                          continue
                     elif transfer.state != TransferState.IN_PROGRESS:
                          logging.warning(f"Received FILE_DATA for transfer {transfer_id[:8]} not in IN_PROGRESS state ({transfer.state.value}). Ignoring chunk.")
                          continue

                     if not transfer.file_handle or transfer.file_handle.closed:
                           logging.error(f"File handle not open or closed for receiving transfer {transfer_id[:8]}. Cannot write chunk.")
                           transfer.state = TransferState.FAILED # Mark as failed
                           # Attempt to notify sender?
                           # Cleanup handled below state change check
                     else:
                          try:
                              chunk_bytes = bytes.fromhex(chunk_hex)
                              await transfer.file_handle.write(chunk_bytes)
                              transfer.transferred_size += len(chunk_bytes)
                              # Check for completion
                              if transfer.transferred_size >= transfer.total_size:
                                   await transfer.file_handle.close()
                                   transfer.file_handle = None
                                   transfer.state = TransferState.COMPLETED
                                   logging.info(f"Finished receiving file for transfer {transfer_id[:8]}")
                          except Exception as write_err:
                               logging.error(f"Error writing chunk for transfer {transfer_id[:8]}: {write_err}")
                               transfer.state = TransferState.FAILED
                               if transfer.file_handle and not transfer.file_handle.closed:
                                    await transfer.file_handle.close()
                               transfer.file_handle = None


                     # Handle state change (COMPLETED or FAILED)
                     if transfer.state != TransferState.IN_PROGRESS:
                          file_basename = os.path.basename(transfer.file_path)
                          completed_transfers[transfer.transfer_id] = {
                               "direction": "receive", "file_path": transfer.file_path,
                               "total_size": transfer.total_size, "transferred_size": transfer.transferred_size,
                               "state": transfer.state.value, "peer_ip": peer_ip
                          }
                          msg = f"Received '{file_basename}' from {sender_display_name}." if transfer.state == TransferState.COMPLETED else f"Failed to receive '{file_basename}' from {sender_display_name}."
                          del active_transfers[transfer_id]
                          await message_queue.put(msg)

                          # Folder completion check
                          folder_id = transfer.folder_id
                          if folder_id and folder_id in folder_transfers:
                               if transfer_id in folder_transfers[folder_id]:
                                    folder_transfers[folder_id].remove(transfer_id)
                                    if not folder_transfers[folder_id]: # Last file in folder done?
                                         del folder_transfers[folder_id]
                                         await message_queue.put(f"Folder transfer (ID: {folder_id[:8]}) from {sender_display_name} completed.")

                     continue # End FILE_DATA processing

                elif message_type == "TRANSFER_PAUSE":
                    transfer_id = data["transfer_id"]
                    transfer = active_transfers.get(transfer_id)
                    if transfer and transfer.state == TransferState.IN_PROGRESS:
                        # Paused by peer (sender_display_name)
                        await transfer.pause(peer_ip) # Record initiator as the peer
                        await message_queue.put(f"Transfer {transfer_id[:8]} paused by {sender_display_name}.")
                    else:
                         logging.warning(f"Received TRANSFER_PAUSE for invalid/unknown transfer {transfer_id[:8]}")
                    continue

                elif message_type == "TRANSFER_RESUME":
                     transfer_id = data["transfer_id"]
                     transfer = active_transfers.get(transfer_id)
                     if transfer and transfer.state == TransferState.PAUSED:
                          # Resumed by peer (sender_display_name)
                          if transfer.initiator == peer_ip: # Check if the pauser is resuming
                               await transfer.resume(peer_ip)
                               await message_queue.put(f"Transfer {transfer_id[:8]} resumed by {sender_display_name}.")
                               # If we were sending, restart the send task
                               if transfer.direction == "send":
                                    asyncio.create_task(send_file_chunks(transfer, websocket))
                          else:
                               my_ip = await get_own_ip()
                               logging.warning(f"Peer {sender_display_name} tried to resume transfer {transfer_id[:8]} paused by {get_peer_display_name(transfer.initiator) if transfer.initiator != my_ip else 'you'}")
                     else:
                          logging.warning(f"Received TRANSFER_RESUME for invalid/unknown transfer {transfer_id[:8]}")
                     continue


                elif message_type == "GROUP_CREATE":
                    groupname = data["groupname"]
                    admin_ip = data["admin_ip"]
                    if groupname not in groups:
                         groups[groupname] = {"admin": admin_ip, "members": {admin_ip}}
                         await message_queue.put(f"Group '{groupname}' created by {get_peer_display_name(admin_ip)}.")
                    else:
                         logging.warning(f"Received duplicate GROUP_CREATE for '{groupname}'.")
                    continue

                elif message_type == "GROUP_INVITE":
                    groupname = data["groupname"]
                    inviter_ip = data["inviter_ip"]
                    own_ip = await get_own_ip()
                    # Add invite to own pending list
                    pending_invites.setdefault(own_ip, set()).add((groupname, inviter_ip))
                    await message_queue.put(f"\n{get_peer_display_name(inviter_ip)} invited you to join group '{groupname}'.\nAccept? (/accept_invite {groupname} or /decline_invite {groupname})")
                    continue

                elif message_type == "GROUP_INVITE_RESPONSE":
                    groupname = data["groupname"]
                    invitee_ip = data["invitee_ip"]
                    invitee_display_name = data.get("invitee_display_name", get_peer_display_name(invitee_ip)) # Use included name or lookup
                    accepted = data["accepted"]
                    own_ip = await get_own_ip()

                    # This message is received by the admin who sent the invite
                    if groupname in groups and groups[groupname]["admin"] == own_ip:
                         # Remove from admin's tracking of pending invites for the invitee (optional tracking)
                         # pending_invites.setdefault(invitee_ip, set()).discard((groupname, own_ip))

                         if accepted:
                              # Add invitee to group members
                              groups[groupname]["members"].add(invitee_ip)
                              # Send update to all members (including new one)
                              await send_group_update_message(groupname, groups[groupname]["members"])
                              await message_queue.put(f"{invitee_display_name} accepted invite and joined '{groupname}'.")
                         else:
                              await message_queue.put(f"{invitee_display_name} declined invite to '{groupname}'.")
                    else:
                         logging.warning(f"Received GROUP_INVITE_RESPONSE for group '{groupname}' but not the admin, or group doesn't exist locally.")
                    continue


                elif message_type == "GROUP_JOIN_REQUEST":
                    groupname = data["groupname"]
                    requester_ip = data["requester_ip"]
                    requester_username = data["requester_username"]
                    own_ip = await get_own_ip()

                    # Received by the potential admin
                    if groupname in groups and groups[groupname]["admin"] == own_ip:
                        # Check if already pending or already a member
                        is_member = requester_ip in groups[groupname]["members"]
                        is_pending = any(req["ip"] == requester_ip for req in pending_join_requests.get(groupname, []))

                        if is_member:
                             logging.info(f"User {requester_username} requested to join '{groupname}' but is already a member.")
                             # Optionally notify requester they are already in?
                        elif is_pending:
                             logging.info(f"User {requester_username} requested to join '{groupname}' again (already pending).")
                        else:
                             pending_join_requests.setdefault(groupname, []).append({"username": requester_username, "ip": requester_ip})
                             await message_queue.put(f"\n{requester_username} requests to join group '{groupname}'.\nApprove? (/approve_join {groupname} {requester_username} or /deny_join {groupname} {requester_username})")
                    else:
                         logging.warning(f"Received join request for '{groupname}' but not the admin or group unknown.")
                    continue

                elif message_type == "GROUP_JOIN_RESPONSE":
                     groupname = data["groupname"]
                     requester_ip = data["requester_ip"] # The IP of the user who requested to join
                     approved = data["approved"]
                     admin_ip = data.get("admin_ip", "unknown admin") # Admin who responded
                     own_ip = await get_own_ip()

                     # Received by the user who sent the join request
                     if requester_ip == own_ip:
                          if approved:
                               # Admin approved, but wait for GROUP_UPDATE to confirm membership locally
                               await message_queue.put(f"Your request to join '{groupname}' was approved by {get_peer_display_name(admin_ip)}. Waiting for group update...")
                          else:
                               await message_queue.put(f"Your request to join '{groupname}' was denied by {get_peer_display_name(admin_ip)}.")
                     else:
                          logging.warning(f"Received GROUP_JOIN_RESPONSE not intended for me (for {get_peer_display_name(requester_ip)}).")
                     continue

                elif message_type == "GROUP_UPDATE":
                    groupname = data["groupname"]
                    admin_ip = data["admin_ip"]
                    members_ips = set(data["members"]) # Should be a list of IPs
                    own_ip = await get_own_ip()

                    if own_ip not in members_ips:
                         # We are not (or no longer) part of this group
                         if groupname in groups:
                              del groups[groupname]
                              # Clean up pending invites/requests related to this group?
                              if own_ip in pending_invites:
                                   pending_invites[own_ip] = {(g, inv) for g, inv in pending_invites[own_ip] if g != groupname}
                                   if not pending_invites[own_ip]: del pending_invites[own_ip]
                              await message_queue.put(f"You have been removed from group '{groupname}'.")
                    else:
                         # Update local group state
                         if groupname not in groups:
                               await message_queue.put(f"Joined group '{groupname}' (Admin: {get_peer_display_name(admin_ip)}).")
                         groups[groupname] = {"admin": admin_ip, "members": members_ips}
                         member_names = sorted([get_peer_display_name(ip) for ip in members_ips])
                         await message_queue.put(f"Group '{groupname}' updated. Members: {', '.join(member_names)}")

                    continue

                # --- TRANSFER ERROR Handling ---
                elif message_type == "TRANSFER_ERROR":
                     transfer_id = data.get("transfer_id")
                     reason = data.get("reason", "Unknown error")
                     transfer = active_transfers.get(transfer_id)
                     if transfer:
                          logging.error(f"Received error for transfer {transfer_id[:8]} from {sender_display_name}: {reason}")
                          await message_queue.put(f"Transfer {transfer_id[:8]} failed: Peer reported error: {reason}")
                          transfer.state = TransferState.FAILED
                          # Clean up handles if necessary
                          if transfer.direction == "receive" and transfer.file_handle and not transfer.file_handle.closed:
                               await transfer.file_handle.close()
                               transfer.file_handle = None
                          # Move to completed/failed and remove from active
                          completed_transfers[transfer_id] = {
                               "direction": transfer.direction, "file_path": transfer.file_path,
                               "total_size": transfer.total_size, "transferred_size": transfer.transferred_size,
                               "state": transfer.state.value, "peer_ip": peer_ip
                          }
                          del active_transfers[transfer_id]
                     else:
                          logging.warning(f"Received TRANSFER_ERROR for unknown transfer ID: {transfer_id}")
                     continue

                # --- Unknown message type ---
                else:
                    logging.warning(f"Received unknown message type '{message_type}' from {sender_display_name} ({peer_ip}).")
                    # await message_queue.put(f"Received unhandled message type '{message_type}' from {sender_display_name}.")


            except json.JSONDecodeError:
                # Handle non-JSON message (e.g., simple string) - maybe basic chat?
                # This requires a decision: strictly JSON or allow plain text?
                # If allowing plain text, requires signature check too.
                # For now, assume JSON protocol and log warning.
                logging.warning(f"Received non-JSON message from {sender_display_name} ({peer_ip}): {message}")
                # await message_queue.put(f"{sender_display_name} (raw): {message}") # If want to display raw
            except Exception as e:
                logging.exception(f"Error processing message from {sender_display_name} ({peer_ip}): {e}")
                # await message_queue.put(f"Error handling message from {sender_display_name}: {e}")


    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"Connection closed normally with {sender_display_name} ({peer_ip})")
    except websockets.exceptions.ConnectionClosedError as e:
        logging.warning(f"Connection closed with error for {sender_display_name} ({peer_ip}). Code: {e.code}, Reason: {e.reason}")
    except asyncio.CancelledError:
        logging.info(f"Receive task cancelled for {sender_display_name} ({peer_ip}).")
        # Ensure connection is closed if task is cancelled externally
        if websocket.state == State.OPEN:
            await websocket.close(code=1001, reason="Receive task cancelled")
    except Exception as e:
        logging.exception(f"Unexpected error in receive loop for {sender_display_name} ({peer_ip}): {e}")
        if websocket.state == State.OPEN:
             await websocket.close(code=1011, reason=f"Internal server error: {e}")


    finally:
        logging.debug(f"Cleaning up connection state for {sender_display_name} ({peer_ip})")

        # --- Cleanup Transfers ---
        active_transfer_ids_for_peer = [
             tid for tid, t in list(active_transfers.items()) if t.peer_ip == peer_ip
        ]
        for transfer_id in active_transfer_ids_for_peer:
             transfer = active_transfers[transfer_id]
             logging.warning(f"Marking active transfer {transfer_id[:8]} ({transfer.state.value}) with {sender_display_name} as FAILED due to disconnect.")
             transfer.state = TransferState.FAILED
             if transfer.file_handle and not transfer.file_handle.closed:
                  try: await transfer.file_handle.close()
                  except Exception as close_err: logging.error(f"Error closing file handle for failed transfer {transfer_id[:8]}: {close_err}")
             transfer.file_handle = None
             # Move to completed/failed list
             completed_transfers[transfer_id] = {
                   "direction": transfer.direction, "file_path": transfer.file_path,
                   "total_size": transfer.total_size, "transferred_size": transfer.transferred_size,
                   "state": transfer.state.value, "peer_ip": peer_ip
              }
             del active_transfers[transfer_id]
             await message_queue.put(f"Transfer {transfer_id[:8]} failed due to peer disconnect.")


        # --- Cleanup Connection State ---
        if peer_ip in connections: del connections[peer_ip]
        if peer_ip in peer_public_keys: del peer_public_keys[peer_ip]
        original_username = get_peer_original_username(peer_ip) # Get username before removing mapping
        if original_username and original_username in peer_usernames: del peer_usernames[original_username]
        if peer_ip in peer_device_ids: del peer_device_ids[peer_ip]
        # Remove display name mapping too
        display_name_to_remove = None
        for d_name, ip_addr in list(username_to_ip.items()):
             if ip_addr == peer_ip:
                  display_name_to_remove = d_name
                  break
        if display_name_to_remove and display_name_to_remove in username_to_ip:
             del username_to_ip[display_name_to_remove]


        # --- Cleanup Groups ---
        own_ip = await get_own_ip()
        groups_to_update = set()
        for groupname in list(groups.keys()):
            group_data = groups[groupname]
            if peer_ip in group_data.get("members", set()):
                 logging.info(f"Removing disconnected peer {sender_display_name} from group '{groupname}'")
                 group_data["members"].remove(peer_ip)
                 if group_data["admin"] == peer_ip:
                      # Admin disconnected! Handle promotion or dissolution?
                      # Simple approach: If members remain, promote first remaining member? Or dissolve?
                      # For now, let's just mark admin as None or remove group if empty
                      if group_data["members"]:
                            logging.warning(f"Admin {sender_display_name} of group '{groupname}' disconnected.")
                            # Elect new admin? For now, just remove admin status
                            groups[groupname]["admin"] = None # Or maybe random.choice(list(members)) ?
                            groups_to_update.add(groupname)
                            await message_queue.put(f"Admin of group '{groupname}' disconnected.")
                      else:
                            del groups[groupname]
                            logging.info(f"Group '{groupname}' removed as last member (admin) disconnected.")
                            await message_queue.put(f"Group '{groupname}' removed (last member disconnected).")
                            # No update needed if group deleted
                 elif group_data["members"]:
                       # A regular member disconnected, update if admin is still connected
                       groups_to_update.add(groupname)
                 else:
                       # Last member (not admin) disconnected
                       logging.info(f"Group '{groupname}' is now empty, removing.")
                       del groups[groupname]
                       await message_queue.put(f"Group '{groupname}' removed (last member disconnected).")
                       # No update needed if group deleted

        # Send updates for modified groups
        for groupname in groups_to_update:
             if groupname in groups: # Check if group still exists
                 # Check if anyone (admin or member) is still connected to send update
                 if groups[groupname]["admin"] in connections or any(m in connections for m in groups[groupname]["members"]):
                      asyncio.create_task(send_group_update_message(groupname, groups[groupname]["members"]))


        # --- Cleanup Pending Invites/Requests involving the disconnected peer ---
        # Invites sent *by* the disconnected peer
        for target_ip, invites in list(pending_invites.items()):
             invites_to_remove = {(g, inv) for g, inv in invites if inv == peer_ip}
             invites -= invites_to_remove # Remove in place
             if not invites: # Remove key if set becomes empty
                  del pending_invites[target_ip]

        # Invites sent *to* the disconnected peer
        if peer_ip in pending_invites:
             del pending_invites[peer_ip]

        # Join requests sent *by* the disconnected peer
        for groupname, requests in list(pending_join_requests.items()):
             requests[:] = [req for req in requests if req["ip"] != peer_ip] # Filter list in place
             if not requests: # Remove key if list becomes empty
                  del pending_join_requests[groupname]


        # Notify user of disconnection
        await message_queue.put(f"Disconnected from {sender_display_name}")

        # Ensure websocket is closed
        if websocket and not websocket.closed:
             await websocket.close(code=1000, reason="Cleanup")