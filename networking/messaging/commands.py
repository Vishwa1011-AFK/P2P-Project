import asyncio
import json
import os
import logging
import ipaddress
from aioconsole import ainput
from websockets.connection import State
from networking.shared_state import (
    connections, message_queue, active_transfers, user_data, peer_public_keys,
    peer_usernames, peer_device_ids, shutdown_event, groups, pending_invites,
    pending_join_requests, pending_approvals, username_to_ip, completed_transfers,
    discovered_peers_by_username # Added
)
from networking.messaging.core import send_message_to_peers # Assuming this stays
from networking.messaging.groups import (
    send_group_create_message, send_group_invite_message, send_group_invite_response,
    send_group_join_request, send_group_join_response, send_group_update_message
)
from networking.messaging.utils import (
    get_peer_display_name, get_own_display_name, resolve_peer_target,
    get_config_directory, initialize_user_config, connect_to_peer, disconnect_from_peer, get_own_ip,
    receive_peer_messages # Import receive_peer_messages
)
from networking.file_transfer import request_file_transfer, TransferState, FileTransfer # Adjusted import
from cryptography.hazmat.primitives import serialization
from .helpers import get_own_display_name # Import serialization


async def user_input(discovery):
    await asyncio.sleep(1)
    my_display_name = get_own_display_name()

    while not shutdown_event.is_set():
        try:
            prompt = f"{my_display_name} > "
            message = (await ainput(prompt)).strip()

            if not message:
                continue

            if message == "/exit":
                print("Shutting down...")
                shutdown_event.set()
                # Main loop's finally block will handle connection closing and task cancellation
                break # Exit the user input loop

            if message == "/help":
                print("\nAvailable commands:")
                print("  /exit                       - Shut down the application")
                print("  /connect <id>               - Connect to a peer by display name, username, or IP")
                print("  /disconnect <id>            - Disconnect from a peer by display name, username, or IP")
                print("  /peers                      - List connected peers")
                print("  /list                       - List all known peers (connected & discovered)")
                print("  /msg <id_or_group> <message> - Send a message to a peer or group")
                print("  /send <id_or_group> <path>  - Send a file/folder to a peer or group")
                print("  /accept_file <transfer_id>  - Accept a file transfer request")
                print("  /deny_file <transfer_id>    - Deny a file transfer request")
                print("  /transfers                  - Show active and recent transfers")
                print("  /pause <transfer_id_prefix> - Pause an active transfer")
                print("  /resume <transfer_id_prefix>- Resume a paused transfer")
                print("  /group_create <groupname>   - Create a new group (you become admin)")
                print("  /group_invite <group> <id>  - Invite a peer to a group (admin only)")
                print("  /accept_invite <groupname>  - Accept a group invite")
                print("  /decline_invite <groupname> - Decline a group invite")
                print("  /group_join <group> <admin_id> - Request to join a group")
                print("  /approve_join <group> <user> - Approve a join request (admin only)")
                print("  /deny_join <group> <user>    - Deny a join request (admin only)")
                print("  /group_members <groupname>  - List members of a group")
                print("  /approve <username>         - Approve a pending connection request")
                print("  /deny <username>            - Deny a pending connection request")
                print("  /pending                    - List pending connection requests")
                print("  /ban <username>             - Ban a user (prevents future connections)")
                print("  /unban <username>           - Unban a user")
                print("  /banned                     - List banned users")
                print("  <message>                   - Send message to all connected peers (default)")
                print("Note: <id> can be username, display name (username(devID)), or IP address.")
                print("Note: <transfer_id> can often be a unique prefix.")
                continue

            if message.startswith("/connect "):
                target_identifier = message[len("/connect "):].strip()
                if not target_identifier:
                     print("Usage: /connect <display_name_or_username_or_ip>")
                     continue
                # connect_to_peer now handles resolution and connection attempt logging
                asyncio.create_task(connect_to_peer(target_identifier, user_data.get("original_username", "unknown")))
                continue

            if message.startswith("/disconnect "):
                identifier = message[len("/disconnect "):].strip()
                if not identifier:
                    print("Usage: /disconnect <display_name_or_username_or_ip>")
                    continue
                await disconnect_from_peer(identifier)
                continue

            if message == "/peers":
                own_ip = await get_own_ip()
                connected_peer_ips = set(connections.keys())
                # Remove self if somehow listed (shouldn't happen with ws server logic)
                connected_peer_ips.discard(own_ip)

                if not connected_peer_ips:
                    print("\nNo peers currently connected.")
                else:
                    print("\nConnected peers:")
                    sorted_peers = sorted(list(connected_peer_ips), key=get_peer_display_name)
                    for peer_ip in sorted_peers:
                        display_name = get_peer_display_name(peer_ip)
                        print(f"- {display_name} ({peer_ip})")
                continue

            if message == "/list":
                own_ip = await get_own_ip()
                own_display_name = get_own_display_name()
                print("\nKnown peers in the network:")
                print(f"- {own_display_name} ({own_ip}) (self)")

                connected_peer_ips = set(connections.keys())
                connected_peer_ips.discard(own_ip)

                if connected_peer_ips:
                    print("\nConnected peers:")
                    sorted_connected = sorted([ip for ip in connected_peer_ips], key=get_peer_display_name)
                    for peer_ip in sorted_connected:
                        display_name = get_peer_display_name(peer_ip)
                        print(f"- {display_name} ({peer_ip})")

                discovered_peers_output = []
                discovered_ips = set()
                # Use discovery.peer_list which has freshest data
                current_discovered = list(discovery.peer_list.items()) # Get snapshot
                for peer_ip, (username, _) in current_discovered:
                     if peer_ip not in connected_peer_ips and peer_ip != own_ip:
                          display_name = get_peer_display_name(peer_ip) # Use helper which formats known peers
                          discovered_peers_output.append(f"- {display_name} ({peer_ip}) (discovered)")
                          discovered_ips.add(peer_ip)


                if discovered_peers_output:
                     print("\nDiscovered peers (not connected):")
                     discovered_peers_output.sort()
                     for line in discovered_peers_output:
                          print(line)

                if not connected_peer_ips and not discovered_peers_output:
                    print("\nNo other peers detected.")

                continue

            if message == "/pending":
                 if not pending_approvals:
                      print("\nNo pending connection requests.")
                 else:
                      print("\nPending connection requests:")
                      for peer_ip, data in pending_approvals.items():
                           # Construct display name for pending request
                            pending_display_name = f"{data['username']}({data.get('device_id', 'unknown')[:8]})"
                            print(f"- {pending_display_name} (Username: {data['username']})")
                 continue

            if message.startswith("/approve "):
                 username_part = message[len("/approve "):].strip()
                 approved_ip = None
                 for peer_ip, approval_data in list(pending_approvals.items()):
                     # Match against original username primarily
                     if approval_data["username"] == username_part:
                         approved_ip = peer_ip
                         break
                     # Fallback: match against display name if username match fails
                     pending_display_name = f"{approval_data['username']}({approval_data.get('device_id', 'unknown')[:8]})"
                     if pending_display_name == username_part:
                         approved_ip = peer_ip
                         break


                 if approved_ip:
                     approval_data = pending_approvals[approved_ip]
                     websocket = approval_data["websocket"]
                     display_name = f"{approval_data['username']}({approval_data['device_id'][:8]})"

                     # Move websocket to main connections dict
                     connections[approved_ip] = websocket
                     # Public key, username, device ID should have been stored during HELLO
                     # Let's assume they were temporarily stored if needed or rely on handle_incoming storing them
                     # Ensure they are correctly populated now for get_peer_display_name etc.
                     # (handle_incoming_connection should already populate these before hitting manual approval)

                     print(f"Approving connection from {display_name}...")

                     # Send HELLO back to confirm approval
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
                     try:
                         await websocket.send(hello_back)
                         # Start listening for messages now that connection is approved
                         asyncio.create_task(receive_peer_messages(websocket, approved_ip))
                         del pending_approvals[approved_ip]
                         await message_queue.put(f"Connection approved and established with {display_name}")
                     except websockets.exceptions.ConnectionClosed:
                          await message_queue.put(f"Peer {display_name} disconnected before approval message could be sent.")
                          # Clean up connection artifacts if websocket closed
                          if approved_ip in connections: del connections[approved_ip]
                          if approved_ip in peer_public_keys: del peer_public_keys[approved_ip]
                          # ... other cleanup
                          if approved_ip in pending_approvals: del pending_approvals[approved_ip] # Ensure removed
                     except Exception as e:
                          await message_queue.put(f"Error sending approval confirmation to {display_name}: {e}")
                          # Consider closing websocket and cleaning up if send failed critically
                          if approved_ip in pending_approvals: del pending_approvals[approved_ip]


                 else:
                     print(f"No pending connection request matching '{username_part}'")
                 continue


            if message.startswith("/deny "):
                 username_part = message[len("/deny "):].strip()
                 denied_ip = None
                 # Find peer IP matching the username part in pending requests
                 for peer_ip, approval_data in list(pending_approvals.items()):
                      if approval_data["username"] == username_part:
                          denied_ip = peer_ip
                          break
                      pending_display_name = f"{approval_data['username']}({approval_data.get('device_id', 'unknown')[:8]})"
                      if pending_display_name == username_part:
                           denied_ip = peer_ip
                           break

                 if denied_ip:
                     approval_data = pending_approvals[denied_ip]
                     websocket = approval_data["websocket"]
                     display_name = f"{approval_data['username']}({approval_data['device_id'][:8]})"
                     print(f"Denying connection from {display_name}...")
                     try:
                         if websocket.state == State.OPEN:
                             await websocket.close(code=1008, reason="Connection denied by user")
                         await message_queue.put(f"Connection from {display_name} denied.")
                     except Exception as e:
                          logging.error(f"Error closing denied connection for {display_name}: {e}")
                          await message_queue.put(f"Connection from {display_name} denied (encountered error during close).")
                     finally:
                          # Ensure removal from pending list regardless of close success
                          del pending_approvals[denied_ip]
                          # Also ensure cleanup of any potentially stored info for this IP
                          if denied_ip in connections: del connections[denied_ip]
                          if denied_ip in peer_public_keys: del peer_public_keys[denied_ip]
                          if denied_ip in peer_device_ids: del peer_device_ids[denied_ip]
                          uname = next((u for u, ip in peer_usernames.items() if ip == denied_ip), None)
                          if uname and uname in peer_usernames: del peer_usernames[uname]
                          dname = next((d for d, ip in username_to_ip.items() if ip == denied_ip), None)
                          if dname and dname in username_to_ip: del username_to_ip[dname]

                 else:
                     print(f"No pending connection request matching '{username_part}'")
                 continue


            if message.startswith("/ban "):
                username_to_ban = message[len("/ban "):].strip()
                if not username_to_ban:
                     print("Usage: /ban <username>")
                     continue
                if "banned_users" not in user_data:
                     user_data["banned_users"] = []
                if username_to_ban == user_data.get("original_username"):
                    print("You cannot ban yourself.")
                    continue
                if username_to_ban not in user_data["banned_users"]:
                     user_data["banned_users"].append(username_to_ban)
                     # Save updated config
                     config_path = os.path.join(get_config_directory(), "keys.json")
                     try:
                         with open(config_path, "r") as f:
                             config_data = json.load(f)
                         config_data["banned_users"] = user_data["banned_users"]
                         with open(config_path, "w") as f:
                             json.dump(config_data, f, indent=4)
                         print(f"User '{username_to_ban}' banned.")
                         # Disconnect if currently connected
                         ban_ip = None
                         for uname, ip_addr in list(peer_usernames.items()):
                              if uname == username_to_ban:
                                   ban_ip = ip_addr
                                   break
                         if ban_ip and ban_ip in connections:
                              print(f"Disconnecting banned user {username_to_ban}...")
                              await disconnect_from_peer(ban_ip) # Use disconnect function

                     except FileNotFoundError:
                          print("Error: Config file not found while trying to save ban list.")
                     except Exception as e:
                          print(f"Error saving ban list: {e}")

                else:
                     print(f"User '{username_to_ban}' is already banned.")
                continue


            if message.startswith("/unban "):
                 username_to_unban = message[len("/unban "):].strip()
                 if not username_to_unban:
                      print("Usage: /unban <username>")
                      continue
                 if "banned_users" in user_data and username_to_unban in user_data["banned_users"]:
                      user_data["banned_users"].remove(username_to_unban)
                      # Save updated config
                      config_path = os.path.join(get_config_directory(), "keys.json")
                      try:
                           with open(config_path, "r") as f:
                               config_data = json.load(f)
                           config_data["banned_users"] = user_data["banned_users"]
                           with open(config_path, "w") as f:
                               json.dump(config_data, f, indent=4)
                           print(f"User '{username_to_unban}' unbanned.")
                      except FileNotFoundError:
                          print("Error: Config file not found while trying to save ban list.")
                      except Exception as e:
                           print(f"Error saving ban list: {e}")

                 else:
                      print(f"User '{username_to_unban}' is not currently banned.")
                 continue

            if message == "/banned":
                 banned_users = user_data.get("banned_users", [])
                 if not banned_users:
                     print("\nNo users are currently banned.")
                 else:
                     print("\nBanned users:")
                     for username in sorted(banned_users):
                         print(f"- {username}")
                 continue

            if message.startswith("/msg "):
                 parts = message[len("/msg "):].split(" ", 1)
                 if len(parts) < 2:
                     print("Usage: /msg <id_or_group> <message>")
                     continue
                 target_identifier, msg_content = parts
                 result, status = await resolve_peer_target(target_identifier)

                 if status == "found":
                     peer_ip = result
                     display_name = get_peer_display_name(peer_ip)
                     if await send_message_to_peers(msg_content, peer_ip):
                         await message_queue.put(f"You -> {display_name}: {msg_content}")
                     else:
                         print(f"Failed to send message to {display_name} (maybe disconnected?).")
                 elif status == "group":
                     group_name = target_identifier # Since resolve returns members list
                     member_ips = [ip for ip in result if ip != await get_own_ip()]
                     if not member_ips:
                          print(f"No other members currently connected in group '{group_name}'.")
                          continue
                     if await send_message_to_peers(msg_content, member_ips):
                         await message_queue.put(f"You -> {group_name}: {msg_content}")
                     else:
                         print(f"Failed to send message to some members of group '{group_name}'.")
                 elif status == "not_found":
                     print(f"Error: Peer or group '{target_identifier}' not found or not connected.")
                 else: # ambiguous
                     print(f"Error: Ambiguous target '{target_identifier}'. Matches: {', '.join(result)}. Please be more specific.")
                 continue


            if message.startswith("/send "):
                parts = message[len("/send "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /send <id_or_group> <file_path>")
                    continue
                target_identifier, file_path = parts
                if not os.path.exists(file_path):
                    print(f"Error: File or directory '{file_path}' not found.")
                    continue

                # Resolve target
                result, status = await resolve_peer_target(target_identifier)

                peers_to_send_to = {} # Dictionary of {peer_ip: websocket}

                if status == "found":
                    peer_ip = result
                    ws = connections.get(peer_ip)
                    if ws and ws.state == State.OPEN:
                        peers_to_send_to[peer_ip] = ws
                    else:
                        print(f"Error: Not connected to {get_peer_display_name(peer_ip)}.")
                elif status == "group":
                    group_name = target_identifier
                    own_ip = await get_own_ip()
                    member_ips = [ip for ip in result if ip != own_ip] # Exclude self
                    group_peers = {ip: connections[ip] for ip in member_ips if ip in connections and connections[ip].state == State.OPEN}
                    if group_peers:
                        peers_to_send_to.update(group_peers)
                    else:
                        print(f"Error: No other connected members found in group '{group_name}'.")
                elif status == "not_found":
                    print(f"Error: Peer or group '{target_identifier}' not found or not connected.")
                elif status == "ambiguous":
                     print(f"Error: Ambiguous target '{target_identifier}'. Matches: {', '.join(result)}. Please be more specific.")


                if peers_to_send_to:
                     # Check if it's a directory or a file
                     if os.path.isdir(file_path):
                          # Sending a folder needs different handling (later)
                          print(f"Sending folders is not yet supported. Path: {file_path}")
                          # TODO: Implement folder sending
                          # - Walk directory os.walk(file_path)
                          # - Create a folder transfer ID
                          # - For each file:
                          #   - Send a specific FILE_TRANSFER message with folder_id and relative path
                          #   - Call request_file_transfer (or similar) for each file
                     elif os.path.isfile(file_path):
                          # Send a single file
                          asyncio.create_task(request_file_transfer(file_path, peers_to_send_to))
                     else:
                          print(f"Error: '{file_path}' is not a valid file or directory.")
                continue


            if message.startswith("/accept_file "):
                transfer_id_prefix = message[len("/accept_file "):].strip()
                matched_transfer_id = None
                match_count = 0
                for tid, transfer in list(active_transfers.items()):
                     if tid.startswith(transfer_id_prefix) and transfer.direction == "receive" and transfer.state == TransferState.PENDING:
                          matched_transfer_id = tid
                          match_count += 1

                if match_count == 0:
                     print(f"No pending transfer found matching prefix '{transfer_id_prefix}'")
                elif match_count > 1:
                     print(f"Multiple pending transfers match '{transfer_id_prefix}'. Please use a longer, unique ID.")
                else:
                     transfer_id = matched_transfer_id
                     transfer = active_transfers[transfer_id]
                     peer_ip = transfer.peer_ip
                     ws = connections.get(peer_ip)

                     if not ws or ws.state != State.OPEN:
                          print(f"Cannot accept transfer {transfer_id[:8]}: Peer {get_peer_display_name(peer_ip)} disconnected.")
                          transfer.state = TransferState.FAILED
                          # Move to completed/failed transfers if needed
                          del active_transfers[transfer_id]
                          continue

                     base_path = "downloads"
                     # Create target directory (including potential subdirs if it was a folder part)
                     relative_dir = os.path.dirname(transfer.file_path) # file_path now holds relative path
                     target_dir = os.path.join(base_path, relative_dir) if relative_dir else base_path
                     os.makedirs(target_dir, exist_ok=True)

                     target_file_path = os.path.join(target_dir, os.path.basename(transfer.file_path))

                     # Update transfer object with the full local path
                     transfer.file_path = target_file_path


                     try:
                          transfer.file_handle = await aiofiles.open(target_file_path, "wb")
                          transfer.state = TransferState.IN_PROGRESS

                          await ws.send(json.dumps({"type": "FILE_TRANSFER_RESPONSE", "transfer_id": transfer_id, "approved": True}))
                          await message_queue.put(f"Accepted file transfer '{os.path.basename(transfer.file_path)}' from {get_peer_display_name(peer_ip)}. Receiving...")
                     except Exception as e:
                          print(f"Error opening file for transfer {transfer_id[:8]}: {e}")
                          transfer.state = TransferState.FAILED
                          del active_transfers[transfer_id]
                          # Notify sender of failure if possible? Difficult if file open failed locally.
                continue


            if message.startswith("/deny_file "):
                 transfer_id_prefix = message[len("/deny_file "):].strip()
                 matched_transfer_id = None
                 match_count = 0
                 # Find the matching PENDING receive transfer
                 for tid, transfer in list(active_transfers.items()):
                     if tid.startswith(transfer_id_prefix) and transfer.direction == "receive" and transfer.state == TransferState.PENDING:
                         matched_transfer_id = tid
                         match_count += 1

                 if match_count == 0:
                      print(f"No pending transfer found matching prefix '{transfer_id_prefix}'")
                 elif match_count > 1:
                      print(f"Multiple pending transfers match '{transfer_id_prefix}'. Please use a longer, unique ID.")
                 else:
                     transfer_id = matched_transfer_id
                     transfer = active_transfers[transfer_id]
                     peer_ip = transfer.peer_ip
                     ws = connections.get(peer_ip)

                     if ws and ws.state == State.OPEN:
                         try:
                              await ws.send(json.dumps({"type": "FILE_TRANSFER_RESPONSE", "transfer_id": transfer_id, "approved": False}))
                         except Exception as e:
                              logging.warning(f"Failed to send denial for transfer {transfer_id[:8]} to {get_peer_display_name(peer_ip)}: {e}")

                     # Remove the transfer regardless of whether denial was sent
                     del active_transfers[transfer_id]
                     await message_queue.put(f"Denied file transfer '{os.path.basename(transfer.file_path)}' from {get_peer_display_name(peer_ip)}")
                 continue


            if message == "/transfers":
                 print("\n--- Transfers ---")
                 if not active_transfers and not completed_transfers:
                     print("No transfers recorded in this session.")
                     continue

                 if active_transfers:
                     print("\nActive transfers:")
                     sorted_active = sorted(active_transfers.items())
                     for transfer_id, transfer in sorted_active:
                         direction = "Sending" if transfer.direction == "send" else "Receiving"
                         try:
                              progress = (transfer.transferred_size / transfer.total_size * 100) if transfer.total_size > 0 else 0
                              total_size_mb = transfer.total_size / (1024 * 1024)
                              transferred_mb = transfer.transferred_size / (1024 * 1024)
                         except ZeroDivisionError:
                              progress = 0
                              total_size_mb = 0
                              transferred_mb = 0

                         peer_display = get_peer_display_name(transfer.peer_ip)
                         file_basename = os.path.basename(transfer.file_path) if transfer.file_path else "N/A"

                         print(f"- ID: {transfer_id[:8]} | State: {transfer.state.value}")
                         print(f"    {direction} '{file_basename}' {'to' if direction == 'Sending' else 'from'} {peer_display}")
                         if transfer.state in [TransferState.IN_PROGRESS, TransferState.PAUSED]:
                              print(f"    Progress: {progress:.1f}% ({transferred_mb:.2f}/{total_size_mb:.2f} MB)")
                         elif transfer.state == TransferState.PENDING:
                              print(f"    Size: {total_size_mb:.2f} MB")


                 if completed_transfers:
                      print("\nRecent Completed/Failed transfers:")
                      sorted_completed = sorted(completed_transfers.items(), key=lambda item: item[0]) # Sort by ID
                      for transfer_id, details in sorted_completed:
                           direction = "Sent" if details["direction"] == "send" else "Received"
                           try:
                                progress = (details["transferred_size"] / details["total_size"] * 100) if details["total_size"] > 0 else 0
                                total_size_mb = details["total_size"] / (1024 * 1024)
                                transferred_mb = details["transferred_size"] / (1024 * 1024)
                           except ZeroDivisionError:
                                progress = 0
                                total_size_mb = 0
                                transferred_mb = 0

                           peer_display = get_peer_display_name(details["peer_ip"]) # May show unknown if peer long gone
                           file_basename = os.path.basename(details["file_path"]) if details["file_path"] else "N/A"
                           final_state = details["state"].upper() # Use the stored state value

                           print(f"- ID: {transfer_id[:8]} | State: {final_state}")
                           print(f"    {direction} '{file_basename}' {'to' if direction == 'Sent' else 'from'} {peer_display}")
                           print(f"    Final: {progress:.1f}% ({transferred_mb:.2f}/{total_size_mb:.2f} MB)")
                 continue


            if message.startswith("/pause "):
                transfer_id_prefix = message[len("/pause "):].strip()
                if not transfer_id_prefix:
                    print("Usage: /pause <transfer_id_prefix>")
                else:
                    matched_transfer = None
                    match_count = 0
                    candidates = []
                    for tid, transfer in active_transfers.items():
                        if tid.startswith(transfer_id_prefix) and transfer.state == TransferState.IN_PROGRESS:
                             candidates.append(transfer)
                             match_count +=1

                    if match_count == 0:
                         print(f"No active (in progress) transfer found matching '{transfer_id_prefix}'")
                    elif match_count > 1:
                         print(f"Multiple active transfers match '{transfer_id_prefix}'. Be more specific.")
                         for t in candidates:
                              print(f"  - {t.transfer_id[:8]} ({'Sending' if t.direction == 'send' else 'Receiving'} '{os.path.basename(t.file_path)}')")
                    else:
                         matched_transfer = candidates[0]
                         transfer_id = matched_transfer.transfer_id
                         peer_ip = matched_transfer.peer_ip
                         ws = connections.get(peer_ip)

                         if not ws or ws.state != State.OPEN:
                              print(f"Cannot pause transfer {transfer_id[:8]}: Peer {get_peer_display_name(peer_ip)} is offline.")
                              # Optional: Mark as failed? Or just leave paused?
                         else:
                              own_ip = await get_own_ip() # Define own_ip here
                              await matched_transfer.pause(own_ip) # Pass own IP as initiator
                              try:
                                   await ws.send(json.dumps({"type": "TRANSFER_PAUSE", "transfer_id": transfer_id}))
                                   await message_queue.put(f"Transfer {transfer_id[:8]} paused.")
                              except Exception as e:
                                   print(f"Paused transfer {transfer_id[:8]} locally, but failed to notify peer: {e}")
                continue


            if message.startswith("/resume "):
                transfer_id_prefix = message[len("/resume "):].strip()
                if not transfer_id_prefix:
                    print("Usage: /resume <transfer_id_prefix>")
                else:
                    matched_transfer = None
                    match_count = 0
                    candidates = []
                    for tid, transfer in active_transfers.items():
                        if tid.startswith(transfer_id_prefix) and transfer.state == TransferState.PAUSED:
                             candidates.append(transfer)
                             match_count += 1

                    if match_count == 0:
                         print(f"No paused transfer found matching '{transfer_id_prefix}'")
                    elif match_count > 1:
                         print(f"Multiple paused transfers match '{transfer_id_prefix}'. Be more specific.")
                         for t in candidates:
                               print(f"  - {t.transfer_id[:8]} ({'Sending' if t.direction == 'send' else 'Receiving'} '{os.path.basename(t.file_path)}')")
                    else:
                         matched_transfer = candidates[0]
                         transfer_id = matched_transfer.transfer_id
                         peer_ip = matched_transfer.peer_ip
                         ws = connections.get(peer_ip)

                         if not ws or ws.state != State.OPEN:
                             print(f"Cannot resume transfer {transfer_id[:8]}: Peer {get_peer_display_name(peer_ip)} is offline.")
                         else:
                             own_ip = await get_own_ip()
                             if matched_transfer.initiator != own_ip:
                                 print(f"Cannot resume transfer {transfer_id[:8]}: Only the user who paused it ({get_peer_display_name(matched_transfer.initiator)}) can resume.")
                             else:
                                 try:
                                      await matched_transfer.resume(own_ip)
                                      await ws.send(json.dumps({"type": "TRANSFER_RESUME", "transfer_id": transfer_id}))
                                      await message_queue.put(f"Transfer {transfer_id[:8]} resumed.")
                                      # If resuming a send transfer, restart chunk sending
                                      if matched_transfer.direction == "send":
                                          from networking.messaging.utils import send_file_chunks # Local import ok here
                                          asyncio.create_task(send_file_chunks(matched_transfer, ws))

                                 except Exception as e:
                                     print(f"Resumed transfer {transfer_id[:8]} locally, but failed to notify peer or restart send: {e}")
                                     # Revert state?
                                     # matched_transfer.state = TransferState.PAUSED # Revert perhaps
                continue


            if message.startswith("/group_create "):
                groupname = message[len("/group_create "):].strip()
                if not groupname:
                     print("Usage: /group_create <groupname>")
                     continue
                if groupname in groups:
                    print(f"Group '{groupname}' already exists.")
                else:
                     own_ip = await get_own_ip()
                     groups[groupname] = {"admin": own_ip, "members": {own_ip}}
                     await send_group_create_message(groupname) # Notify others
                     await message_queue.put(f"Group '{groupname}' created. You are the admin.")
                continue

            if message.startswith("/group_invite "):
                 parts = message[len("/group_invite "):].split(" ", 1)
                 if len(parts) < 2:
                     print("Usage: /group_invite <groupname> <id_or_ip>")
                     continue

                 groupname, identifier = parts[0].strip(), parts[1].strip()
                 if not groupname or not identifier:
                      print("Usage: /group_invite <groupname> <id_or_ip>")
                      continue

                 if groupname not in groups:
                     print(f"Group '{groupname}' does not exist.")
                 elif groups[groupname]["admin"] != await get_own_ip():
                     print(f"You are not the admin of group '{groupname}'.")
                 else:
                     result, status = await resolve_peer_target(identifier)
                     if status == "found":
                          peer_ip_to_invite = result
                          if peer_ip_to_invite in groups[groupname]["members"]:
                              print(f"{get_peer_display_name(peer_ip_to_invite)} is already in the group '{groupname}'.")
                          else:
                              await send_group_invite_message(groupname, peer_ip_to_invite)
                     elif status == "not_found":
                          print(f"Error: Peer '{identifier}' not found or not connected.")
                     elif status == "ambiguous":
                          print(f"Error: Ambiguous target '{identifier}'. Matches: {', '.join(result)}. Please be more specific.")
                     elif status == "group":
                           print(f"Error: Cannot invite a group ('{identifier}') to another group.")
                 continue

            if message.startswith("/accept_invite "):
                groupname = message[len("/accept_invite "):].strip()
                if not groupname:
                    print("Usage: /accept_invite <groupname>")
                    continue
                own_ip = await get_own_ip()
                invite_to_accept = None
                # Check invites for own_ip
                if own_ip in pending_invites:
                    for invite_group, inviter_ip in list(pending_invites[own_ip]):
                        if invite_group == groupname:
                            invite_to_accept = (invite_group, inviter_ip)
                            break

                if not invite_to_accept:
                    print(f"No pending invite found for group '{groupname}'.")
                else:
                    _, inviter_ip = invite_to_accept
                    # Remove from pending *before* sending response
                    pending_invites[own_ip].remove(invite_to_accept)
                    if not pending_invites[own_ip]: # Clean up set if empty
                         del pending_invites[own_ip]

                    await send_group_invite_response(groupname, inviter_ip, True)
                    # Local state update (adding self) happens when receiving GROUP_UPDATE from admin
                    await message_queue.put(f"Accepted invite for '{groupname}'. Waiting for admin update...")
                continue

            if message.startswith("/decline_invite "):
                groupname = message[len("/decline_invite "):].strip()
                if not groupname:
                    print("Usage: /decline_invite <groupname>")
                    continue

                own_ip = await get_own_ip()
                invite_to_decline = None
                if own_ip in pending_invites:
                    for invite_group, inviter_ip in list(pending_invites[own_ip]):
                        if invite_group == groupname:
                            invite_to_decline = (invite_group, inviter_ip)
                            break

                if not invite_to_decline:
                    print(f"No pending invite found for group '{groupname}'.")
                else:
                    _, inviter_ip = invite_to_decline
                    pending_invites[own_ip].remove(invite_to_decline)
                    if not pending_invites[own_ip]:
                         del pending_invites[own_ip]

                    await send_group_invite_response(groupname, inviter_ip, False)
                    await message_queue.put(f"Declined invite for group '{groupname}'.")
                continue

            if message.startswith("/group_join "):
                parts = message[len("/group_join "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /group_join <groupname> <admin_id_or_ip>")
                    continue
                groupname, admin_identifier = parts[0].strip(), parts[1].strip()
                if not groupname or not admin_identifier:
                      print("Usage: /group_join <groupname> <admin_id_or_ip>")
                      continue

                result, status = await resolve_peer_target(admin_identifier)
                if status == "found":
                    admin_ip = result
                    await send_group_join_request(groupname, admin_ip)
                    await message_queue.put(f"Sent join request for '{groupname}' to {get_peer_display_name(admin_ip)}")
                elif status == "not_found":
                     print(f"Error: Potential admin '{admin_identifier}' not found or not connected.")
                elif status == "ambiguous":
                     print(f"Error: Ambiguous potential admin '{admin_identifier}'. Matches: {', '.join(result)}. Please be more specific.")
                elif status == "group":
                     print(f"Error: Cannot target a group ('{admin_identifier}') as an admin.")
                continue


            if message.startswith("/approve_join "):
                 parts = message[len("/approve_join "):].split(" ", 1)
                 if len(parts) < 2:
                     print("Usage: /approve_join <groupname> <username>")
                     continue
                 groupname, username = parts[0].strip(), parts[1].strip()
                 if not groupname or not username:
                      print("Usage: /approve_join <groupname> <username>")
                      continue

                 if groupname not in groups:
                     print(f"Group '{groupname}' does not exist.")
                 elif groups[groupname]["admin"] != await get_own_ip():
                     print(f"You are not the admin of group '{groupname}'.")
                 else:
                     request_to_approve = None
                     # Check pending requests for this group
                     if groupname in pending_join_requests:
                         for request_data in list(pending_join_requests[groupname]):
                             if request_data["username"] == username:
                                 request_to_approve = request_data
                                 break

                     if not request_to_approve:
                          print(f"No pending join request found from username '{username}' for group '{groupname}'.")
                     else:
                          # Remove from pending
                          pending_join_requests[groupname].remove(request_to_approve)
                          if not pending_join_requests[groupname]: # Clean up list if empty
                               del pending_join_requests[groupname]

                          requester_ip = request_to_approve["ip"]

                          # Add member to local group state
                          groups[groupname]["members"].add(requester_ip)

                          # Send approval response to requester
                          await send_group_join_response(groupname, requester_ip, True)

                          # Send update to all (now including new) members
                          await send_group_update_message(groupname, groups[groupname]["members"])

                          await message_queue.put(f"Approved join request from '{username}' for '{groupname}'. Group updated.")
                 continue


            if message.startswith("/deny_join "):
                 parts = message[len("/deny_join "):].split(" ", 1)
                 if len(parts) < 2:
                     print("Usage: /deny_join <groupname> <username>")
                     continue
                 groupname, username = parts[0].strip(), parts[1].strip()
                 if not groupname or not username:
                      print("Usage: /deny_join <groupname> <username>")
                      continue

                 if groupname not in groups:
                     print(f"Group '{groupname}' does not exist.")
                 elif groups[groupname]["admin"] != await get_own_ip():
                      print(f"You are not the admin of group '{groupname}'.")
                 else:
                      request_to_deny = None
                      if groupname in pending_join_requests:
                          for request_data in list(pending_join_requests[groupname]):
                               if request_data["username"] == username:
                                   request_to_deny = request_data
                                   break

                      if not request_to_deny:
                           print(f"No pending join request found from username '{username}' for group '{groupname}'.")
                      else:
                           pending_join_requests[groupname].remove(request_to_deny)
                           if not pending_join_requests[groupname]:
                                del pending_join_requests[groupname]

                           requester_ip = request_to_deny["ip"]
                           await send_group_join_response(groupname, requester_ip, False)
                           await message_queue.put(f"Denied join request from '{username}' for group '{groupname}'.")
                 continue


            if message.startswith("/group_members "):
                groupname = message[len("/group_members "):].strip()
                if not groupname:
                     print("Usage: /group_members <groupname>")
                     continue

                if groupname not in groups:
                    print(f"Group '{groupname}' does not exist or you are not a member.")
                else:
                    members = groups[groupname].get("members", set())
                    admin_ip = groups[groupname].get("admin")

                    if not members:
                        print(f"Group '{groupname}' currently has no members listed.")
                    else:
                        print(f"\nMembers of group '{groupname}':")
                        sorted_members = sorted(list(members), key=get_peer_display_name)
                        for member_ip in sorted_members:
                             suffix = " (admin)" if member_ip == admin_ip else ""
                             print(f"- {get_peer_display_name(member_ip)}{suffix}")
                continue


            # Default message sending (no leading '/')
            if not message.startswith("/"):
                if not connections:
                    print("No peers connected to send the message to. Use /connect first.")
                else:
                     # Send to all connected peers
                     if await send_message_to_peers(message):
                         await message_queue.put(f"You (to all): {message}")
                     else:
                         # This case might happen if send_message_to_peers fails internally
                         print("Failed to send message to all peers (some might have disconnected).")
                continue

            # If it starts with / but doesn't match anything above
            print(f"Unknown command: '{message.split()[0]}'. Type /help for available commands.")


        except asyncio.CancelledError:
            print("\nInput task cancelled. Exiting...")
            break # Exit loop if task is cancelled
        except EOFError:
             print("\nEOF received, shutting down...")
             shutdown_event.set()
             break
        except Exception as e:
             print(f"\nAn error occurred in the input loop: {e}")
             logging.exception("Error details:") # Log full traceback for debugging
             await asyncio.sleep(0.1) # Prevent rapid error loops


async def display_messages():
    while not shutdown_event.is_set():
        try:
            item = await message_queue.get()

            # --- FIX: Reconstruct the prompt string ---
            my_display_name = get_own_display_name()
            current_prompt_line = f"{my_display_name} > "
            # --- END FIX ---

            message_to_display = ""
            # Handle different types of items from the queue
            if isinstance(item, str):
                message_to_display = item
            elif isinstance(item, dict):
                 # Handle specific dictionary message structures meant for display
                 if item.get("type") == "approval_request":
                      message_to_display = item.get("message", "Approval request received.")
                 elif item.get("type") == "file_transfer_approval":
                      message_to_display = item.get("message", "File transfer request received.")
                 else:
                      # Default display for unexpected dictionaries (optional)
                      # message_to_display = f"System Message: {item}"
                      logging.debug(f"Received unformatted dict in message_queue: {item}")
                      message_to_display = item.get("message", str(item)) # Fallback

            # Use carriage return and clear line code for smoother display update
            # \r moves cursor to beginning, \033[K clears line
            # Print message, add newline, then reprint the prompt without a trailing newline
            print(f"\r\033[K{message_to_display}\n{current_prompt_line}", end='', flush=True)

            message_queue.task_done()

        except asyncio.CancelledError:
             break
        except Exception as e:
            # Avoid complex formatting within the error message itself
            print(f"\nError displaying message: {e}") # Ensure newline to avoid prompt overwrite
            logging.exception("Display error details:")
            # Try to reprint the prompt after an error to restore the input line
            try:
                 my_disp_name_err = get_own_display_name()
                 prompt_err = f"{my_disp_name_err} > "
                 print(prompt_err, end='', flush=True)
            except Exception:
                 pass # Ignore errors during error handling display
            await asyncio.sleep(0.5) # Brief pause after error