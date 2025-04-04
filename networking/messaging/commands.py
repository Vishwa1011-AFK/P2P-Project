import asyncio
import json
import os
from aioconsole import ainput
from networking.shared_state import (
    connections, message_queue, active_transfers, user_data, peer_public_keys,
    peer_usernames, peer_device_ids, shutdown_event, groups, pending_invites, pending_join_requests,
    pending_approvals
)
from networking.messaging.core import send_message_to_peers
from networking.messaging.groups import (
    send_group_create_message, send_group_invite_message, send_group_invite_response,
    send_group_join_request, send_group_join_response, send_group_update_message
)
from networking.messaging.utils import (
    get_peer_display_name, get_own_display_name, resolve_peer_target,
    get_config_directory, initialize_user_config, connect_to_peer, disconnect_from_peer, get_own_ip
)
from networking.file_transfer import send_file, TransferState

async def user_input(discovery):
    """Handle user input commands asynchronously."""
    await asyncio.sleep(1)  # Brief delay to ensure initialization completes
    my_display_name = get_own_display_name()

    while not shutdown_event.is_set():
        try:
            message = (await ainput(f"{my_display_name} > ")).strip()
            if not message:
                continue

            # Exit command
            if message == "/exit":
                print("Initiating shutdown...")
                shutdown_event.set()
                break

            # Help command
            if message == "/help":
                print("\nAvailable commands:")
                print("  /exit                       - Shut down the application")
                print("  /help                       - Show this help message")
                print("  /list                       - List all active peers in the network")
                print("  /peers                      - List currently connected peers")
                print("  /connect <username>         - Connect to a peer by username")
                print("  /disconnect <name>          - Disconnect from a peer by display name or username")
                print("  /msg <name> <message>       - Send a private message to a peer")
                print("  /send <name> <file_path>    - Send a file to a peer")
                print("  /pause <transfer_id>        - Pause a file transfer")
                print("  /resume <transfer_id>       - Resume a paused file transfer")
                print("  /transfers                  - List all active file transfers")
                print("  /groups                     - List all groups you are in")
                print("  /users <groupname>          - List users in a specific group")
                print("  /create_group <groupname>   - Create a new group")
                print("  /invite <group> <username>  - Invite a user to a group (admin only)")
                print("  /accept_invite <group>      - Accept a group invitation")
                print("  /decline_invite <group>     - Decline a group invitation")
                print("  /request_join <group>       - Request to join a group")
                print("  /approve_join <group> <user>- Approve a join request (admin only)")
                print("  /deny_join <group> <user>   - Deny a join request (admin only)")
                print("  /approve <username>         - Approve a connection request")
                print("  /deny <username>            - Deny a connection request")
                print("  <message>                   - Send a message to all connected peers")
                continue

            # List all active peers in the network
            if message == "/list":
                if not discovery.peer_list:
                    print("No active peers discovered in the network.")
                else:
                    print("Active peers in the network:")
                    for peer_ip, (username, last_seen) in discovery.peer_list.items():
                        status = "Connected" if peer_ip in connections else "Disconnected"
                        print(f"- {username} ({peer_ip}) - {status}")
                continue

            # List connected peers
            if message == "/peers":
                if not connections:
                    print("No peers connected.")
                else:
                    print("Connected peers:")
                    for peer_ip in connections:
                        display_name = get_peer_display_name(peer_ip)
                        print(f"- {display_name} ({peer_ip})")
                continue

            # Connect to a peer
            if message.startswith("/connect "):
                target_username = message[len("/connect "):].strip()
                if not target_username:
                    print("Usage: /connect <username>")
                    continue
                peer_ip = next((ip for ip, (uname, _) in discovery.peer_list.items() if uname == target_username), None)
                if not peer_ip:
                    print(f"No peer found with username '{target_username}' in discovery list.")
                    continue
                if peer_ip in connections:
                    print(f"Already connected to {get_peer_display_name(peer_ip)}.")
                    continue
                asyncio.create_task(connect_to_peer(peer_ip, user_data["original_username"], target_username))
                print(f"Attempting to connect to {target_username}...")
                continue

            # Disconnect from a peer
            if message.startswith("/disconnect "):
                target_identifier = message[len("/disconnect "):].strip()
                if not target_identifier:
                    print("Usage: /disconnect <display_name_or_username>")
                    continue
                result, status = await resolve_peer_target(target_identifier)
                if status == "found":
                    peer_ip = result
                    await disconnect_from_peer(peer_ip)
                    print(f"Disconnected from {get_peer_display_name(peer_ip)}")
                elif status == "not_found":
                    print(f"No connected peer found matching: {target_identifier}")
                else:
                    print(f"Ambiguous target '{target_identifier}'. Matches: {', '.join(result)}")
                continue

            # Send a private message
            if message.startswith("/msg "):
                parts = message[len("/msg "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /msg <display_name_or_username> <message>")
                    continue
                target_identifier, msg_content = parts
                result, status = await resolve_peer_target(target_identifier)
                if status == "found":
                    peer_ip = result
                    resolved_display_name = get_peer_display_name(peer_ip)
                    if await send_message_to_peers(msg_content, peer_ip):
                        await message_queue.put(f"You (to {resolved_display_name}): {msg_content}")
                    else:
                        print(f"Failed to send message to {resolved_display_name}.")
                elif status == "not_found":
                    print(f"No connected peer found matching: {target_identifier}")
                else:
                    print(f"Ambiguous target '{target_identifier}'. Matches: {', '.join(result)}")
                continue

            # Send a file
            if message.startswith("/send "):
                parts = message[len("/send "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /send <display_name_or_username> <file_path>")
                    continue
                target_identifier, file_path = parts
                if not os.path.isfile(file_path):
                    print(f"Error: '{file_path}' is not a file or does not exist.")
                    continue
                result, status = await resolve_peer_target(target_identifier)
                if status == "found":
                    peer_ip = result
                    ws = connections.get(peer_ip)
                    if ws and not ws.closed:
                        resolved_display_name = get_peer_display_name(peer_ip)
                        print(f"Starting send '{os.path.basename(file_path)}' to {resolved_display_name}...")
                        asyncio.create_task(send_file(file_path, {peer_ip: ws}))
                    else:
                        print(f"Error: Connection invalid for {resolved_display_name}.")
                elif status == "not_found":
                    print(f"Error: No connected peer found matching: {target_identifier}.")
                else:
                    print(f"Error: Ambiguous target '{target_identifier}'. Matches: {', '.join(result)}")
                continue

            # Pause a file transfer
            if message.startswith("/pause "):
                transfer_id_prefix = message[len("/pause "):].strip()
                if not transfer_id_prefix:
                    print("Usage: /pause <transfer_id_prefix>")
                    continue
                matched_transfer = None
                match_count = 0
                for tid, transfer in active_transfers.items():
                    if tid.startswith(transfer_id_prefix):
                        matched_transfer = transfer
                        match_count += 1
                if match_count == 0:
                    print(f"No transfer matching '{transfer_id_prefix}'")
                    continue
                if match_count > 1:
                    print(f"Multiple transfers match '{transfer_id_prefix}'. Be more specific.")
                    continue
                peer_ip = matched_transfer.peer_ip
                transfer_id = matched_transfer.transfer_id
                ws = connections.get(peer_ip)
                if not ws or ws.closed:
                    print(f"Cannot pause transfer {transfer_id[:8]}: Peer offline.")
                    continue
                if matched_transfer.state == TransferState.IN_PROGRESS:
                    await ws.send(json.dumps({"type": "TRANSFER_PAUSE", "transfer_id": transfer_id}))
                    await matched_transfer.pause()
                    print(f"Transfer {transfer_id[:8]} paused.")
                else:
                    print(f"Cannot pause (state: {matched_transfer.state.value})")
                continue

            # Resume a file transfer
            if message.startswith("/resume "):
                transfer_id_prefix = message[len("/resume "):].strip()
                if not transfer_id_prefix:
                    print("Usage: /resume <transfer_id_prefix>")
                    continue
                matched_transfer = None
                match_count = 0
                for tid, transfer in active_transfers.items():
                    if tid.startswith(transfer_id_prefix):
                        matched_transfer = transfer
                        match_count += 1
                if match_count == 0:
                    print(f"No transfer matching '{transfer_id_prefix}'")
                    continue
                if match_count > 1:
                    print(f"Multiple transfers match '{transfer_id_prefix}'. Be more specific.")
                    continue
                peer_ip = matched_transfer.peer_ip
                transfer_id = matched_transfer.transfer_id
                ws = connections.get(peer_ip)
                if not ws or ws.closed:
                    print(f"Cannot resume transfer {transfer_id[:8]}: Peer offline.")
                    continue
                if matched_transfer.state == TransferState.PAUSED:
                    await ws.send(json.dumps({"type": "TRANSFER_RESUME", "transfer_id": transfer_id}))
                    await matched_transfer.resume()
                    print(f"Transfer {transfer_id[:8]} resumed.")
                else:
                    print(f"Cannot resume (state: {matched_transfer.state.value})")
                continue

            # List active transfers
            if message == "/transfers":
                if not active_transfers:
                    print("\nNo active transfers.")
                    continue
                print("\nActive transfers:")
                for transfer_id, transfer in active_transfers.items():
                    direction = "Sending" if transfer.direction == "send" else "Receiving"
                    progress = (transfer.transferred_size / transfer.total_size * 100) if transfer.total_size > 0 else 0
                    total_size_mb = transfer.total_size / (1024 * 1024)
                    transferred_mb = transfer.transferred_size / (1024 * 1024)
                    peer_display = get_peer_display_name(transfer.peer_ip)
                    print(f"- ID: {transfer_id[:8]}... State: {transfer.state.value}")
                    print(f"    {direction} '{os.path.basename(transfer.file_path)}' {'to' if direction == 'Sending' else 'from'} {peer_display}")
                    print(f"    Progress: {progress:.1f}% ({transferred_mb:.2f}/{total_size_mb:.2f} MB)")
                continue

            # List all groups
            if message == "/groups":
                if not groups:
                    print("You are not in any groups.")
                else:
                    print("Your groups:")
                    for groupname, info in groups.items():
                        print(f"- {groupname} (Admin: {get_peer_display_name(info['admin'])})")
                continue

            # List users in a group
            if message.startswith("/users "):
                groupname = message[len("/users "):].strip()
                if groupname not in groups:
                    print(f"You are not in group '{groupname}'")
                else:
                    print(f"Users in '{groupname}':")
                    for member_ip in groups[groupname]["members"]:
                        print(f"- {get_peer_display_name(member_ip)}")
                continue

            # Create a group
            if message.startswith("/create_group "):
                groupname = message[len("/create_group "):].strip()
                if not groupname:
                    print("Usage: /create_group <groupname>")
                    continue
                if groupname in groups:
                    print(f"Group '{groupname}' already exists.")
                else:
                    own_ip = await get_own_ip()
                    groups[groupname] = {"admin": own_ip, "members": {own_ip}}
                    await send_group_create_message(groupname)
                    print(f"Group '{groupname}' created.")
                continue

            # Invite a user to a group
            if message.startswith("/invite "):
                parts = message[len("/invite "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /invite <groupname> <username>")
                    continue
                groupname, username = parts
                own_ip = await get_own_ip()
                if groupname not in groups or groups[groupname]["admin"] != own_ip:
                    print("You are not the admin of this group.")
                    continue
                peer_ip = peer_usernames.get(username)
                if not peer_ip:
                    print(f"User '{username}' not found.")
                    continue
                if peer_ip in groups[groupname]["members"]:
                    print(f"'{username}' is already in '{groupname}'.")
                    continue
                await send_group_invite_message(groupname, peer_ip)
                print(f"Invited {username} to '{groupname}'")
                continue

            # Accept a group invite
            if message.startswith("/accept_invite "):
                groupname = message[len("/accept_invite "):].strip()
                invite = next((inv for inv in pending_invites if inv["groupname"] == groupname), None)
                if not invite:
                    print(f"No pending invite for '{groupname}'")
                    continue
                pending_invites.remove(invite)
                own_ip = await get_own_ip()
                await send_group_invite_response(groupname, invite["inviter_ip"], True)
                groups[groupname] = {"admin": invite["inviter_ip"], "members": {invite["inviter_ip"], own_ip}}
                print(f"Accepted invite to '{groupname}'")
                continue

            # Decline a group invite
            if message.startswith("/decline_invite "):
                groupname = message[len("/decline_invite "):].strip()
                invite = next((inv for inv in pending_invites if inv["groupname"] == groupname), None)
                if not invite:
                    print(f"No pending invite for '{groupname}'")
                    continue
                pending_invites.remove(invite)
                await send_group_invite_response(groupname, invite["inviter_ip"], False)
                print(f"Declined invite to '{groupname}'")
                continue

            # Request to join a group
            if message.startswith("/request_join "):
                groupname = message[len("/request_join "):].strip()
                if not groupname:
                    print("Usage: /request_join <groupname>")
                    continue
                if groupname not in groups:
                    print(f"Group '{groupname}' not found.")
                    continue
                if await get_own_ip() in groups[groupname]["members"]:
                    print(f"You are already in '{groupname}'.")
                    continue
                admin_ip = groups[groupname]["admin"]
                await send_group_join_request(groupname, admin_ip)
                print(f"Sent join request for '{groupname}' to admin.")
                continue

            # Approve a join request
            if message.startswith("/approve_join "):
                parts = message[len("/approve_join "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /approve_join <groupname> <username>")
                    continue
                groupname, username = parts
                own_ip = await get_own_ip()
                if groupname not in groups or groups[groupname]["admin"] != own_ip:
                    print("You are not the admin of this group.")
                    continue
                requester = next((req for req in pending_join_requests[groupname] if req["requester_username"] == username), None)
                if not requester:
                    print(f"No pending join request from '{username}' for '{groupname}'")
                    continue
                pending_join_requests[groupname].remove(requester)
                requester_ip = requester["requester_ip"]
                groups[groupname]["members"].add(requester_ip)
                await send_group_join_response(groupname, requester_ip, True)
                await send_group_update_message(groupname, list(groups[groupname]["members"]))
                print(f"Approved join request from '{username}' for '{groupname}'")
                continue

            # Deny a join request
            if message.startswith("/deny_join "):
                parts = message[len("/deny_join "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /deny_join <groupname> <username>")
                    continue
                groupname, username = parts
                own_ip = await get_own_ip()
                if groupname not in groups or groups[groupname]["admin"] != own_ip:
                    print("You are not the admin of this group.")
                    continue
                requester = next((req for req in pending_join_requests[groupname] if req["requester_username"] == username), None)
                if not requester:
                    print(f"No pending join request from '{username}' for '{groupname}'")
                    continue
                pending_join_requests[groupname].remove(requester)
                requester_ip = requester["requester_ip"]
                await send_group_join_response(groupname, requester_ip, False)
                print(f"Denied join request from '{username}' for '{groupname}'")
                continue

            # Approve or deny a connection request (manual approval)
            if message.startswith(("/approve ", "/deny ")):
                action, username = message.split(" ", 1)
                username = username.strip()
                peer_ip = peer_usernames.get(username)
                if not peer_ip or peer_ip not in pending_approvals:
                    print(f"No pending connection request from '{username}'")
                    continue
                approval_future = pending_approvals[peer_ip]
                if action == "/approve":
                    approval_future.set_result(True)
                    print(f"Approved connection from {get_peer_display_name(peer_ip)}")
                else:
                    approval_future.set_result(False)
                    print(f"Denied connection from {get_peer_display_name(peer_ip)}")
                continue

            # Default: Send message to all peers
            if connections and await send_message_to_peers(message):
                await message_queue.put(f"You (to all): {message}")
            else:
                print("No peers connected to send message to.")

        except Exception as e:
            print(f"Error in user_input: {e}")
            await asyncio.sleep(0.1)

async def display_messages():
    """Display messages and prompts from the message queue."""
    while not shutdown_event.is_set():
        try:
            item = await message_queue.get()
            if isinstance(item, str):
                print(f"\n{item}")
            elif isinstance(item, dict) and item.get("type") == "approval_request":
                peer_ip = item["peer_ip"]
                requesting_username = item["requesting_username"]
                print(f"\nConnection request from {requesting_username}. Approve? (/approve {requesting_username.split('(')[0]} or /deny {requesting_username.split('(')[0]})")
            message_queue.task_done()
        except Exception as e:
            print(f"Error displaying message: {e}")
            await asyncio.sleep(1)