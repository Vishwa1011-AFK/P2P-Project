import asyncio
import json
import os
from aioconsole import ainput
from websockets.connection import State
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
    await asyncio.sleep(1)
    my_display_name = get_own_display_name()

    while not shutdown_event.is_set():
        try:
            message = (await ainput(f"{my_display_name} > ")).strip()
            if not message:
                continue

            if message == "/exit":
                print("Shutting down immediately...")  # Immediate feedback
                shutdown_event.set()
                for ws in connections.values():
                    if ws.state == State.OPEN:
                        await ws.close(code=1000, reason="User initiated shutdown")
                continue

            if message == "/help":
                print("\nAvailable commands:")
                print("  /exit - Shut down the application")
                print("  /connect <ip> - Connect to a peer by IP")
                print("  /disconnect <display_name_or_username> - Disconnect from a peer")
                print("  /peers - List connected peers")
                print("  /msg <display_name_or_username_or_groupname> <message> - Send a message")
                print("  /send <display_name_or_username_or_groupname> <file_path> - Send a file or folder")
                print("  /accept_file <transfer_id> - Accept a file transfer")
                print("  /deny_file <transfer_id> - Deny a file transfer")
                print("  /transfers - Show active and completed transfers")
                print("  /pause <transfer_id_prefix> - Pause a transfer")
                print("  /resume <transfer_id_prefix> - Resume a paused transfer")
                print("  /group_create <groupname> - Create a new group")
                print("  /group_invite <groupname> <display_name_or_username> - Invite a peer to a group")
                print("  /accept_invite <groupname> - Accept a group invite")
                print("  /decline_invite <groupname> - Decline a group invite")
                print("  /group_join <groupname> <admin_display_name_or_username> - Request to join a group")
                print("  /approve_join <groupname> <username> - Approve a join request")
                print("  /deny_join <groupname> <username> - Deny a join request")
                print("  /group_members <groupname> - List group members")
                print("  /approve <username> - Approve a pending connection")
                print("  /deny <username> - Deny a pending connection")
                continue

            if message.startswith("/connect "):
                peer_ip = message[len("/connect "):].strip()
                asyncio.create_task(connect_to_peer(peer_ip))
                continue

            if message.startswith("/disconnect "):
                identifier = message[len("/disconnect "):].strip()
                result, status = await resolve_peer_target(identifier)
                if status == "found":
                    await disconnect_from_peer(result)
                    print(f"Disconnected from {get_peer_display_name(result)}")
                elif status == "not_found":
                    print(f"No connected peer found matching: {identifier}")
                else:
                    print(f"Ambiguous target '{identifier}'. Matches: {', '.join(result)}")
                continue

            if message == "/peers":
                if not connections:
                    print("\nNo connected peers.")
                else:
                    print("\nConnected peers:")
                    for peer_ip in connections:
                        username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), "unknown")
                        device_id = peer_device_ids.get(peer_ip, "unknown")
                        print(f"- {username}({device_id}) at {peer_ip}")
                continue

            if message.startswith("/msg "):
                parts = message[len("/msg "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /msg <display_name_or_username_or_groupname> <message>")
                    continue
                target_identifier, msg_content = parts
                result, status = await resolve_peer_target(target_identifier)
                if status == "found":
                    peer_ip = result
                    if await send_message_to_peers(msg_content, peer_ip):
                        await message_queue.put(f"You (to {get_peer_display_name(peer_ip)}): {msg_content}")
                    else:
                        print(f"Failed to send message to {get_peer_display_name(peer_ip)}.")
                elif target_identifier in groups and await get_own_ip() in groups[target_identifier]["members"]:
                    member_ips = [ip for ip in groups[target_identifier]["members"] if ip != await get_own_ip()]
                    if await send_message_to_peers(msg_content, member_ips):
                        await message_queue.put(f"You (to {target_identifier}): {msg_content}")
                    else:
                        print(f"Failed to send message to group '{target_identifier}'.")
                elif status == "not_found":
                    print(f"No connected peer or group found matching: {target_identifier}")
                else:
                    print(f"Ambiguous target '{target_identifier}'. Matches: {', '.join(result)}")
                continue

            if message.startswith("/send "):
                parts = message[len("/send "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /send <display_name_or_username_or_groupname> <file_path>")
                    continue
                target_identifier, file_path = parts
                if not os.path.exists(file_path):
                    print(f"Error: '{file_path}' does not exist.")
                    continue
                result, status = await resolve_peer_target(target_identifier)
                if status == "found":
                    peer_ip = result
                    ws = connections.get(peer_ip)
                    if ws and ws.state == State.OPEN:
                        print(f"Starting send '{os.path.basename(file_path)}' to {get_peer_display_name(peer_ip)}...")
                        asyncio.create_task(send_file(file_path, {peer_ip: ws}))
                    else:
                        print(f"Error: Connection invalid for {get_peer_display_name(peer_ip)}.")
                elif target_identifier in groups and await get_own_ip() in groups[target_identifier]["members"]:
                    peers = {ip: connections[ip] for ip in groups[target_identifier]["members"] if ip in connections and connections[ip].state == State.OPEN}
                    if peers:
                        print(f"Starting send '{os.path.basename(file_path)}' to group '{target_identifier}'...")
                        asyncio.create_task(send_file(file_path, peers))
                    else:
                        print(f"Error: No connected members in group '{target_identifier}'.")
                elif status == "not_found":
                    print(f"Error: No connected peer or group found matching: {target_identifier}.")
                else:
                    print(f"Error: Ambiguous target '{target_identifier}'. Matches: {', '.join(result)}")
                continue

            if message.startswith("/accept_file "):
                transfer_id = message[len("/accept_file "):].strip()
                transfer = active_transfers.get(transfer_id)
                if transfer and transfer.direction == "receive" and transfer.state == TransferState.PENDING:
                    transfer.state = TransferState.IN_PROGRESS
                    folder_id = transfer.folder_id
                    base_path = "downloads" if not folder_id else os.path.join("downloads", os.path.dirname(transfer.file_path))
                    os.makedirs(base_path, exist_ok=True)
                    transfer.file_handle = await aiofiles.open(transfer.file_path, "wb")
                    ws = connections.get(transfer.peer_ip)
                    if ws and ws.state == State.OPEN:
                        await ws.send(json.dumps({"type": "file_transfer_response", "transfer_id": transfer_id, "approved": True}))
                        await message_queue.put(f"Accepted file transfer '{transfer.file_path}' from {get_peer_display_name(transfer.peer_ip)}")
                    else:
                        transfer.state = TransferState.FAILED
                        del active_transfers[transfer_id]
                        await message_queue.put("Failed to accept file: Peer disconnected.")
                else:
                    print(f"No pending file transfer with ID '{transfer_id}'")
                continue

            if message.startswith("/deny_file "):
                transfer_id = message[len("/deny_file "):].strip()
                transfer = active_transfers.get(transfer_id)
                if transfer and transfer.direction == "receive" and transfer.state == TransferState.PENDING:
                    ws = connections.get(transfer.peer_ip)
                    if ws and ws.state == State.OPEN:
                        await ws.send(json.dumps({"type": "file_transfer_response", "transfer_id": transfer_id, "approved": False}))
                    del active_transfers[transfer_id]
                    await message_queue.put(f"Denied file transfer '{transfer.file_path}' from {get_peer_display_name(transfer.peer_ip)}")
                else:
                    print(f"No pending file transfer with ID '{transfer_id}'")
                continue

            if message.startswith("/transfers"):
                if not active_transfers and not completed_transfers:
                    print("\nNo transfers in this session.")
                    continue
                if active_transfers:
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
                if completed_transfers:
                    print("\nCompleted/Failed transfers:")
                    for transfer_id, details in completed_transfers.items():
                        direction = "Sending" if details["direction"] == "send" else "Receiving"
                        progress = (details["transferred_size"] / details["total_size"] * 100) if details["total_size"] > 0 else 0
                        total_size_mb = details["total_size"] / (1024 * 1024)
                        transferred_mb = details["transferred_size"] / (1024 * 1024)
                        peer_display = get_peer_display_name(details["peer_ip"])
                        print(f"- ID: {transfer_id[:8]}... State: {details['state']}")
                        print(f"    {direction} '{os.path.basename(details['file_path'])}' {'to' if direction == 'Sending' else 'from'} {peer_display}")
                        print(f"    Progress: {progress:.1f}% ({transferred_mb:.2f}/{total_size_mb:.2f} MB)")
                continue

            if message.startswith("/pause "):
                transfer_id_prefix = message[len("/pause "):].strip()
                if not transfer_id_prefix:
                    print("Usage: /pause <transfer_id_prefix>")
                else:
                    matched_transfer = None
                    match_count = 0
                    for tid, transfer in active_transfers.items():
                        if tid.startswith(transfer_id_prefix):
                            matched_transfer = transfer
                            match_count += 1
                    if match_count == 0:
                        print(f"No transfer matching '{transfer_id_prefix}'")
                    elif match_count > 1:
                        print(f"Multiple transfers match '{transfer_id_prefix}'. Be more specific.")
                    else:
                        transfer_id = matched_transfer.transfer_id
                        own_ip = await get_own_ip()
                        peer_ip = matched_transfer.peer_ip
                        ws = connections.get(peer_ip)
                        if not ws or ws.state != State.OPEN:
                            print(f"Cannot pause transfer {transfer_id[:8]}: Peer offline.")
                        elif matched_transfer.state == TransferState.IN_PROGRESS:
                            await matched_transfer.pause(own_ip)
                            await ws.send(json.dumps({"type": "TRANSFER_PAUSE", "transfer_id": transfer_id}))
                            print(f"Transfer {transfer_id[:8]} paused.")
                        else:
                            print(f"Cannot pause (state: {matched_transfer.state.value})")
                continue

            if message.startswith("/resume "):
                transfer_id_prefix = message[len("/resume "):].strip()
                if not transfer_id_prefix:
                    print("Usage: /resume <transfer_id_prefix>")
                else:
                    matched_transfer = None
                    match_count = 0
                    for tid, transfer in active_transfers.items():
                        if tid.startswith(transfer_id_prefix):
                            matched_transfer = transfer
                            match_count += 1
                    if match_count == 0:
                        print(f"No transfer matching '{transfer_id_prefix}'")
                    elif match_count > 1:
                        print(f"Multiple transfers match '{transfer_id_prefix}'. Be more specific.")
                    else:
                        transfer_id = matched_transfer.transfer_id
                        own_ip = await get_own_ip()
                        peer_ip = matched_transfer.peer_ip
                        ws = connections.get(peer_ip)
                        if not ws or ws.state != State.OPEN:
                            print(f"Cannot resume transfer {transfer_id[:8]}: Peer offline.")
                        elif matched_transfer.state == TransferState.PAUSED:
                            if matched_transfer.initiator != own_ip:
                                print(f"Cannot resume transfer {transfer_id[:8]}: Only the pausing user can resume it.")
                            else:
                                await matched_transfer.resume(own_ip)
                                await ws.send(json.dumps({"type": "TRANSFER_RESUME", "transfer_id": transfer_id}))
                                print(f"Transfer {transfer_id[:8]} resumed.")
                        else:
                            print(f"Cannot resume (state: {matched_transfer.state.value})")
                continue

            if message.startswith("/group_create "):
                groupname = message[len("/group_create "):].strip()
                if groupname in groups:
                    print(f"Group '{groupname}' already exists.")
                else:
                    own_ip = await get_own_ip()
                    groups[groupname]["admin"] = own_ip
                    groups[groupname]["members"].add(own_ip)
                    await send_group_create_message(groupname)
                    print(f"Group '{groupname}' created.")
                continue

            if message.startswith("/group_invite "):
                parts = message[len("/group_invite "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /group_invite <groupname> <display_name_or_username>")
                else:
                    groupname, identifier = parts
                    if groupname not in groups:
                        print(f"Group '{groupname}' does not exist.")
                    elif await get_own_ip() != groups[groupname]["admin"]:
                        print(f"You are not the admin of '{groupname}'.")
                    else:
                        result, status = await resolve_peer_target(identifier)
                        if status == "found":
                            await send_group_invite_message(groupname, result)
                        elif status == "not_found":
                            print(f"No connected peer found matching: {identifier}")
                        else:
                            print(f"Ambiguous target '{identifier}'. Matches: {', '.join(result)}")
                continue

            if message.startswith("/accept_invite "):
                groupname = message[len("/accept_invite "):].strip()
                if groupname not in groups:
                    print(f"Group '{groupname}' does not exist.")
                else:
                    own_ip = await get_own_ip()
                    invite = next(((g, i) for g, i in pending_invites[own_ip] if g == groupname), None)
                    if not invite:
                        print(f"No pending invite for '{groupname}'")
                    else:
                        pending_invites[own_ip].remove(invite)
                        await send_group_invite_response(groupname, invite[1], True)
                        groups[groupname]["members"].add(own_ip)
                        await send_group_update_message(groupname, groups[groupname]["members"])
                        print(f"Accepted invite to '{groupname}'")
                continue

            if message.startswith("/decline_invite "):
                groupname = message[len("/decline_invite "):].strip()
                if groupname not in groups:
                    print(f"Group '{groupname}' does not exist.")
                else:
                    own_ip = await get_own_ip()
                    invite = next(((g, i) for g, i in pending_invites[own_ip] if g == groupname), None)
                    if not invite:
                        print(f"No pending invite for '{groupname}'")
                    else:
                        pending_invites[own_ip].remove(invite)
                        await send_group_invite_response(groupname, invite[1], False)
                        print(f"Declined invite to '{groupname}'")
                continue

            if message.startswith("/group_join "):
                parts = message[len("/group_join "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /group_join <groupname> <admin_display_name_or_username>")
                else:
                    groupname, admin_identifier = parts
                    if groupname not in groups:
                        print(f"Group '{groupname}' does not exist.")
                    else:
                        result, status = await resolve_peer_target(admin_identifier)
                        if status == "found":
                            await send_group_join_request(groupname, result)
                            print(f"Sent join request for '{groupname}' to {get_peer_display_name(result)}")
                        elif status == "not_found":
                            print(f"No connected peer found matching: {admin_identifier}")
                        else:
                            print(f"Ambiguous target '{admin_identifier}'. Matches: {', '.join(result)}")
                continue

            if message.startswith("/approve_join "):
                parts = message[len("/approve_join "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /approve_join <groupname> <username>")
                else:
                    groupname, username = parts
                    if groupname not in groups:
                        print(f"Group '{groupname}' does not exist.")
                    elif await get_own_ip() != groups[groupname]["admin"]:
                        print(f"You are not the admin of '{groupname}'.")
                    else:
                        requester = next((r for r in pending_join_requests[groupname] if r["username"] == username), None)
                        if not requester:
                            print(f"No pending join request from '{username}' for '{groupname}'")
                        else:
                            pending_join_requests[groupname].remove(requester)
                            requester_ip = requester["ip"]
                            groups[groupname]["members"].add(requester_ip)
                            await send_group_join_response(groupname, requester_ip, True)
                            await send_group_update_message(groupname, groups[groupname]["members"])
                            await message_queue.put(f"{username} has joined '{groupname}'")
                            print(f"Approved join request from '{username}' for '{groupname}'")
                continue

            if message.startswith("/deny_join "):
                parts = message[len("/deny_join "):].split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /deny_join <groupname> <username>")
                else:
                    groupname, username = parts
                    if groupname not in groups:
                        print(f"Group '{groupname}' does not exist.")
                    elif await get_own_ip() != groups[groupname]["admin"]:
                        print(f"You are not the admin of '{groupname}'.")
                    else:
                        requester = next((r for r in pending_join_requests[groupname] if r["username"] == username), None)
                        if not requester:
                            print(f"No pending join request from '{username}' for '{groupname}'")
                        else:
                            pending_join_requests[groupname].remove(requester)
                            await send_group_join_response(groupname, requester["ip"], False)
                            print(f"Denied join request from '{username}' for '{groupname}'")
                continue

            if message.startswith("/group_members "):
                groupname = message[len("/group_members "):].strip()
                if groupname not in groups:
                    print(f"Group '{groupname}' does not exist.")
                else:
                    members = groups[groupname]["members"]
                    if not members:
                        print(f"Group '{groupname}' has no members.")
                    else:
                        print(f"\nMembers of '{groupname}':")
                        for member_ip in members:
                            print(f"- {get_peer_display_name(member_ip)}")
                continue

            if message.startswith("/approve "):
                username = message[len("/approve "):].strip()
                approved = False
                for peer_ip, approval_data in list(pending_approvals.items()):
                    if approval_data["username"] == username:
                        connections[peer_ip] = approval_data["websocket"]
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
                        await approval_data["websocket"].send(hello_back)
                        asyncio.create_task(receive_peer_messages(approval_data["websocket"], peer_ip))
                        del pending_approvals[peer_ip]
                        approved = True
                        await message_queue.put(f"Connected to {username}({approval_data['device_id']}) at {peer_ip}")
                        break
                if not approved:
                    print(f"No pending connection request from '{username}'")
                continue

            if message.startswith("/deny "):
                username = message[len("/deny "):].strip()
                denied = False
                for peer_ip, approval_data in list(pending_approvals.items()):
                    if approval_data["username"] == username:
                        await approval_data["websocket"].close(code=1008, reason="Connection denied by user")
                        del pending_approvals[peer_ip]
                        denied = True
                        break
                if not denied:
                    print(f"No pending connection request from '{username}'")
                continue

            if await send_message_to_peers(message):
                await message_queue.put(f"You: {message}")
            else:
                print("No peers connected to send the message.")

        except Exception as e:
            print(f"Error in user_input: {e}")
            await asyncio.sleep(0.1)

async def display_messages():
    while not shutdown_event.is_set():
        try:
            item = await message_queue.get()
            if isinstance(item, str):
                print(f"\n{item}")
            elif isinstance(item, dict):
                if item.get("type") == "approval_request":
                    print(f"\nConnection request from {item['requesting_username']}. Approve? (/approve {item['requesting_username'].split('(')[0]} or /deny {item['requesting_username'].split('(')[0]})")
                elif item.get("type") == "file_transfer_approval":
                    print(f"\n{item['message']}")
            message_queue.task_done()
        except Exception as e:
            print(f"Error displaying message: {e}")
            await asyncio.sleep(1)