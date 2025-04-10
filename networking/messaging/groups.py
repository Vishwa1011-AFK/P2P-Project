import json
import logging
from websockets.connection import State
from networking.shared_state import connections, groups, pending_invites, message_queue, user_data
from networking.messaging.helpers import get_own_ip, get_peer_display_name

async def send_group_create_message(groupname):
    own_ip = await get_own_ip()
    message = json.dumps({"type": "GROUP_CREATE", "groupname": groupname, "admin_ip": own_ip})
    # Send to all connected peers
    sent_count = 0
    for peer_ip, ws in connections.items():
        if ws and ws.state == State.OPEN and peer_ip != own_ip:
             try:
                 await ws.send(message)
                 sent_count += 1
             except Exception as e:
                 logging.warning(f"Failed to send group create notification for '{groupname}' to {get_peer_display_name(peer_ip)}: {e}")
    logging.info(f"Sent group create notification for '{groupname}' to {sent_count} peers.")


async def send_group_invite_message(groupname, peer_ip):
    own_ip = await get_own_ip()
    message = json.dumps({"type": "GROUP_INVITE", "groupname": groupname, "inviter_ip": own_ip})
    ws = connections.get(peer_ip)
    if ws and ws.state == State.OPEN:
        try:
             await ws.send(message)
             # Use setdefault to initialize if key doesn't exist
             pending_invites.setdefault(peer_ip, set()).add((groupname, own_ip))
             await message_queue.put(f"Sent invite to {get_peer_display_name(peer_ip)} for group '{groupname}'.")
             return True
        except Exception as e:
             logging.error(f"Failed to send group invite for '{groupname}' to {get_peer_display_name(peer_ip)}: {e}")
             return False
    else:
        logging.warning(f"Cannot send group invite: No active connection to {get_peer_display_name(peer_ip)}.")
        return False

async def send_group_invite_response(groupname, inviter_ip, accepted):
    own_ip = await get_own_ip()
    own_display_name = get_peer_display_name(own_ip) # Get own display name for message
    message = json.dumps({
        "type": "GROUP_INVITE_RESPONSE",
        "groupname": groupname,
        "invitee_ip": own_ip,
        "invitee_display_name": own_display_name, # Include display name
        "accepted": accepted
     })
    ws = connections.get(inviter_ip)
    if ws and ws.state == State.OPEN:
        try:
             await ws.send(message)
             logging.info(f"Sent {'accept' if accepted else 'decline'} response for group '{groupname}' to {get_peer_display_name(inviter_ip)}")
        except Exception as e:
             logging.error(f"Failed to send group invite response for '{groupname}' to {get_peer_display_name(inviter_ip)}: {e}")
    else:
         logging.warning(f"Cannot send group invite response: Admin {get_peer_display_name(inviter_ip)} seems disconnected.")


async def send_group_join_request(groupname, admin_ip):
    own_ip = await get_own_ip()
    message = json.dumps({
        "type": "GROUP_JOIN_REQUEST",
        "groupname": groupname,
        "requester_ip": own_ip,
        "requester_username": user_data.get("original_username", "unknown")
    })
    ws = connections.get(admin_ip)
    if ws and ws.state == State.OPEN:
        try:
            await ws.send(message)
            logging.info(f"Sent join request for '{groupname}' to admin {get_peer_display_name(admin_ip)}")
        except Exception as e:
            logging.error(f"Failed to send join request for '{groupname}' to admin {get_peer_display_name(admin_ip)}: {e}")
    else:
         logging.warning(f"Cannot send join request: Admin {get_peer_display_name(admin_ip)} seems disconnected.")


async def send_group_join_response(groupname, requester_ip, approved):
    admin_ip = await get_own_ip() # Admin is sending this
    message = json.dumps({
        "type": "GROUP_JOIN_RESPONSE",
        "groupname": groupname,
        "admin_ip": admin_ip, # Include admin IP for context
        "requester_ip": requester_ip, # This indicates who the response is *for*
        "approved": approved
    })
    ws = connections.get(requester_ip)
    if ws and ws.state == State.OPEN:
        try:
            await ws.send(message)
            logging.info(f"Sent join {'approval' if approved else 'denial'} for '{groupname}' to {get_peer_display_name(requester_ip)}")
        except Exception as e:
            logging.error(f"Failed to send join response for '{groupname}' to {get_peer_display_name(requester_ip)}: {e}")
    else:
         logging.warning(f"Cannot send join response: Requester {get_peer_display_name(requester_ip)} seems disconnected.")


async def send_group_update_message(groupname, members_set):
    """Sends the current member list to all members of the group."""
    if groupname not in groups:
         logging.warning(f"Attempted to send update for non-existent group '{groupname}'")
         return

    admin_ip = groups[groupname].get("admin")
    members_list = list(members_set)

    message = json.dumps({
        "type": "GROUP_UPDATE",
        "groupname": groupname,
        "admin_ip": admin_ip,
        "members": members_list # Send list of member IPs
     })

    sent_count = 0
    for member_ip in members_list:
        ws = connections.get(member_ip)
        if ws and ws.state == State.OPEN:
            try:
                await ws.send(message)
                sent_count += 1
            except Exception as e:
                logging.warning(f"Failed to send group update for '{groupname}' to {get_peer_display_name(member_ip)}: {e}")
        # else: Peer is in the member list but not currently connected, they'll get update if they reconnect? (or rely on admin sending again?)

    logging.info(f"Sent group update for '{groupname}' to {sent_count}/{len(members_list)} members.")