import json
from networking.shared_state import connections, groups
from networking.messaging.utils import get_own_ip

async def send_group_create_message(groupname):
    own_ip = await get_own_ip()
    message = json.dumps({"type": "GROUP_CREATE", "groupname": groupname, "admin_ip": own_ip})
    for ws in connections.values():
        if ws.open:
            await ws.send(message)

async def send_group_invite_message(groupname, peer_ip):
    own_ip = await get_own_ip()
    message = json.dumps({"type": "GROUP_INVITE", "groupname": groupname, "inviter_ip": own_ip})
    ws = connections.get(peer_ip)
    if ws and ws.open:
        await ws.send(message)

async def send_group_invite_response(groupname, inviter_ip, accepted):
    own_ip = await get_own_ip()
    message = json.dumps({"type": "GROUP_INVITE_RESPONSE", "groupname": groupname, "invitee_ip": own_ip, "accepted": accepted})
    ws = connections.get(inviter_ip)
    if ws and ws.open:
        await ws.send(message)

async def send_group_join_request(groupname, admin_ip):
    own_ip = await get_own_ip()
    from networking.shared_state import user_data
    message = json.dumps({
        "type": "GROUP_JOIN_REQUEST",
        "groupname": groupname,
        "requester_ip": own_ip,
        "requester_username": user_data["original_username"]
    })
    ws = connections.get(admin_ip)
    if ws and ws.open:
        await ws.send(message)

async def send_group_join_response(groupname, requester_ip, approved):
    message = json.dumps({
        "type": "GROUP_JOIN_RESPONSE",
        "groupname": groupname,
        "requester_ip": requester_ip,
        "approved": approved
    })
    ws = connections.get(requester_ip)
    if ws and ws.open:
        await ws.send(message)

async def send_group_update_message(groupname, members):
    message = json.dumps({"type": "GROUP_UPDATE", "groupname": groupname, "members": members})
    for member_ip in groups[groupname]["members"]:
        ws = connections.get(member_ip)
        if ws and ws.open:
            await ws.send(message)