import asyncio
from collections import defaultdict

# File Transfers
active_transfers = {} # {transfer_id: FileTransfer object}
completed_transfers = {} # {transfer_id: {details...}} - Store recent history

# Messaging
message_queue = asyncio.Queue() # For displaying messages to the user

# Connections & Peers
connections = {} # {peer_ip: websocket_connection} - Active connections
peer_public_keys = {} # {peer_ip: cryptography_public_key_object}
peer_usernames = {} # {original_username: peer_ip} - For connected peers
peer_device_ids = {} # {peer_ip: device_id_string} - For connected peers
username_to_ip = {} # {display_name: peer_ip} - display_name is username(devID)
discovered_peers_by_username = {} # {username: peer_ip} - From discovery broadcasts

# User & Config
user_data = {} # Stores own username, keys, device_id, banned_users list

# Application State
shutdown_event = asyncio.Event()

# Manual Connection Approval
pending_approvals = {} # {peer_ip: {"username": ..., "device_id": ..., "websocket": ...}}
connection_denials = set() # Track explicitly denied IPs temporarily? (Maybe not needed)

# Groups
groups = {} # {groupname: {"admin": admin_ip, "members": {member_ip1, member_ip2,...}}}
pending_invites = defaultdict(set) # {target_peer_ip: {(groupname, inviter_ip), ...}}
pending_join_requests = defaultdict(list) # {groupname: [{"username":..., "ip":...}, ...]}