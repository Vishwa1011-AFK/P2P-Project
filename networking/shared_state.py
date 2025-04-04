import asyncio
from collections import defaultdict

shutdown_event = asyncio.Event()
active_transfers = {}
message_queue = asyncio.Queue()
connections = {}  # {peer_ip: websocket}
user_data = {}
peer_public_keys = {}  # {peer_ip: public_key}
peer_usernames = {}  # {username: peer_ip}
peer_device_ids = {}
groups = defaultdict(lambda: {"admin": None, "members": set()})  # {groupname: {"admin": admin_ip, "members": set of ips}}
pending_invites = []  # [{"groupname": groupname, "inviter_ip": ip}]
pending_join_requests = defaultdict(list)  # {groupname: [{"requester_ip": ip, "requester_username": username}]}
pending_approvals = {}  # A dictionary, e.g., {peer_ip: approval_status}
connection_denials = {}  # A dictionary to track denied connections, e.g., {peer_ip: denial_count}