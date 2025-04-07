import asyncio
from collections import defaultdict

shutdown_event = asyncio.Event()
active_transfers = {}
completed_transfers = {}  # {transfer_id: {details}}
message_queue = asyncio.Queue()
connections = {}
user_data = {}
peer_public_keys = {}
peer_usernames = {}
peer_device_ids = {}
groups = defaultdict(lambda: {"admin": None, "members": set()})
pending_invites = defaultdict(set)  # {invitee_ip: {(groupname, inviter_ip)}}
pending_join_requests = defaultdict(list)
pending_approvals = {}
connection_denials = defaultdict(int)  # {(requester_username, requester_device_id): count}