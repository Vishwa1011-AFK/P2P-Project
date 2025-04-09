import asyncio
from collections import defaultdict

active_transfers = {}
completed_transfers = {}
message_queue = asyncio.Queue()
connections = {}
user_data = {}
peer_public_keys = {}
peer_usernames = {}
peer_device_ids = {}
shutdown_event = asyncio.Event()
pending_approvals = {}
connection_denials = set()
groups = {}
pending_invites = defaultdict(set)
pending_join_requests = defaultdict(list)
username_to_ip = {}  # New mapping: display_name -> IP