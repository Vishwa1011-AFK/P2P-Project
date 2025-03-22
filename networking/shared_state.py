import asyncio
from collections import defaultdict

shutdown_event = asyncio.Event()
active_transfers = {}
message_queue = asyncio.Queue()
connections = {}  # {peer_ip: websocket}
user_data = {}
peer_public_keys = {}  # {peer_ip: public_key}
peer_usernames = {}  # {username: peer_ip}
pending_file_approvals = {}  # {transfer_id: asyncio.Future}