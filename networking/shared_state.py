import asyncio
from collections import defaultdict

shutdown_event = asyncio.Event()
active_transfers = {} 
message_queue = asyncio.Queue()
connections = {}
user_data = {}
peer_public_keys = {}
peer_usernames = {}  
pending_file_receive_approvals = {}
pending_file_send_acks = {}