import asyncio
from collections import defaultdict

connections_lock = asyncio.Lock()
peer_data_lock = asyncio.Lock() 
active_transfers_lock = asyncio.Lock()

shutdown_event = asyncio.Event()
active_transfers = {}
message_queue = asyncio.Queue(maxsize=1000)
connections = {}  
user_data = {}
peer_public_keys = {}  
peer_usernames = {}  
peer_device_ids = {}