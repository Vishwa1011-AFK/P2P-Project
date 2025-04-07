import asyncio
import os
import uuid
import aiofiles
import hashlib
import logging
import json
from enum import Enum
from networking.shared_state import active_transfers, completed_transfers, shutdown_event, message_queue, connections
from networking.messaging.utils import get_peer_display_name
from websockets.connection import State

class TransferState(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class FileTransfer:
    def __init__(self, file_path, peer_ip, direction="send", folder_id=None):
        self.file_path = file_path
        self.peer_ip = peer_ip
        self.direction = direction
        self.transfer_id = str(uuid.uuid4())
        self.folder_id = folder_id  # For grouping folder contents
        self.total_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        self.transferred_size = 0
        self.file_handle = None
        self.state = TransferState.PENDING if direction == "receive" else TransferState.IN_PROGRESS
        self.hash_algo = hashlib.sha256()
        self.expected_hash = None
        self.condition = asyncio.Condition()
        self.initiator = None

    async def pause(self, initiator):
        async with self.condition:
            if self.state == TransferState.IN_PROGRESS and (self.initiator is None or self.initiator == initiator):
                self.state = TransferState.PAUSED
                self.initiator = initiator
                logging.info(f"Transfer {self.transfer_id} paused by {initiator}")
                self.condition.notify_all()

    async def resume(self, initiator):
        async with self.condition:
            if self.state == TransferState.PAUSED and self.initiator == initiator:
                self.state = TransferState.IN_PROGRESS
                logging.info(f"Transfer {self.transfer_id} resumed by {initiator}")
                self.condition.notify_all()

async def compute_hash(file_path):
    hash_algo = hashlib.sha256()
    async with aiofiles.open(file_path, "rb") as f:
        while True:
            chunk = await f.read(1024 * 1024)
            if not chunk:
                break
            hash_algo.update(chunk)
    return hash_algo.hexdigest()

async def send_file(file_path, peers):
    if os.path.isdir(file_path):
        folder_id = str(uuid.uuid4())
        base_dir = os.path.basename(file_path)
        tasks = []
        for root, _, files in os.walk(file_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, os.path.dirname(file_path))
                tasks.append(send_single_file(full_path, peers, folder_id, rel_path))
        await asyncio.gather(*tasks)
    else:
        await send_single_file(file_path, peers)

async def send_single_file(file_path, peers, folder_id=None, rel_path=None):
    transfer_id = str(uuid.uuid4())
    file_size = os.path.getsize(file_path)
    file_name = rel_path or os.path.basename(file_path)
    file_hash = await compute_hash(file_path)
    peer_ip = list(peers.keys())[0] if len(peers) == 1 else None
    transfer = FileTransfer(file_path, peer_ip, direction="send", folder_id=folder_id)
    transfer.transfer_id = transfer_id
    transfer.total_size = file_size
    transfer.expected_hash = file_hash
    active_transfers[transfer_id] = transfer

    request_message = json.dumps({
        "type": "file_transfer_request",
        "transfer_id": transfer_id,
        "filename": file_name,
        "filesize": file_size,
        "file_hash": file_hash,
        "folder_id": folder_id
    })
    connected_peers = {}
    for peer_ip, ws in peers.items():
        if ws.state == State.OPEN:
            await ws.send(request_message)
            connected_peers[peer_ip] = ws

    if not connected_peers:
        del active_transfers[transfer_id]
        await message_queue.put(f"Error: Could not initiate transfer '{file_name}' with recipient.")
        return

    peers = connected_peers
    await asyncio.sleep(30)  # Timeout for approval
    if transfer.state != TransferState.IN_PROGRESS:
        del active_transfers[transfer_id]
        await message_queue.put(f"Transfer of '{file_name}' timed out or was denied.")
        return

    async with aiofiles.open(file_path, "rb") as f:
        transfer.file_handle = f
        chunk_size = 1024 * 1024
        while not shutdown_event.is_set():
            async with transfer.condition:
                while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                    await transfer.condition.wait()
                if shutdown_event.is_set():
                    break
                if transfer.state != TransferState.IN_PROGRESS:
                    break
            chunk = await f.read(chunk_size)
            if not chunk:
                transfer.state = TransferState.COMPLETED
                break
            transfer.transferred_size += len(chunk)
            transfer.hash_algo.update(chunk)
            chunk_hex = chunk.hex()
            message = json.dumps({"type": "file_chunk", "transfer_id": transfer_id, "chunk": chunk_hex})
            for peer_ip, ws in list(peers.items()):
                if ws.state == State.OPEN:
                    try:
                        await ws.send(message)
                    except Exception as e:
                        logging.error(f"Failed to send chunk to {peer_ip}: {e}")
                        del peers[peer_ip]
                else:
                    del peers[peer_ip]
            if not peers:
                transfer.state = TransferState.FAILED
                break
    if transfer.file_handle:
        await transfer.file_handle.close()
    transfer_details = {
        "file_path": transfer.file_path,
        "peer_ip": transfer.peer_ip,
        "direction": transfer.direction,
        "total_size": transfer.total_size,
        "transferred_size": transfer.transferred_size,
        "state": transfer.state.value,
        "folder_id": transfer.folder_id
    }
    if transfer.state in (TransferState.COMPLETED, TransferState.FAILED):
        completed_transfers[transfer_id] = transfer_details
        del active_transfers[transfer_id]
    if transfer.state == TransferState.COMPLETED:
        await message_queue.put(f"Sent '{file_name}' successfully to {get_peer_display_name(peer_ip) if peer_ip else 'group'}.")
    elif transfer.state == TransferState.FAILED:
        await message_queue.put(f"Failed to send '{file_name}' due to peer disconnection.")
    elif shutdown_event.is_set():
        await message_queue.put(f"Transfer of '{file_name}' cancelled due to shutdown.")