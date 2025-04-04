# networking/file_transfer.py
import asyncio
import os
import uuid
import aiofiles
import hashlib
import logging
import json
import websockets
from enum import Enum
from networking.shared_state import active_transfers, shutdown_event, message_queue
from networking.messaging.utils import get_peer_display_name  # Import for display name

class TransferState(Enum):
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class FileTransfer:
    def __init__(self, file_path, peer_ip, direction="send"):
        self.file_path = file_path
        self.peer_ip = peer_ip
        self.direction = direction
        self.transfer_id = str(uuid.uuid4())
        self.total_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        self.transferred_size = 0
        self.file_handle = None
        self.state = TransferState.IN_PROGRESS
        self.hash_algo = hashlib.sha256()
        self.expected_hash = None
        self.condition = asyncio.Condition()

    async def pause(self):
        async with self.condition:
            if self.state == TransferState.IN_PROGRESS:
                self.state = TransferState.PAUSED
                logging.info(f"Transfer {self.transfer_id} paused.")
                self.condition.notify_all()

    async def resume(self):
        async with self.condition:
            if self.state == TransferState.PAUSED:
                self.state = TransferState.IN_PROGRESS
                logging.info(f"Transfer {self.transfer_id} resumed.")
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
    transfer_id = str(uuid.uuid4())
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    file_hash = await compute_hash(file_path)
    transfer = FileTransfer(file_path, list(peers.keys())[0], direction="send")
    transfer.transfer_id = transfer_id
    transfer.total_size = file_size
    transfer.expected_hash = file_hash
    active_transfers[transfer_id] = transfer

    init_message = json.dumps({
        "type": "file_transfer_init",
        "transfer_id": transfer_id,
        "filename": file_name,
        "filesize": file_size,
        "file_hash": file_hash
    })
    connected_peers = {}
    for peer_ip, ws in peers.items():
        if ws.open:
            await ws.send(init_message)
            connected_peers[peer_ip] = ws

    if not connected_peers:
        del active_transfers[transfer_id]
        await message_queue.put(f"Error: Could not initiate transfer '{file_name}' with recipient(s).")
        return

    peers = connected_peers
    async with aiofiles.open(file_path, "rb") as f:
        transfer.file_handle = f
        chunk_size = 1024 * 1024
        while not shutdown_event.is_set():
            async with transfer.condition:
                while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                    await transfer.condition.wait()
                if transfer.state != TransferState.IN_PROGRESS:
                    break
            chunk = await f.read(chunk_size)
            if not chunk:
                transfer.state = TransferState.COMPLETED
                break
            transfer.transferred_size += len(chunk)
            for peer_ip, ws in list(peers.items()):
                if ws.open:
                    await ws.send(chunk)
                else:
                    del peers[peer_ip]
            if not peers:
                transfer.state = TransferState.FAILED
                break
    if transfer.file_handle:
        await transfer.file_handle.close()
    if transfer.state == TransferState.COMPLETED:
        await message_queue.put(f"Sent '{file_name}' successfully.")

async def update_transfer_progress():
    """Periodically update and display progress of active file transfers."""
    while not shutdown_event.is_set():
        try:
            if active_transfers:
                for transfer_id, transfer in active_transfers.items():
                    if transfer.total_size > 0:  # Avoid division by zero
                        progress = (transfer.transferred_size / transfer.total_size) * 100
                        direction = "Sending" if transfer.direction == "send" else "Receiving"
                        peer_display = get_peer_display_name(transfer.peer_ip)
                        msg = (
                            f"Transfer {transfer_id[:8]}: {direction} "
                            f"'{os.path.basename(transfer.file_path)}' "
                            f"to/from {peer_display} - {progress:.1f}% "
                            f"({transfer.transferred_size / (1024 * 1024):.2f}/"
                            f"{transfer.total_size / (1024 * 1024):.2f} MB)"
                        )
                        logging.info(msg)
                        await message_queue.put(msg)
            await asyncio.sleep(5)  # Update every 5 seconds
        except Exception as e:
            logging.error(f"Error in update_transfer_progress: {e}")
            await asyncio.sleep(5)