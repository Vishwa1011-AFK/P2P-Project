import os
import uuid
import enum
import asyncio
import aiofiles
from networking.shared_state import active_transfers, message_queue
from networking.messaging.helpers import get_peer_display_name

class TransferState(enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class FileTransfer:
    def __init__(self, peer_ip, direction, file_path, total_size, transfer_id=None, folder_id=None):
        self.peer_ip = peer_ip
        self.direction = direction
        self.file_path = file_path
        self.total_size = total_size
        self.transfer_id = transfer_id or str(uuid.uuid4())
        self.transferred_size = 0
        self.state = TransferState.PENDING
        self.file_handle = None
        self.folder_id = folder_id
        self.initiator = None

    async def pause(self, initiator):
        if self.state == TransferState.IN_PROGRESS:
            self.state = TransferState.PAUSED
            self.initiator = initiator
            if self.direction == "receive" and self.file_handle:
                await self.file_handle.close()
                self.file_handle = None

    async def resume(self, initiator):
        if self.state == TransferState.PAUSED and self.initiator == initiator:
            self.state = TransferState.IN_PROGRESS
            if self.direction == "receive":
                self.file_handle = await aiofiles.open(self.file_path, "ab")

async def send_file(file_path, peers):
    total_size = os.path.getsize(file_path)
    transfer_id = str(uuid.uuid4())
    file_transfer = FileTransfer(list(peers.keys())[0], "send", file_path, total_size, transfer_id)
    active_transfers[transfer_id] = file_transfer

    for peer_ip, websocket in peers.items():
        await websocket.send(json.dumps({
            "type": "FILE_TRANSFER",
            "transfer_id": transfer_id,
            "file_path": file_path,
            "file_size": total_size
        }))
    await message_queue.put(f"Requested to send '{os.path.basename(file_path)}' ({total_size / (1024 * 1024):.2f} MB) to {get_peer_display_name(file_transfer.peer_ip)}")